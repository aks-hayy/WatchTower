import os
import sys
import json
import time
import queue as queue_module
import threading
import multiprocessing
import traceback
import uuid
from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn

# Ensure project root is in sys.path
from core.context import context
if context.root_dir not in sys.path:
    sys.path.insert(0, context.root_dir)

from core.backend_policy import BackendPolicyError, backend_policy
from core.packet_engine.config import PacketEngineConfig
from core.packet_engine.capture import start_capture
from core.packet_engine.rust_capture import start_rust_capture, rust_sensor_available
from core.packet_engine.backend_provenance import reported_backend_version
from core.packet_engine.flow_worker import flow_worker
from core.packet_engine.evidence_worker import evidence_worker
from core.packet_engine.persistence import DailyAccumulator
from core.storage.database import WatchtowerDB
from core.endpoint.sysmon import SysmonCollector
from core.utils.logger import setup_logger

logger = setup_logger("WatchtowerDaemon", log_file=os.path.join(context.logs_dir, "daemon.log"))
RUST_CAPTURE_READY_TIMEOUT_SECONDS = 5.0


class EngineManager:
    def __init__(self):
        self.engines = {}  # interface_name -> dict of procs, queues, events
        self.lock = threading.Lock()
        self.config = PacketEngineConfig()
        self.config.validate()
        self.accumulator = DailyAccumulator(data_dir=context.data_dir)
        self._endpoint_db = WatchtowerDB(data_dir=context.data_dir)
        self.daemon_instance_id = str(uuid.uuid4())
        self.local_node_id = self._endpoint_db.local_sensor_node_id()
        reconciled = self._endpoint_db.reconcile_orphaned_capture_sessions(self.daemon_instance_id)
        if reconciled:
            logger.warning("Reconciled %s capture session(s) left by a previous daemon", reconciled)
        self.sysmon_collector = SysmonCollector(self._endpoint_db)
        self.instance_state_path = os.path.join(context.data_dir, "daemon.instance.json")
        self._write_instance_state()

        self.subscribers = []
        self.subscriber_lock = threading.Lock()

        # Lifecycle Management
        self.last_heartbeat = time.time()
        self.background_mode = False
        self.lease_duration = 3600  # 1 hour default
        self.should_shutdown = False

    def _write_instance_state(self):
        value = {
            "daemon_instance_id": self.daemon_instance_id,
            "installation_id": self.local_node_id,
            "pid": os.getpid(),
            "executable": sys.executable,
            "started_at": time.time(),
            "port": context.daemon_port,
        }
        temporary = self.instance_state_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
        os.replace(temporary, self.instance_state_path)

    def release_thread_resources(self):
        self._endpoint_db.remove()

    def get_expires_in(self):
        if self.background_mode:
            return 999999
        elapsed = time.time() - self.last_heartbeat
        return max(0, self.lease_duration - elapsed)

    def heartbeat(self, duration=60):
        self.last_heartbeat = time.time()
        self.lease_duration = max(self.lease_duration, duration)
        return {"status": "ok", "expires_in": self.lease_duration}

    def set_background_mode(self, enabled=True):
        self.background_mode = enabled
        return {"status": "ok", "background_mode": self.background_mode}

    def trigger_shutdown(self):
        self.should_shutdown = True
        return {"status": "ok", "message": "shutdown_triggered"}

    def start_engine(self, interface, backend=None, source_type="network"):
        with self.lock:
            if source_type not in {"network", "bluetooth"}:
                return {"status": "error", "message": f"Unknown capture source: {source_type!r}"}
            if source_type == "bluetooth":
                from core.capture_sources.bluetooth import BluetoothHCISource
                devices = {device.device_id: device for device in BluetoothHCISource().list_devices()}
                selected = devices.get(str(interface))
                if not selected or not selected.available:
                    reason = selected.unavailable_reason if selected else f"Bluetooth controller {interface!r} was not found"
                    return {"status": "error", "message": reason}
            else:
                from core.capture_sources.network import NetworkInterfaceSource

                try:
                    selected = NetworkInterfaceSource().get_device(interface)
                except ValueError as exc:
                    return {"status": "error", "message": str(exc)}
                if not selected.available:
                    return {"status": "error", "message": selected.unavailable_reason}
                interface = selected.device_id

            try:
                backend = backend_policy.capture_backend(
                    source_type=source_type,
                    requested_backend=backend,
                    source_backends=selected.backends,
                )
            except BackendPolicyError as exc:
                return {"status": "error", "message": str(exc)}
            if interface in self.engines:
                return {"status": "already_running", "interface": interface}
            if backend == "rust" and not rust_sensor_available():
                return {"status": "error", "message": "Rust capture backend is not built; run scripts/build_rust_sensor.ps1"}

            backend_version = reported_backend_version(backend)
            session_id = str(uuid.uuid4())
            origin = {
                "session_id": session_id,
                "source_type": source_type,
                "device_id": interface,
                "backend": backend,
                "link_type": "bluetooth-hci" if source_type == "bluetooth" else "ethernet",
                "sensor_node_id": self.local_node_id,
                "source": f"live_{interface}#{session_id[:12]}",
            }
            if backend_version:
                origin["backend_version"] = backend_version
            record_source = f"live_{interface}#{session_id[:12]}"

            # Setup Queues & stop event
            packet_queue = multiprocessing.Queue(maxsize=self.config.packet_queue_size)
            snapshot_queue = multiprocessing.Queue(maxsize=self.config.snapshot_queue_size)
            control_queue = multiprocessing.Queue(maxsize=self.config.control_queue_size)
            evidence_queue = multiprocessing.Queue(maxsize=self.config.evidence_queue_size)
            acknowledgement_queue = multiprocessing.Queue(maxsize=16)
            metrics = {
                "received_packets": multiprocessing.Value("Q", 0),
                "emitted_packets": multiprocessing.Value("Q", 0),
                "dropped_packets": multiprocessing.Value("Q", 0),
                "queue_full_events": multiprocessing.Value("Q", 0),
                "last_packet_at": multiprocessing.Value("d", 0.0),
                "processed_packets": multiprocessing.Value("Q", 0),
                "detector_errors": multiprocessing.Value("Q", 0),
                "evidence_dropped": multiprocessing.Value("Q", 0),
                "snapshot_dropped": multiprocessing.Value("Q", 0),
                "pending_packets": multiprocessing.Value("Q", 0),
                "queue_depth": multiprocessing.Value("Q", 0),
                "queue_depth_high_watermark": multiprocessing.Value("Q", 0),
                "queue_lag_total_ms": multiprocessing.Value("d", 0.0),
                "queue_lag_samples": multiprocessing.Value("Q", 0),
                "queue_lag_current_ms": multiprocessing.Value("d", 0.0),
                "queue_lag_max_ms": multiprocessing.Value("d", 0.0),
            }
            worker_done_event = multiprocessing.Event()
            stop_event = multiprocessing.Event()  # ← clean stop signal for capture
            readiness_queue = multiprocessing.Queue(maxsize=1) if backend == "rust" else None

            # Capture process — uses stop_event for graceful shutdown
            if source_type == "bluetooth":
                from core.capture_sources.bluetooth import start_bluetooth_capture
                capture_target = start_bluetooth_capture
            else:
                capture_target = start_rust_capture if backend == "rust" else start_capture
            capture_args = (interface, packet_queue, True, stop_event, origin, metrics)
            if readiness_queue is not None:
                capture_args += (readiness_queue,)
            capture_proc = multiprocessing.Process(
                target=capture_target,
                args=capture_args,
                daemon=True
            )

            # Worker process
            worker_proc = multiprocessing.Process(
                target=flow_worker,
                args=(packet_queue, snapshot_queue, self.config, control_queue, evidence_queue,
                      origin, metrics, worker_done_event, acknowledgement_queue),
                daemon=True
            )

            # Evidence process
            evidence_proc = multiprocessing.Process(
                target=evidence_worker,
                args=(evidence_queue, self.config, acknowledgement_queue),
                daemon=True
            )

            capture_proc.start()
            if readiness_queue is not None:
                try:
                    readiness = readiness_queue.get(
                        timeout=RUST_CAPTURE_READY_TIMEOUT_SECONDS
                    )
                except queue_module.Empty:
                    readiness = {
                        "status": "error",
                        "message": (
                            "Rust capture sensor did not become ready within "
                            f"{RUST_CAPTURE_READY_TIMEOUT_SECONDS:g} seconds"
                        ),
                    }
                if readiness.get("status") != "ready":
                    stop_event.set()
                    if capture_proc.is_alive():
                        capture_proc.terminate()
                    capture_proc.join(timeout=3)
                    return {
                        "status": "error",
                        "message": str(
                            readiness.get("message")
                            or "Rust capture sensor failed to become ready"
                        ),
                    }

            worker_proc.start()
            evidence_proc.start()

            session_db = WatchtowerDB(data_dir=self.config.data_dir)
            session_db.create_capture_session(
                session_id=session_id, source_type=source_type, device_id=interface,
                backend=backend, link_type=origin["link_type"], source=record_source,
                metadata={"backend_version": backend_version} if backend_version else None,
                daemon_instance_id=self.daemon_instance_id,
                sensor_node_id=self.local_node_id,
            )
            session_db.close()

            self.engines[interface] = {
                "capture_proc": capture_proc,
                "worker_proc": worker_proc,
                "packet_queue": packet_queue,
                "snapshot_queue": snapshot_queue,
                "control_queue": control_queue,
                "evidence_queue": evidence_queue,
                "stop_event": stop_event,
                "evidence_proc": evidence_proc,
                "origin": origin,
                "metrics": metrics,
                "worker_done_event": worker_done_event,
                "acknowledgement_queue": acknowledgement_queue,
            }

            # Endpoint telemetry starts only after capture readiness and session
            # publication have both succeeded.
            if source_type == "network":
                collector = getattr(self, "sysmon_collector", None)
                if collector is not None:
                    collector.start()

            # Start snapshot relay thread (exits cleanly when engine removed)
            threading.Thread(
                target=self._relay_snapshots,
                args=(interface,),
                daemon=True,
                name=f"relay-{interface}"
            ).start()

            logger.info(f"Engine started for {interface}")
            return {
                "status": "started", "interface": interface,
                "backend": backend, "session_id": session_id,
                **({"backend_version": backend_version} if backend_version else {}),
            }

    def stop_engine(self, interface):
        with self.lock:
            engine = self.engines.get(interface)
            if engine is None:
                return {"status": "not_running", "interface": interface}
            if engine.get("stopping"):
                return {
                    "status": "draining",
                    "interface": interface,
                    "session_id": engine["origin"]["session_id"],
                }
            engine["stopping"] = True

        session_id = engine["origin"]["session_id"]
        session_db = WatchtowerDB(data_dir=self.config.data_dir)
        session_db.update_capture_session_state(session_id, "draining", reason="operator_stop")

        capture_proc = engine["capture_proc"]
        worker_proc = engine["worker_proc"]
        evidence_proc = engine["evidence_proc"]
        capture_forced = worker_forced = evidence_forced = False
        control_signal_failed = evidence_signal_failed = False
        worker_ack = evidence_ack = None

        engine["stop_event"].set()
        capture_proc.join(timeout=10.0)
        capture_forced = capture_proc.is_alive()
        if capture_forced:
            logger.warning("Capture process for %s did not stop gracefully; killing.", interface)
            capture_proc.kill()
            capture_proc.join(timeout=2.0)

        try:
            engine["control_queue"].put(
                {"type": "STOP", "reason": "capture_forced" if capture_forced else "operator_stop"},
                timeout=5.0,
            )
        except queue_module.Full:
            control_signal_failed = True
            logger.error("Control queue for %s remained full during shutdown", interface)

        acknowledgement_queue = engine["acknowledgement_queue"]
        worker_deadline = time.monotonic() + self.config.drain_timeout_seconds
        while time.monotonic() < worker_deadline and worker_ack is None:
            try:
                acknowledgement = acknowledgement_queue.get(timeout=0.25)
            except queue_module.Empty:
                if not worker_proc.is_alive():
                    break
                continue
            if acknowledgement.get("stage") == "worker":
                worker_ack = acknowledgement
            elif acknowledgement.get("stage") == "evidence":
                evidence_ack = acknowledgement

        worker_proc.join(timeout=3.0 if worker_ack else 0.25)
        worker_forced = worker_proc.is_alive()
        if worker_forced:
            logger.warning("Worker process for %s did not exit after drain; killing.", interface)
            worker_proc.kill()
            worker_proc.join(timeout=2.0)

        try:
            engine["evidence_queue"].put(None, timeout=5.0)
        except queue_module.Full:
            evidence_signal_failed = True
        evidence_deadline = time.monotonic() + 15.0
        while time.monotonic() < evidence_deadline and evidence_ack is None:
            try:
                acknowledgement = acknowledgement_queue.get(timeout=0.25)
            except queue_module.Empty:
                if not evidence_proc.is_alive():
                    break
                continue
            if acknowledgement.get("stage") == "evidence":
                evidence_ack = acknowledgement
        evidence_proc.join(timeout=3.0 if evidence_ack else 0.25)
        evidence_forced = evidence_proc.is_alive()
        if evidence_forced:
            evidence_proc.kill()
            evidence_proc.join(timeout=2.0)

        metrics = {key: value.value for key, value in engine["metrics"].items()}
        samples = int(metrics.pop("queue_lag_samples", 0))
        lag_total = float(metrics.pop("queue_lag_total_ms", 0.0))
        metrics.pop("queue_lag_current_ms", None)
        metrics["queue_lag_ms"] = lag_total / samples if samples else 0.0
        metrics["pending_packets"] = max(
            0, int(metrics.get("emitted_packets", 0)) - int(metrics.get("processed_packets", 0))
        )

        if worker_ack:
            session_db.acknowledge_capture_stage(
                session_id, "worker",
                persisted_generation=int(worker_ack.get("persisted_generation") or 0),
            )
        if evidence_ack:
            session_db.acknowledge_capture_stage(session_id, "evidence")

        data_complete = (
            worker_ack is not None
            and evidence_ack is not None
            and not control_signal_failed
            and not evidence_signal_failed
            and metrics["pending_packets"] == 0
        )
        reasons = []
        if capture_forced:
            reasons.append("capture_forced")
        if worker_ack is None:
            reasons.append("worker_persistence_ack_timeout")
        elif worker_forced:
            reasons.append("worker_exit_forced_after_ack")
        if control_signal_failed:
            reasons.append("control_signal_failed")
        if evidence_ack is None:
            reasons.append("evidence_persistence_ack_timeout")
        elif evidence_forced:
            reasons.append("evidence_exit_forced_after_ack")
        if evidence_signal_failed:
            reasons.append("evidence_signal_failed")
        if metrics["pending_packets"]:
            reasons.append(f"{metrics['pending_packets']}_packets_pending")

        processing_state = "complete" if data_complete else "partial"
        completion_reason = ",".join(reasons) if reasons else "drained_and_acknowledged"
        process_outcome = ",".join(
            reason for reason in reasons if "forced" in reason
        ) or "graceful"
        session_db.acknowledge_capture_stage(
            session_id, "finalizing", process_exit_outcome=process_outcome,
        )
        session_db.finish_capture_session(
            session_id, metrics=metrics, processing_state=processing_state,
            completion_reason=completion_reason,
            error=None if data_complete else completion_reason,
        )
        session_db.close()

        with self.lock:
            self.engines.pop(interface, None)
        logger.info("Engine stopped for %s", interface)
        return {
            "status": "stopped", "interface": interface, "session_id": session_id,
            "processing_state": processing_state, "completion_reason": completion_reason,
            "worker_acknowledged": worker_ack is not None,
            "evidence_acknowledged": evidence_ack is not None,
            "metrics": metrics,
        }

    def _stop_engine_legacy(self, interface):
        with self.lock:
            if interface not in self.engines:
                return {"status": "not_running", "interface": interface}

            engine = self.engines[interface]

            # 1. Signal capture to stop via event (graceful — stop_filter in sniff)
            engine["stop_event"].set()

            # 2. Signal worker to flush and exit
            engine["control_queue"].put({"type": "STOP"})

            # 3. Wait up to 3s for graceful shutdown, then force kill
            capture_proc = engine["capture_proc"]
            worker_proc = engine["worker_proc"]

            capture_proc.join(timeout=3.0)
            if capture_proc.is_alive():
                logger.warning(f"Capture process for {interface} did not stop gracefully — killing.")
                capture_proc.kill()

            worker_proc.join(timeout=3.0)
            if worker_proc.is_alive():
                logger.warning(f"Worker process for {interface} did not stop gracefully — killing.")
                worker_proc.kill()

            # 3.5 Stop evidence worker
            evidence_proc = engine["evidence_proc"]
            engine["evidence_queue"].put(None) # Signal exit
            evidence_proc.join(timeout=2.0)
            if evidence_proc.is_alive():
                evidence_proc.kill()

            metrics = {key: value.value for key, value in engine["metrics"].items()}
            session_db = WatchtowerDB(data_dir=self.config.data_dir)
            session_db.finish_capture_session(engine["origin"]["session_id"], metrics=metrics)
            session_db.close()

            # 4. Remove from tracking (relay thread will notice and exit)
            del self.engines[interface]
            logger.info(f"Engine stopped for {interface}")
            return {"status": "stopped", "interface": interface}

    def stop_all(self):
        """Stop all running engines. Safe to call on shutdown."""
        interfaces = list(self.engines.keys())
        for iface in interfaces:
            try:
                self.stop_engine(iface)
            except Exception as e:
                logger.error(f"Error stopping {iface}: {e}")
        self.sysmon_collector.stop()
        self._endpoint_db.close()
        try:
            if os.path.exists(self.instance_state_path):
                with open(self.instance_state_path, "r", encoding="utf-8") as handle:
                    state = json.load(handle)
                if state.get("daemon_instance_id") == self.daemon_instance_id:
                    os.remove(self.instance_state_path)
        except (OSError, ValueError):
            logger.warning("Unable to remove daemon instance state", exc_info=True)

    def dump_pcap(self, interface, filename):
        with self.lock:
            if interface not in self.engines:
                return {"status": "error", "message": f"Engine for {interface} not running"}

            engine = self.engines[interface]
            engine["control_queue"].put({"type": "DUMP", "filename": filename})
            logger.info(f"Dump triggered for {interface} -> {filename}")
            return {"status": "dump_triggered", "interface": interface, "filename": filename}

    def get_status(self):
        with self.lock:
            engine_health = {}
            for interface, engine in self.engines.items():
                engine_health[interface] = {
                    "capture_alive": engine["capture_proc"].is_alive(),
                    "worker_alive": engine["worker_proc"].is_alive(),
                    "evidence_alive": engine["evidence_proc"].is_alive(),
                    "capture_pid": engine["capture_proc"].pid,
                    "worker_pid": engine["worker_proc"].pid,
                    "evidence_pid": engine["evidence_proc"].pid,
                    "backend": engine["origin"]["backend"],
                    **(
                        {"backend_version": engine["origin"]["backend_version"]}
                        if engine["origin"].get("backend_version") else {}
                    ),
                    "source_type": engine["origin"]["source_type"],
                    "session_id": engine["origin"]["session_id"],
                    "received_packets": engine["metrics"]["received_packets"].value,
                    "emitted_packets": engine["metrics"]["emitted_packets"].value,
                    "dropped_packets": engine["metrics"]["dropped_packets"].value,
                    "queue_full_events": engine["metrics"]["queue_full_events"].value,
                    "last_packet_at": engine["metrics"]["last_packet_at"].value or None,
                    "processed_packets": engine["metrics"]["processed_packets"].value,
                    "detector_errors": engine["metrics"]["detector_errors"].value,
                    "evidence_dropped": engine["metrics"]["evidence_dropped"].value,
                    "snapshot_dropped": engine["metrics"]["snapshot_dropped"].value,
                    "pending_packets": max(
                        0,
                        engine["metrics"]["emitted_packets"].value
                        - engine["metrics"]["processed_packets"].value,
                    ),
                    "queue_depth": engine["metrics"]["queue_depth"].value,
                    "queue_depth_high_watermark": engine["metrics"]["queue_depth_high_watermark"].value,
                    "queue_lag_ms": (
                        engine["metrics"]["queue_lag_current_ms"].value
                    ),
                    "queue_lag_max_ms": engine["metrics"]["queue_lag_max_ms"].value,
                    "processing_state": "running",
                    "shutdown_stage": "draining" if engine.get("stopping") else "capturing",
                }
            return {
                "running": True,
                "daemon_instance_id": self.daemon_instance_id,
                "installation_id": self.local_node_id,
                "pid": os.getpid(),
                "interfaces": list(self.engines.keys()),
                "engines": engine_health,
                "healthy": all(
                    all(value[key] for key in ("capture_alive", "worker_alive", "evidence_alive"))
                    for value in engine_health.values()
                ),
                "background_mode": self.background_mode,
                "expires_in": self.get_expires_in(),
                "endpoint_telemetry": self.sysmon_collector.status(include_counts=False),
            }

    def _relay_snapshots(self, interface):
        """Relays snapshots from the engine queue to all connected socket subscribers.
        Exits cleanly when the engine is removed from self.engines.
        """
        logger.debug(f"Relay thread started for {interface}")
        while True:
            # Check if this engine still exists
            with self.lock:
                if interface not in self.engines:
                    logger.debug(f"Relay thread exiting for {interface} (engine removed)")
                    break
                snapshot_queue = self.engines[interface]["snapshot_queue"]

            try:
                # Use timeout so we periodically check the exit condition
                item = snapshot_queue.get(timeout=1.0)
            except queue_module.Empty:
                continue
            except Exception as e:
                logger.error(f"Snapshot queue error for {interface}: {e}")
                time.sleep(1)
                continue

            try:
                from dataclasses import asdict
                if isinstance(item, tuple) and len(item) == 2:
                    mode, snapshot = item
                else:
                    mode, snapshot = "GLOBAL", item

                msg = json.dumps({
                    "type": "snapshot",
                    "mode": mode,
                    "data": asdict(snapshot)
                }) + "\n"

                with self.subscriber_lock:
                    dead = []
                    for sub in self.subscribers:
                        try:
                            sub.request.sendall(msg.encode("utf-8"))
                        except Exception:
                            dead.append(sub)
                    for sub in dead:
                        self.subscribers.remove(sub)

            except Exception as e:
                logger.error(f"Snapshot relay error for {interface}: {e}")


# Windows multiprocessing re-imports this module in capture/worker children.
# Those children must not construct an EngineManager or reconcile the parent
# daemon's active session as orphaned; only the real server process owns it.
manager = None if __name__ == "__mp_main__" else EngineManager()


def _start_engine_from_request(engine_manager, request):
    return engine_manager.start_engine(
        request.get("interface"),
        request.get("backend"),
        request.get("source_type", "network"),
    )


def _recv_line(sock, max_bytes=65536):
    """Read a complete newline-terminated JSON line from a socket.
    Handles responses larger than a single recv() buffer.
    """
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if b"\n" in buf or len(buf) > max_bytes:
            break
    return buf.decode("utf-8").strip()


class DaemonHandler(BaseRequestHandler):
    def send_message(self, msg_dict):
        try:
            data = json.dumps(msg_dict).encode("utf-8") + b"\n"
            self.request.sendall(data)
        except Exception:
            pass

    def handle(self):
        from core.daemon.manager import DaemonManager
        auth_key = DaemonManager.get_or_create_key()

        try:
            f = self.request.makefile("r", encoding="utf-8")

            # Step 1: Auth handshake
            auth_line = f.readline().strip()
            if not auth_line:
                return

            try:
                auth_req = json.loads(auth_line)
                if auth_req.get("auth") != auth_key:
                    logger.warning(f"Unauthorized connection attempt from {self.client_address[0]}")
                    self.send_message({"status": "error", "message": "unauthorized"})
                    return
            except json.JSONDecodeError:
                logger.warning(f"Invalid auth JSON from {self.client_address[0]}")
                self.send_message({"status": "error", "message": "invalid_auth_json"})
                return

            self.send_message({"status": "authenticated"})

            # Step 2: Command loop
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    req = json.loads(line)
                    action = req.get("action")

                    if action == "status":
                        self.send_message(manager.get_status())
                    elif action == "start":
                        self.send_message(_start_engine_from_request(manager, req))
                    elif action == "stop":
                        self.send_message(manager.stop_engine(req.get("interface")))
                    elif action == "dump":
                        self.send_message(manager.dump_pcap(req.get("interface"), req.get("filename")))
                    elif action == "heartbeat":
                        self.send_message(manager.heartbeat(req.get("duration", 60)))
                    elif action == "background":
                        self.send_message(manager.set_background_mode(req.get("enabled", True)))
                    elif action == "shutdown":
                        self.send_message({"status": "shutting_down"})
                        manager.trigger_shutdown()
                        return
                    elif action == "subscribe":
                        with manager.subscriber_lock:
                            manager.subscribers.append(self)
                        self.send_message({"status": "subscribed"})
                        # Keep alive for snapshot streaming
                        while True:
                            time.sleep(10)
                    else:
                        self.send_message({"status": "error", "message": f"unknown action: {action}"})

                except Exception as e:
                    logger.error(f"Command execution error: {e}\n{traceback.format_exc()}")
                    self.send_message({"status": "error", "message": str(e)})

        except Exception as e:
            logger.error(f"Handler fatal error: {e}\n{traceback.format_exc()}")
        finally:
            manager.release_thread_resources()


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


def run_daemon():
    if not context.is_admin and os.environ.get("WATCHTOWER_SENSOR_SERVICE") != "1":
        print("ERROR: Daemon must run as Administrator.")
        sys.exit(1)

    from core.daemon.manager import DaemonManager
    DaemonManager.get_or_create_key()

    server = ThreadedTCPServer(("127.0.0.1", context.daemon_port), DaemonHandler)
    logger.info(f"Watchtower Daemon listening on port {context.daemon_port}")

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        while not manager.should_shutdown:
            time.sleep(1)
            if manager.get_expires_in() <= 0:
                logger.info("Lease expired. Stopping all engines and shutting down.")
                break
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt — shutting down daemon.")
    manager.stop_all()
    server.shutdown()
    server.server_close()
    sys.exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run_daemon()

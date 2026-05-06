import os
import sys
import json
import time
import queue as queue_module
import threading
import multiprocessing
import traceback
from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn

# Ensure project root is in sys.path
from core.context import context
if context.root_dir not in sys.path:
    sys.path.insert(0, context.root_dir)

from core.packet_engine.config import PacketEngineConfig
from core.packet_engine.capture import start_capture
from core.packet_engine.flow_worker import flow_worker
from core.packet_engine.evidence_worker import evidence_worker
from core.packet_engine.persistence import DailyAccumulator
from core.utils.logger import setup_logger
from core.ai.worker import AIWorker

logger = setup_logger("WatchtowerDaemon", log_file=os.path.join(context.logs_dir, "daemon.log"))


class EngineManager:
    def __init__(self):
        self.engines = {}  # interface_name -> dict of procs, queues, events
        self.lock = threading.Lock()
        self.config = PacketEngineConfig()
        self.accumulator = DailyAccumulator(data_dir=context.data_dir)

        self.subscribers = []
        self.subscriber_lock = threading.Lock()

        # Lifecycle Management
        self.last_heartbeat = time.time()
        self.background_mode = False
        self.lease_duration = 3600  # 1 hour default
        self.should_shutdown = False

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

    def start_engine(self, interface):
        with self.lock:
            if interface in self.engines:
                return {"status": "already_running", "interface": interface}

            # Setup Queues & stop event
            packet_queue = multiprocessing.Queue()
            snapshot_queue = multiprocessing.Queue()
            control_queue = multiprocessing.Queue()
            evidence_queue = multiprocessing.Queue()
            stop_event = multiprocessing.Event()  # ← clean stop signal for capture

            # Capture process — uses stop_event for graceful shutdown
            capture_proc = multiprocessing.Process(
                target=start_capture,
                args=(interface, packet_queue, True, stop_event),
                daemon=True
            )

            # Worker process
            worker_proc = multiprocessing.Process(
                target=flow_worker,
                args=(packet_queue, snapshot_queue, self.config, control_queue, evidence_queue),
                daemon=True
            )

            # Evidence process
            evidence_proc = multiprocessing.Process(
                target=evidence_worker,
                args=(evidence_queue, self.config),
                daemon=True
            )

            capture_proc.start()
            worker_proc.start()
            evidence_proc.start()

            self.engines[interface] = {
                "capture_proc": capture_proc,
                "worker_proc": worker_proc,
                "packet_queue": packet_queue,
                "snapshot_queue": snapshot_queue,
                "control_queue": control_queue,
                "evidence_queue": evidence_queue,
                "stop_event": stop_event,
                "evidence_proc": evidence_proc
            }

            # Start snapshot relay thread (exits cleanly when engine removed)
            threading.Thread(
                target=self._relay_snapshots,
                args=(interface,),
                daemon=True,
                name=f"relay-{interface}"
            ).start()

            logger.info(f"Engine started for {interface}")
            return {"status": "started", "interface": interface}

    def stop_engine(self, interface):
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
            return {
                "running": True,
                "interfaces": list(self.engines.keys()),
                "background_mode": self.background_mode,
                "expires_in": self.get_expires_in()
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


manager = EngineManager()


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
                    self.send_message({"status": "error", "message": "unauthorized"})
                    return
            except json.JSONDecodeError:
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
                        self.send_message(manager.start_engine(req.get("interface")))
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


class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


def run_daemon():
    if not context.is_admin:
        print("ERROR: Daemon must run as Administrator.")
        sys.exit(1)

    from core.daemon.manager import DaemonManager
    DaemonManager.get_or_create_key()

    # Start AI Worker
    from core.storage.database import WatchtowerDB
    db = WatchtowerDB()
    ai_worker = AIWorker(db)
    ai_worker.start()

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

    ai_worker.stop()
    server.shutdown()
    server.server_close()
    sys.exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run_daemon()

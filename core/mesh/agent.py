"""Outbound mesh agent with a durable encrypted spool and typed command handling."""

from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import time
import uuid
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet

from core import __version__
from core.backend_policy import backend_policy
from core.daemon.client import DaemonClient
from core.endpoint.sysmon import SysmonCollector
from core.investigation.export import CaseExporter
from core.investigation.service import InvestigationService
from core.mesh.contracts import MESH_PROTOCOL_VERSION, TelemetryEnvelope, payload_hash
from core.mesh.security import certificate_fingerprint, new_node_csr
from core.mesh.spool import EncryptedMeshSpool
from core.mesh.transport import MeshGrpcClient


CASE_CHUNK_BYTES = 700 * 1024
MAX_CASE_BUNDLE_BYTES = 20 * 1024 * 1024


class MeshAgent:
    def __init__(self, db, data_dir: Optional[str] = None):
        self.db = db
        self.directory = Path(data_dir or db.data_dir) / "mesh" / "agent"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.config_path = self.directory / "agent.json"
        self.key_path = self.directory / "client.key"
        self.cert_path = self.directory / "client.pem"
        self.ca_path = self.directory / "ca.pem"
        self.spool_key_path = self.directory / "spool.key"

    def status(self) -> Dict[str, Any]:
        config = self._config()
        spool = self._spool()
        try:
            return {
                "enrolled": bool(config.get("controller") and self.cert_path.exists() and self.ca_path.exists()),
                "node_id": config.get("node_id"), "controller": config.get("controller"),
                "pending_envelopes": spool.count_pending(), "spool_bytes": spool.bytes_pending(),
                "max_spool_bytes": spool.max_bytes, "protocol_version": MESH_PROTOCOL_VERSION,
            }
        finally:
            spool.close()

    def enroll(self, controller: str, token: str, ca_certificate_path: str, name: Optional[str] = None,
               enrollment_port: int = 9443, ingest_port: int = 9444) -> Dict[str, Any]:
        return self._enroll_with_root(
            controller, token, Path(ca_certificate_path).read_bytes(), name,
            enrollment_port, ingest_port,
        )

    def join(self, join_code: str, name: Optional[str] = None) -> Dict[str, Any]:
        from core.mesh.service import MeshControllerService
        package = MeshControllerService.decode_join_package(join_code)
        root = str(package["ca_certificate_pem"]).encode("utf-8")
        result = self._enroll_with_root(
            str(package["controller"]), str(package["token"]), root,
            name or package.get("requested_name"),
            int(package.get("enrollment_port") or 9443),
            int(package.get("ingest_port") or 9444),
        )
        result["controller_ca_fingerprint"] = package["ca_fingerprint"]
        result["expected_capabilities"] = package.get("expected_capabilities") or {}
        return result

    def _enroll_with_root(self, controller: str, token: str, root: bytes,
                          name: Optional[str], enrollment_port: int,
                          ingest_port: int) -> Dict[str, Any]:
        if self._config().get("node_id"):
            raise RuntimeError("This sensor is already enrolled; leave the current mesh before joining another")
        node_id = f"node-{uuid.uuid4()}"
        private_key, csr = new_node_csr(node_id)
        client = MeshGrpcClient(controller, enrollment_port=enrollment_port, ingest_port=ingest_port)
        result = client.enroll({
            "protocol_version": MESH_PROTOCOL_VERSION, "token": token, "node_id": node_id,
            "name": name or platform.node() or node_id, "platform": platform.platform(), "agent_version": __version__,
            "capabilities": self.capabilities(), "csr_pem": csr.decode("utf-8"),
        }, root)
        self.key_path.write_bytes(private_key)
        self.cert_path.write_text(str(result["client_certificate_pem"]), encoding="utf-8")
        self.ca_path.write_text(str(result["ca_certificate_pem"]), encoding="utf-8")
        controller_ca_fingerprint = certificate_fingerprint(root)
        for path in (self.key_path, self.cert_path, self.ca_path):
            try:
                path.chmod(0o600)
            except OSError:
                pass
        config = {
            "node_id": node_id, "name": name or platform.node() or node_id, "controller": controller,
            "controller_ca_fingerprint": controller_ca_fingerprint,
            "enrollment_port": int(enrollment_port), "ingest_port": int(ingest_port), "next_sequence": 1,
            "flow_after_id": 0, "observation_after": 0.0, "session_after": 0.0,
            "alert_after_id": 0, "finding_after_id": 0, "hardware_after_id": 0,
        }
        self._write_config(config)
        return {
            "node_id": node_id,
            "controller": controller,
            "certificate_fingerprint": result["node"]["certificate_fingerprint"],
            "controller_ca_fingerprint": controller_ca_fingerprint,
        }

    def leave(self, reason: str = "Operator removed this sensor", force: bool = False) -> Dict[str, Any]:
        config = self._require_config()
        node_id = str(config["node_id"])
        notified = False
        notification_error = None
        try:
            self.queue("lifecycle", {"state": "leaving", "reason": str(reason)[:500]}, priority=100)
            self.flush_once()
            notified = True
        except Exception as exc:
            notification_error = str(exc)
            if not force:
                raise RuntimeError(
                    f"Controller could not acknowledge leave: {notification_error}. "
                    "Retry when connected or use --force for local credential removal."
                ) from exc
        for path in (
            self.config_path, self.key_path, self.cert_path, self.ca_path, self.spool_key_path,
            self.directory / "spool.db", self.directory / "spool.db-wal", self.directory / "spool.db-shm",
        ):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        return {
            "left": True,
            "node_id": node_id,
            "controller_notified": notified,
            "notification_error": notification_error,
        }

    def capabilities(self) -> Dict[str, Any]:
        try:
            from core.capture_sources import default_registry
            devices = default_registry().list_devices()
            source_types = sorted({device.source_type for device in devices})
            capture_devices = [{
                "device_id": device.device_id,
                "name": device.name,
                "description": device.description,
                "source_type": device.source_type,
                "available": bool(device.available),
                "unavailable_reason": device.unavailable_reason,
                "backends": list(device.backends),
            } for device in devices[:100]]
        except Exception:
            source_types, capture_devices = [], []
        try:
            from core.forensics.plugin_loader import PluginLoader
            plugins = list(PluginLoader().list_plugins().values())
            parsers = sorted(item["name"] for item in plugins if item.get("type") == "parser" and item.get("valid"))
            detectors = sorted(item.get("detector_id") or item["name"] for item in plugins if item.get("type") == "detector" and item.get("valid"))
        except Exception:
            parsers, detectors = [], []
        endpoint = SysmonCollector(self.db).status()
        return {
            "capture_sources": source_types, "capture_devices": capture_devices,
            "sysmon": bool(endpoint.get("available")),
            "process_service_attribution": bool(endpoint.get("available")), "raw_export": True,
            "parsers": parsers, "detectors": detectors,
        }

    def queue(self, envelope_type: str, payload: Dict[str, Any], priority: int = 0) -> Dict[str, Any]:
        config = self._require_config()
        sequence = int(config.get("next_sequence") or 1)
        envelope = TelemetryEnvelope(
            node_id=str(config["node_id"]), sequence=sequence, envelope_type=envelope_type,
            payload=payload, created_at=time.time(),
        )
        spool = self._spool()
        try:
            status = spool.enqueue(sequence, envelope.to_dict(), priority=priority)
        finally:
            spool.close()
        config["next_sequence"] = sequence + 1
        self._write_config(config)
        return {"sequence": sequence, **status}

    def collect_once(self, limit: int = 250) -> Dict[str, Any]:
        config = self._require_config()
        exported = self.db.mesh_export_batch(
            config.get("flow_after_id", 0), config.get("observation_after", 0.0), config.get("session_after", 0.0), limit,
            alert_after_id=config.get("alert_after_id", 0), finding_after_id=config.get("finding_after_id", 0),
            hardware_after_id=config.get("hardware_after_id", 0),
            sensor_node_id=str(config.get("node_id") or ""),
        )
        queued = []
        health = {
            "captured_at": time.time(), "endpoint": self.db.endpoint_telemetry_status(),
            "agent": self.status(), "capabilities": self.capabilities(),
        }
        queued.append(self.queue("health", {"health": health, "capabilities": health["capabilities"]}, priority=10))
        if exported["sessions"]:
            queued.append(self.queue("sessions", {"items": exported["sessions"]}, priority=20))
            config["session_after"] = max(
                max(float(item.get("started_at") or 0.0), float(item.get("ended_at") or 0.0))
                for item in exported["sessions"]
            )
        if exported["flows"]:
            queued.append(self.queue("flows", {"items": exported["flows"]}, priority=0))
            config["flow_after_id"] = max(int(item["id"]) for item in exported["flows"])
        if exported["endpoint_observations"]:
            queued.append(self.queue("endpoint_observations", {"items": exported["endpoint_observations"]}, priority=10))
            config["observation_after"] = max(float(item["created_at"]) for item in exported["endpoint_observations"])
        if exported["findings"]:
            queued.append(self.queue("findings", {"items": exported["findings"]}, priority=20))
            config["finding_after_id"] = max(int(item["id"]) for item in exported["findings"])
        if exported["alerts"]:
            queued.append(self.queue("alerts", {"items": exported["alerts"]}, priority=20))
            config["alert_after_id"] = max(int(item["id"]) for item in exported["alerts"])
        if exported["hardware_observations"]:
            queued.append(self.queue("hardware_observations", {"items": exported["hardware_observations"]}, priority=10))
            config["hardware_after_id"] = max(int(item["id"]) for item in exported["hardware_observations"])
        # queue() persists its own sequence increment; refresh before persisting cursors.
        config["next_sequence"] = self._config().get("next_sequence", config.get("next_sequence", 1))
        self._write_config(config)
        return {
            "queued": queued, "session_count": len(exported["sessions"]), "flow_count": len(exported["flows"]),
            "observation_count": len(exported["endpoint_observations"]), "finding_count": len(exported["findings"]),
            "alert_count": len(exported["alerts"]), "hardware_observation_count": len(exported["hardware_observations"]),
        }

    def flush_once(self) -> Dict[str, Any]:
        config = self._require_config()
        spool = self._spool()
        sent = 0
        try:
            while True:
                stored = spool.next()
                if stored is None:
                    break
                envelope = self._upgrade_spooled_envelope(stored)
                response = self._client(config).ingest(envelope)
                spool.acknowledge(int(response["ack_sequence"]))
                sent += 1
                commands = list(response.get("commands") or [])
                if commands:
                    completed = self._handle_commands(commands)
                    if completed:
                        self.queue("command_results", {"items": completed}, priority=20)
        finally:
            spool.close()
        return {"sent": sent, **self.status()}

    @staticmethod
    def _upgrade_spooled_envelope(stored: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a locally persisted v1 record to the v2 wire digest."""
        envelope = TelemetryEnvelope.from_dict(stored)
        if envelope.protocol_version == MESH_PROTOCOL_VERSION and envelope.digest_algorithm:
            return envelope.to_dict()
        upgraded = TelemetryEnvelope(
            node_id=envelope.node_id,
            sequence=envelope.sequence,
            envelope_type=envelope.envelope_type,
            payload=envelope.payload,
            created_at=envelope.created_at,
            protocol_version=MESH_PROTOCOL_VERSION,
            payload_digest=payload_hash(envelope.payload),
        )
        return upgraded.to_dict()

    def _handle_commands(self, commands: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """Execute only explicit typed commands and retain idempotent results locally."""
        config = self._require_config()
        completed = dict(config.get("completed_commands") or {})
        results: list[Dict[str, Any]] = []
        for command in commands[:20]:
            command_id = str(command.get("id") or "")
            if not command_id:
                continue
            prior = completed.get(command_id)
            if isinstance(prior, dict):
                results.append(prior)
                continue
            action = str(command.get("action") or "")
            arguments = dict(command.get("arguments") or {})
            try:
                result = self._execute_command(action, arguments)
                outcome = {
                    "command_id": command_id,
                    "status": (
                        "failed"
                        if isinstance(result, dict) and result.get("status") == "error"
                        else "completed"
                    ),
                    "result": result,
                }
                if action == "case.export":
                    transfer = self._queue_case_bundle(command_id, outcome["result"])
                    outcome["result"].update(transfer)
            except Exception as exc:
                outcome = {
                    "command_id": command_id,
                    "status": "failed",
                    "result": {"error": str(exc)[:500]},
                }
            completed[command_id] = outcome
            results.append(outcome)
        if len(completed) > 1000:
            completed = dict(list(completed.items())[-1000:])
        config["completed_commands"] = completed
        self._write_config(config)
        return results

    def _execute_command(self, action: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if action == "capture.start":
            interface = str(arguments.get("interface") or "")
            if not interface:
                raise ValueError("capture.start requires an interface")
            source_type = str(arguments.get("source_type") or "network")
            return DaemonClient().start_engine(
                interface,
                backend=backend_policy.capture_backend(
                    source_type=source_type,
                    requested_backend=arguments.get("backend"),
                ),
                source_type=source_type,
            )
        if action == "capture.stop":
            interface = str(arguments.get("interface") or "")
            if not interface:
                raise ValueError("capture.stop requires an interface")
            return DaemonClient().stop_engine(interface)
        if action == "case.export":
            ip = str(arguments.get("ip") or "")
            if not ip:
                raise ValueError("case.export requires an IP address")
            investigation = InvestigationService(self.db).investigate(
                ip, source=arguments.get("source"), persist=False,
            )
            output = CaseExporter(Path(self.db.data_dir) / "cases").export(
                investigation, arguments.get("case_name"),
            )
            manifest = output / "manifest.json"
            archive = Path(shutil.make_archive(str(output), "zip", root_dir=str(output.parent), base_dir=output.name))
            return {
                "case_bundle": output.name, "manifest_sha256": CaseExporter._hash(manifest),
                "_case_archive_path": str(archive),
            }
        raise ValueError("Unsupported mesh command")

    def _queue_case_bundle(self, command_id: str, result: Dict[str, Any]) -> Dict[str, Any]:
        """Queue a bounded, content-addressed case export after explicit controller approval."""
        archive_path = Path(str(result.pop("_case_archive_path", "")))
        if not archive_path.is_file():
            raise RuntimeError("Case archive was not created")
        try:
            payload = archive_path.read_bytes()
        finally:
            try:
                archive_path.unlink()
            except OSError:
                pass
        if len(payload) > MAX_CASE_BUNDLE_BYTES:
            raise ValueError(f"Case bundle exceeds {MAX_CASE_BUNDLE_BYTES // (1024 * 1024)} MiB transfer limit")
        digest = sha256(payload).hexdigest()
        chunks = [payload[index:index + CASE_CHUNK_BYTES] for index in range(0, len(payload), CASE_CHUNK_BYTES)] or [b""]
        case_id = f"{command_id}-{digest[:16]}"
        for index, chunk in enumerate(chunks):
            self.queue("case_bundle", {
                "command_id": command_id, "case_id": case_id, "case_name": result.get("case_bundle"),
                "manifest_sha256": result.get("manifest_sha256"), "archive_sha256": digest,
                "total_chunks": len(chunks), "chunk_index": index,
                "chunk_sha256": sha256(chunk).hexdigest(),
                "data_base64": base64.b64encode(chunk).decode("ascii"),
            }, priority=20)
        return {"case_transfer": {"case_id": case_id, "archive_sha256": digest, "chunks": len(chunks)}}

    def sync_once(self, limit: int = 250) -> Dict[str, Any]:
        collected = self.collect_once(limit)
        return {"collect": collected, "flush": self.flush_once()}

    def _client(self, config: Dict[str, Any]) -> MeshGrpcClient:
        return MeshGrpcClient(
            str(config["controller"]), int(config.get("enrollment_port") or 9443), int(config.get("ingest_port") or 9444),
            self.ca_path.read_bytes(), self.key_path.read_bytes(), self.cert_path.read_bytes(),
        )

    def _spool(self) -> EncryptedMeshSpool:
        if not self.spool_key_path.exists():
            self.spool_key_path.write_bytes(Fernet.generate_key())
            try:
                self.spool_key_path.chmod(0o600)
            except OSError:
                pass
        return EncryptedMeshSpool(str(self.directory / "spool.db"), self.spool_key_path.read_bytes())

    def _config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def _require_config(self) -> Dict[str, Any]:
        config = self._config()
        if not config.get("controller") or not config.get("node_id"):
            raise RuntimeError("Mesh agent is not enrolled")
        return config

    def _write_config(self, value: Dict[str, Any]) -> None:
        temporary = self.config_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        temporary.replace(self.config_path)

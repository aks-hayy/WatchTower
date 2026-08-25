"""Controller-side mesh authority, ingestion, and typed command service."""

from __future__ import annotations

import base64
from pathlib import Path, PurePosixPath
from hashlib import sha256
import json
import secrets
import shutil
import socket
import time
import uuid
import zipfile
from typing import Any, Dict, Iterable, Optional

from cryptography import x509
from core.detection.contracts import DetectionFindingV2
from core.mesh.contracts import MESH_PROTOCOL_VERSION, TelemetryEnvelope
from core.mesh.security import MeshAuthority, certificate_fingerprint, token_hash


ALLOWED_COMMANDS = {"capture.start", "capture.stop", "case.export"}
MAX_CASE_BUNDLE_BYTES = 20 * 1024 * 1024
MAX_CASE_BUNDLE_FILES = 128
MAX_CASE_BUNDLE_EXPANDED_BYTES = 50 * 1024 * 1024
JOIN_PACKAGE_VERSION = "watchtower.mesh.join.v1"


class MeshControllerService:
    def __init__(self, db, data_dir: Optional[str] = None):
        self.db = db
        self.authority = MeshAuthority(data_dir or str(db.data_dir))
        self.config_path = self.authority.directory / "controller.json"

    def initialize(self, host: str = "127.0.0.1") -> Dict[str, Any]:
        self.authority.initialize(host)
        if not self.config_path.exists():
            self._write_config({
                "mode": "local", "bind_host": host, "advertised_address": host,
                "enrollment_port": 9443, "ingest_port": 9444, "configured_at": time.time(),
            })
        return self.status()

    def setup(self, mode: str = "local", address: Optional[str] = None,
              enrollment_port: int = 9443, ingest_port: int = 9444,
              acknowledge_public_risk: bool = False) -> Dict[str, Any]:
        mode = str(mode or "local").strip().lower()
        if mode not in {"local", "vpn", "public"}:
            raise ValueError("Controller mode must be local, vpn, or public")
        if mode == "public" and not acknowledge_public_risk:
            raise ValueError("Direct-public mode requires explicit acknowledgement of its security warning")
        advertised = str(address or self._default_advertised_address()).strip()
        if not advertised or any(char.isspace() for char in advertised):
            raise ValueError("A valid controller address is required")
        bind_host = advertised if mode == "vpn" else "0.0.0.0"
        enrollment_port = max(1, min(int(enrollment_port), 65535))
        ingest_port = max(1, min(int(ingest_port), 65535))
        if enrollment_port == ingest_port:
            raise ValueError("Enrollment and ingest ports must differ")
        if self.authority.ready:
            current_address = str(self._config().get("advertised_address") or "")
            if current_address and current_address != advertised:
                self.authority.rotate_server_certificate(advertised)
        else:
            self.authority.initialize(advertised)
        self._write_config({
            "mode": mode, "bind_host": bind_host, "advertised_address": advertised,
            "enrollment_port": enrollment_port, "ingest_port": ingest_port,
            "configured_at": time.time(),
        })
        return self.status()

    def status(self) -> Dict[str, Any]:
        nodes = [self._health_view(node) for node in self.db.list_sensor_nodes()]
        runtime = {}
        runtime_path = self.authority.directory / "runtime.json"
        if runtime_path.exists():
            try:
                runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                runtime = {"state": "unknown", "error": "Controller runtime state is unreadable"}
        return {
            "protocol_version": MESH_PROTOCOL_VERSION,
            "authority_ready": self.authority.ready,
            "local_node_id": self.db.local_sensor_node_id(),
            "nodes": len(nodes),
            "online_nodes": sum(1 for node in nodes if node.get("status") in {"online", "local"}),
            "nodes_detail": nodes,
            "configuration": self._config(),
            "runtime": runtime,
            "ca_fingerprint": (
                certificate_fingerprint(self.authority.ca_certificate())
                if self.authority.ca_cert_path.exists() else None
            ),
        }

    def create_enrollment(self, name: Optional[str] = None, ttl_seconds: int = 3600,
                          max_uses: int = 1, created_by: str = "local-operator") -> Dict[str, Any]:
        if not self.authority.ready:
            raise RuntimeError("Initialize the mesh controller before creating enrollment tokens")
        token = secrets.token_urlsafe(32)
        record = self.db.create_mesh_enrollment(
            str(uuid.uuid4()), token_hash(token), time.time() + max(60, min(int(ttl_seconds), 86400)),
            name, max(1, min(int(max_uses), 10)), created_by,
        )
        config = self._config()
        if not config.get("advertised_address"):
            raise RuntimeError("Run mesh controller setup before creating a join package")
        package = {
            "version": JOIN_PACKAGE_VERSION,
            "controller": config["advertised_address"],
            "enrollment_port": int(config.get("enrollment_port") or 9443),
            "ingest_port": int(config.get("ingest_port") or 9444),
            "token": token,
            "expires_at": record["expires_at"],
            "requested_name": name,
            "ca_certificate_pem": self.authority.ca_certificate().decode("utf-8"),
            "ca_fingerprint": certificate_fingerprint(self.authority.ca_certificate()),
            "expected_capabilities": {"capture": True, "telemetry": True},
        }
        join_code = "WTJ1-" + base64.urlsafe_b64encode(
            json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return {
            **record, "token": token, "join_code": join_code,
            "controller": package["controller"], "ca_fingerprint": package["ca_fingerprint"],
        }

    def rotate_certificate(self) -> Dict[str, Any]:
        host = str(self._config().get("advertised_address") or "127.0.0.1")
        return {
            "rotated": True,
            "server_fingerprint": self.authority.rotate_server_certificate(host),
            "restart_required": True,
        }

    def enroll(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self.authority.ready:
            raise RuntimeError("Mesh controller is not initialized")
        token = str(request.get("token") or "")
        node_id = str(request.get("node_id") or "")
        csr_pem = str(request.get("csr_pem") or "").encode("utf-8")
        if not token or not node_id or not csr_pem or len(node_id) > 128:
            raise ValueError("Enrollment requires token, node_id, and CSR")
        enrollment = self.db.consume_mesh_enrollment(token_hash(token))
        if not enrollment:
            raise PermissionError("Enrollment token is invalid, expired, exhausted, or revoked")
        certificate = self.authority.sign_csr(csr_pem, node_id)
        certificate_data = x509.load_pem_x509_certificate(certificate)
        node = self.db.upsert_sensor_node({
            "id": node_id,
            "name": str(request.get("name") or enrollment.get("requested_name") or node_id)[:256],
            "certificate_fingerprint": certificate_fingerprint(certificate),
            "status": "online", "platform": str(request.get("platform") or "unknown")[:256],
            "agent_version": str(request.get("agent_version") or "unknown")[:128],
            "capabilities": dict(request.get("capabilities") or {}),
            "health": {
                "enrolled_at": time.time(),
                "certificate_expires_at": certificate_data.not_valid_after_utc.timestamp(),
            },
        })
        return {
            "protocol_version": MESH_PROTOCOL_VERSION, "node": node,
            "client_certificate_pem": certificate.decode("utf-8"),
            "ca_certificate_pem": self.authority.ca_certificate().decode("utf-8"),
        }

    def ingest(self, node_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        node = self.db.get_sensor_node(node_id)
        if not node or node.get("status") in {"revoked", "decommissioned"}:
            raise PermissionError("Mesh node is not enrolled or has been revoked")
        envelope = TelemetryEnvelope.from_dict(payload)
        if envelope.node_id != node_id:
            raise PermissionError("Mesh client certificate and envelope node do not match")
        receipt = self.db.record_mesh_receipt(node_id, envelope.sequence, envelope.envelope_type, envelope.payload_digest)
        if receipt["duplicate"]:
            return {"ack_sequence": envelope.sequence, **receipt, "commands": self.db.pending_mesh_commands(node_id)}
        if not receipt["accepted"]:
            raise ValueError(receipt["reason"])
        applied = self._apply(node_id, envelope)
        return {"ack_sequence": envelope.sequence, **receipt, "applied": applied, "commands": self.db.pending_mesh_commands(node_id)}

    def _apply(self, node_id: str, envelope: TelemetryEnvelope) -> int:
        payload = envelope.payload
        if envelope.envelope_type == "health":
            self.db.update_sensor_node_health(node_id, dict(payload.get("health") or payload), dict(payload.get("capabilities") or {}))
            return 1
        if envelope.envelope_type == "sessions":
            return self.db.upsert_mesh_capture_sessions(list(payload.get("items") or []), node_id)
        if envelope.envelope_type == "endpoint_observations":
            rows = [dict(row, sensor_node_id=node_id) for row in list(payload.get("items") or [])[:500]]
            return self.db.upsert_endpoint_process_observations(rows)
        if envelope.envelope_type == "flows":
            rows = []
            for row in list(payload.get("items") or [])[:1000]:
                value = dict(row)
                original_source = str(value.get("source") or "live")
                value["source"] = original_source if original_source.startswith(f"mesh:{node_id}:") else f"mesh:{node_id}:{original_source}"
                value["sensor_node_id"] = node_id
                metadata = value.get("l7_metadata") or {}
                if isinstance(metadata, dict):
                    metadata.setdefault("mesh_origin_source", original_source)
                    value["l7_metadata"] = metadata
                rows.append(value)
            self.db.bulk_upsert_flows(rows)
            return len(rows)
        if envelope.envelope_type == "alerts":
            count = 0
            for row in list(payload.get("items") or [])[:500]:
                value = dict(row)
                source = str(value.get("source") or "live")
                source = source if source.startswith(f"mesh:{node_id}:") else f"mesh:{node_id}:{source}"
                self.db.insert_alert(
                    str(value.get("entity_ip") or "unknown"), float(value.get("timestamp") or time.time()),
                    str(value.get("type") or "MESH_ALERT"), str(value.get("severity") or "LOW"),
                    float(value.get("score") or 0.0), str(value.get("explanation") or "Mesh alert"),
                    dict(value.get("evidence") or {}), source=source,
                    capture_session_id=value.get("capture_session_id"), capture_interface=value.get("capture_interface"),
                    capture_backend=value.get("capture_backend"), capture_type=value.get("capture_type") or "network",
                    sensor_node_id=node_id,
                )
                count += 1
            return count
        if envelope.envelope_type == "findings":
            count = 0
            for row in list(payload.get("items") or [])[:500]:
                value = dict(row)
                value["source"] = str(value.get("source") or "live")
                if not value["source"].startswith(f"mesh:{node_id}:"):
                    value["source"] = f"mesh:{node_id}:{value['source']}"
                value["sensor_node_id"] = node_id
                allowed = {name: value[name] for name in DetectionFindingV2.__dataclass_fields__ if name in value}
                finding = DetectionFindingV2(**allowed)
                self.db.upsert_detection_finding(finding)
                count += 1
            return count
        if envelope.envelope_type == "hardware_observations":
            count = 0
            for row in list(payload.get("items") or [])[:500]:
                value = dict(row)
                value["sensor_node_id"] = node_id
                self.db.insert_hardware_observation(value)
                count += 1
            return count
        if envelope.envelope_type == "command_results":
            count = 0
            for row in list(payload.get("items") or [])[:100]:
                command_id = str(row.get("command_id") or "")
                if not command_id:
                    continue
                command = self.db.complete_mesh_command(
                    command_id, str(row.get("status") or "failed"), dict(row.get("result") or {}),
                    sensor_node_id=node_id,
                )
                if command:
                    count += 1
            return count
        if envelope.envelope_type == "case_bundle":
            self._ingest_case_bundle(node_id, payload)
            return 1
        if envelope.envelope_type == "lifecycle":
            state = str(payload.get("state") or "")
            if state == "leaving":
                self.db.decommission_sensor_node(node_id, str(payload.get("reason") or "Agent left mesh"))
                return 1
            raise ValueError("Unsupported mesh lifecycle state")
        raise ValueError("Unsupported mesh telemetry type")

    def queue_command(self, node_id: str, action: str, arguments: Dict[str, Any],
                      requested_by: str = "local-operator", ttl_seconds: int = 300) -> Dict[str, Any]:
        if action not in ALLOWED_COMMANDS:
            raise ValueError("Unsupported mesh command")
        node = self.db.get_sensor_node(node_id)
        if not node or node.get("status") in {"revoked", "decommissioned"}:
            raise ValueError("Mesh node is unavailable")
        normalized = json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"))
        key = sha256(f"{node_id}:{action}:{normalized}".encode("utf-8")).hexdigest()
        return self.db.queue_mesh_command(
            str(uuid.uuid4()), node_id, action, arguments or {}, time.time() + max(30, min(int(ttl_seconds), 3600)), key,
            requested_by,
        )

    def revoke(self, node_id: str, reason: str) -> bool:
        return self.db.decommission_sensor_node(node_id, reason)

    @staticmethod
    def decode_join_package(code: str) -> Dict[str, Any]:
        value = str(code or "").strip()
        if not value.startswith("WTJ1-"):
            raise ValueError("Join package must start with WTJ1-")
        encoded = value[5:] + "=" * (-len(value[5:]) % 4)
        try:
            package = json.loads(base64.urlsafe_b64decode(encoded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Join package is malformed") from exc
        if package.get("version") != JOIN_PACKAGE_VERSION:
            raise ValueError("Join package version is unsupported")
        if float(package.get("expires_at") or 0) <= time.time():
            raise ValueError("Join package has expired")
        certificate = str(package.get("ca_certificate_pem") or "").encode("utf-8")
        if certificate_fingerprint(certificate) != package.get("ca_fingerprint"):
            raise ValueError("Join package CA fingerprint does not match its certificate")
        return package

    def _config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write_config(self, value: Dict[str, Any]) -> None:
        temporary = self.config_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        temporary.replace(self.config_path)

    @staticmethod
    def _default_advertised_address() -> str:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))
            value = str(probe.getsockname()[0])
            if value and value != "0.0.0.0":
                return value
        except OSError:
            pass
        finally:
            probe.close()
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"

    def _ingest_case_bundle(self, node_id: str, payload: Dict[str, Any]) -> bool:
        """Durably assemble a command-approved case zip without accepting arbitrary archive paths."""
        command_id = str(payload.get("command_id") or "")
        command = self.db.get_mesh_command(command_id, sensor_node_id=node_id)
        if not command or command.get("action") != "case.export" or command.get("status") not in {"queued", "completed"}:
            raise PermissionError("Case bundle is not bound to an approved case.export command")
        case_id = str(payload.get("case_id") or "")
        archive_digest = str(payload.get("archive_sha256") or "").lower()
        manifest_digest = str(payload.get("manifest_sha256") or "").lower()
        total_chunks = int(payload.get("total_chunks", 0))
        chunk_index = int(payload.get("chunk_index", -1))
        if not case_id or len(case_id) > 160 or not all(char.isalnum() or char in "-_" for char in case_id):
            raise ValueError("Invalid case bundle identifier")
        if len(archive_digest) != 64 or any(char not in "0123456789abcdef" for char in archive_digest):
            raise ValueError("Invalid case bundle digest")
        if len(manifest_digest) != 64 or any(char not in "0123456789abcdef" for char in manifest_digest):
            raise ValueError("Invalid case manifest digest")
        if not 1 <= total_chunks <= 32 or not 0 <= chunk_index < total_chunks:
            raise ValueError("Invalid case bundle chunk range")
        try:
            chunk = base64.b64decode(str(payload.get("data_base64") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid case bundle chunk encoding") from exc
        if len(chunk) > 1024 * 1024 or sha256(chunk).hexdigest() != str(payload.get("chunk_sha256") or ""):
            raise ValueError("Case bundle chunk integrity check failed")

        node_root = Path(self.db.data_dir) / "mesh" / "imports" / node_id / case_id
        node_root.mkdir(parents=True, exist_ok=True)
        state_path = node_root / "state.json"
        state = {"total_chunks": total_chunks, "archive_sha256": archive_digest, "received": []}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError("Case bundle state is unreadable") from exc
        if int(state.get("total_chunks") or 0) != total_chunks or state.get("archive_sha256") != archive_digest:
            raise ValueError("Case bundle chunk conflicts with existing transfer")
        part = node_root / f"{chunk_index:03d}.part"
        if not part.exists():
            part.write_bytes(chunk)
        received = sorted(set(int(value) for value in state.get("received") or []) | {chunk_index})
        state["received"] = received
        state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
        if len(received) != total_chunks:
            return False

        archive = node_root / "bundle.zip"
        with archive.open("wb") as destination:
            for index in range(total_chunks):
                source = node_root / f"{index:03d}.part"
                if not source.is_file():
                    return False
                destination.write(source.read_bytes())
        if archive.stat().st_size > MAX_CASE_BUNDLE_BYTES or sha256(archive.read_bytes()).hexdigest() != archive_digest:
            raise ValueError("Case bundle archive integrity check failed")
        destination = Path(self.db.data_dir) / "cases" / "mesh" / node_id / case_id
        if destination.exists():
            manifests = list(destination.rglob("manifest.json"))
            if len(manifests) == 1 and sha256(manifests[0].read_bytes()).hexdigest() == manifest_digest:
                return True
            raise ValueError("Case bundle destination conflicts with an existing export")
        destination.mkdir(parents=True, exist_ok=False)
        try:
            self._extract_case_archive(archive, destination)
            manifests = list(destination.rglob("manifest.json"))
            if len(manifests) != 1 or sha256(manifests[0].read_bytes()).hexdigest() != manifest_digest:
                raise ValueError("Case bundle manifest integrity check failed")
            manifest_data = json.loads(manifests[0].read_text(encoding="utf-8"))
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        try:
            self.db.enqueue_graph_events([{
                "event_key": f"case:{node_id}:{case_id}", "operation": "case",
                "payload": {
                    "id": case_id, "sensor_node_id": node_id, "target": manifest_data.get("target"),
                    "source": manifest_data.get("source"), "generated_at": manifest_data.get("generated_at"),
                    "manifest_sha256": manifest_digest,
                },
            }])
        except Exception:
            # The imported case remains available even if graph projection is temporarily unavailable.
            pass
        for part in node_root.glob("*.part"):
            part.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)
        try:
            node_root.rmdir()
        except OSError:
            pass
        return True

    @staticmethod
    def _extract_case_archive(archive: Path, destination: Path) -> None:
        try:
            with zipfile.ZipFile(archive) as bundle:
                entries = bundle.infolist()
                total_size = sum(max(0, item.file_size) for item in entries)
                if len(entries) > MAX_CASE_BUNDLE_FILES or total_size > MAX_CASE_BUNDLE_EXPANDED_BYTES or bundle.testzip():
                    raise ValueError("Case bundle exceeds extraction safety limits")
                for entry in entries:
                    relative = PurePosixPath(entry.filename)
                    if relative.is_absolute() or ".." in relative.parts or not entry.filename:
                        raise ValueError("Case bundle contains an unsafe path")
                    output = destination.joinpath(*relative.parts)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(entry, "r") as source, output.open("wb") as target:
                        while block := source.read(1024 * 1024):
                            target.write(block)
        except zipfile.BadZipFile as exc:
            raise ValueError("Case bundle is not a valid zip archive") from exc

    @staticmethod
    def _health_view(node: Dict[str, Any]) -> Dict[str, Any]:
        """Add derived operations metrics without changing the node's reported evidence."""
        result = dict(node)
        health = dict(result.get("health") or {})
        now = time.time()
        captured_at = float(health.get("captured_at") or 0.0)
        last_seen = float(result.get("last_seen_at") or 0.0)
        agent = dict(health.get("agent") or {})
        expires_at = float(health.get("certificate_expires_at") or 0.0)
        health["controller_metrics"] = {
            "clock_skew_seconds": round(now - captured_at, 3) if captured_at else None,
            "ingestion_lag_seconds": round(max(0.0, now - last_seen), 3) if last_seen else None,
            "spool_bytes": int(agent.get("spool_bytes") or 0),
            "spool_capacity_bytes": int(agent.get("max_spool_bytes") or 0),
            "certificate_expires_in_seconds": round(expires_at - now, 3) if expires_at else None,
            "capability_mismatch": False,
        }
        result["health"] = health
        return result

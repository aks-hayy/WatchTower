import base64
from hashlib import sha256
from io import BytesIO
import zipfile

import pytest
from cryptography.fernet import Fernet

from core.mesh.contracts import TelemetryEnvelope
from core.mesh.agent import MeshAgent
from core.mesh.security import new_node_csr
from core.mesh.service import MeshControllerService
from core.mesh.spool import EncryptedMeshSpool
from core.mesh.transport import MeshGrpcClient, MeshGrpcServer
from core.storage.database import WatchtowerDB
from core.storage.models import HardwareObservation, MeshCommand


def _enroll(service, name="node-one"):
    key, csr = new_node_csr("node-test-1")
    token = service.create_enrollment(name=name)["token"]
    return service.enroll({
        "token": token, "node_id": "node-test-1", "name": name, "platform": "Windows",
        "agent_version": "1.0.0", "capabilities": {"sysmon": True}, "csr_pem": csr.decode("utf-8"),
    })


def test_mesh_enrollment_issues_node_certificate_and_consumes_token(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    enrolled = _enroll(service)
    assert enrolled["node"]["id"] == "node-test-1"
    assert "BEGIN CERTIFICATE" in enrolled["client_certificate_pem"]
    assert db.get_sensor_node("node-test-1")["capabilities"]["sysmon"]
    db.close()


def test_mesh_ingest_is_idempotent_and_namespaces_remote_flow_source(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    envelope = TelemetryEnvelope(
        node_id="node-test-1", sequence=1, envelope_type="flows", created_at=100.0,
        payload={"items": [{
            "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "src_port": 50000, "dst_port": 443,
            "protocol": "TCP", "start_time": 100.0, "last_seen": 101.0, "packet_count": 2,
            "byte_count": 200, "source": "live_Ethernet#session", "l7_metadata": {},
        }]},
    )
    first = service.ingest("node-test-1", envelope.to_dict())
    second = service.ingest("node-test-1", envelope.to_dict())
    assert first["accepted"] and first["applied"] == 1
    assert second["duplicate"]
    flow = db.get_flows(limit=1)[0]
    assert flow["sensor_node_id"] == "node-test-1"
    assert flow["source"].startswith("mesh:node-test-1:")
    db.close()


def test_mesh_sessions_are_persisted_with_their_node_provenance(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    envelope = TelemetryEnvelope(
        "node-test-1", 2, "sessions", {"items": [{
            "id": "remote-session-1", "source_type": "network", "device_id": "Ethernet",
            "interface": "Ethernet", "backend": "rust", "source": "live_Ethernet#remote-session-1",
            "started_at": 100.0, "status": "STOPPED", "processing_state": "complete", "complete": True,
        }]}, 100.0,
    )
    assert service.ingest("node-test-1", envelope.to_dict())["applied"] == 1
    rows = db.get_capture_sessions(sensor_node_id="node-test-1")
    assert rows[0]["source"].startswith("mesh:node-test-1:")
    assert rows[0]["backend"] == "rust"
    db.close()


def test_mesh_receipt_rejects_same_sequence_with_different_payload(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    first = TelemetryEnvelope("node-test-1", 4, "health", {"health": {"queue_lag_ms": 1}}, 100.0)
    second = TelemetryEnvelope("node-test-1", 4, "health", {"health": {"queue_lag_ms": 2}}, 100.0)
    assert service.ingest("node-test-1", first.to_dict())["accepted"]
    try:
        service.ingest("node-test-1", second.to_dict())
        assert False, "conflicting sequence must be rejected"
    except ValueError as exc:
        assert "sequence_payload_conflict" in str(exc)
    db.close()


def test_mesh_health_keeps_enrollment_certificate_expiry(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    before = db.get_sensor_node("node-test-1")["health"]["certificate_expires_at"]
    envelope = TelemetryEnvelope(
        "node-test-1", 5, "health", {"health": {"captured_at": 100.0, "queue_lag_ms": 3.0}}, 100.0,
    )
    service.ingest("node-test-1", envelope.to_dict())
    health = db.get_sensor_node("node-test-1")["health"]
    assert health["certificate_expires_at"] == before
    assert health["queue_lag_ms"] == 3.0
    db.close()


def test_mesh_ingests_findings_alerts_and_hardware_with_node_scope(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    finding = TelemetryEnvelope("node-test-1", 10, "findings", {"items": [{
        "finding_type": "recon.port_scan", "detector_id": "scan.detector", "detector_version": "2.0.0",
        "category": "THREAT", "impact": "MEDIUM", "confidence": 0.9, "subject": "10.0.0.5",
        "observed_at": 100.0, "explanation": "bounded scan evidence", "evidence": {"dst_port": 443},
        "signal_family": "recon", "correlation_group": "recon.scan",
    }]}, 100.0)
    alert = TelemetryEnvelope("node-test-1", 11, "alerts", {"items": [{
        "entity_ip": "10.0.0.5", "timestamp": 101.0, "type": "PORT_SCAN", "severity": "MEDIUM",
        "score": 30.0, "explanation": "bounded scan evidence", "source": "live", "evidence": {"ports": 20},
    }]}, 101.0)
    hardware = TelemetryEnvelope("node-test-1", 12, "hardware_observations", {"items": [{
        "timestamp": 102.0, "source_type": "bluetooth", "device_id": "hci0",
        "observation_type": "advertisement", "subject": "AA:BB:CC:DD:EE:FF", "metadata": {"name": "test"},
    }]}, 102.0)
    assert service.ingest("node-test-1", finding.to_dict())["applied"] == 1
    assert service.ingest("node-test-1", alert.to_dict())["applied"] == 1
    assert service.ingest("node-test-1", hardware.to_dict())["applied"] == 1
    assert db.get_detection_findings(sensor_node_id="node-test-1")[0]["sensor_node_id"] == "node-test-1"
    assert db.get_alerts(sensor_node_id="node-test-1")[0]["sensor_node_id"] == "node-test-1"
    observed = db._get_session().query(HardwareObservation).filter_by(sensor_node_id="node-test-1").one()
    assert observed.source_type == "bluetooth"
    db.close()


def test_encrypted_mesh_spool_bounds_and_acknowledges(tmp_path):
    spool = EncryptedMeshSpool(str(tmp_path / "spool.db"), Fernet.generate_key(), max_bytes=16 * 1024 * 1024)
    spool.enqueue(1, {"sequence": 1, "payload": {"x": 1}}, priority=0)
    assert spool.next()["sequence"] == 1
    spool.acknowledge(1)
    assert spool.count_pending() == 0
    spool.close()


def test_mesh_command_completion_is_bound_to_the_originating_node(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    queued = service.queue_command("node-test-1", "capture.stop", {"interface": "Ethernet"})
    envelope = TelemetryEnvelope(
        "node-test-1", 9, "command_results",
        {"items": [{"command_id": queued["id"], "status": "completed", "result": {"status": "stopped"}}]},
        101.0,
    )
    result = service.ingest("node-test-1", envelope.to_dict())
    assert result["applied"] == 1
    command = db._get_session().query(MeshCommand).filter_by(id=queued["id"]).first()
    assert command.status == "completed"
    assert db.pending_mesh_commands("node-test-1") == []
    db.close()


def test_mesh_capture_command_results_reflect_daemon_failure_and_success(
    tmp_path, monkeypatch
):
    import core.mesh.agent as agent_module

    calls = []

    class Database:
        data_dir = tmp_path

    class Daemon:
        def start_engine(self, interface, backend=None, source_type="network"):
            calls.append((interface, backend, source_type))
            if backend == "rust":
                return {
                    "status": "error",
                    "message": "Rust capture backend is not built",
                }
            return {"status": "started", "backend": backend}

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    monkeypatch.setattr(agent_module, "DaemonClient", Daemon)
    agent = MeshAgent(Database())
    agent._write_config({
        "node_id": "node-test",
        "controller": "127.0.0.1",
        "completed_commands": {},
    })

    results = agent._handle_commands([
        {
            "id": "missing-rust",
            "action": "capture.start",
            "arguments": {"interface": "Ethernet"},
        },
        {
            "id": "explicit-python",
            "action": "capture.start",
            "arguments": {"interface": "Ethernet", "backend": "python"},
        },
    ])

    assert results == [
        {
            "command_id": "missing-rust",
            "status": "failed",
            "result": {
                "status": "error",
                "message": "Rust capture backend is not built",
            },
        },
        {
            "command_id": "explicit-python",
            "status": "completed",
            "result": {"status": "started", "backend": "python"},
        },
    ]
    assert calls == [
        ("Ethernet", "rust", "network"),
        ("Ethernet", "python", "network"),
    ]


def test_mesh_case_bundle_is_chunked_hashed_and_extracted_safely(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    command = service.queue_command("node-test-1", "case.export", {"ip": "10.0.0.5"})
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("case/investigation.json", '{"target":"10.0.0.5"}')
        archive.writestr("case/manifest.json", '{"format":"watchtower-case-v1"}')
    bundle = buffer.getvalue()
    manifest_digest = sha256(b'{"format":"watchtower-case-v1"}').hexdigest()
    chunks = [bundle[: max(1, len(bundle) // 2)], bundle[max(1, len(bundle) // 2):]]
    digest = sha256(bundle).hexdigest()
    for index, chunk in enumerate(chunks):
        envelope = TelemetryEnvelope("node-test-1", 30 + index, "case_bundle", {
            "command_id": command["id"], "case_id": "command-test-abcdef0123456789", "case_name": "case",
            "manifest_sha256": manifest_digest, "archive_sha256": digest, "total_chunks": len(chunks),
            "chunk_index": index, "chunk_sha256": sha256(chunk).hexdigest(),
            "data_base64": base64.b64encode(chunk).decode("ascii"),
        }, 110.0 + index)
        assert service.ingest("node-test-1", envelope.to_dict())["applied"] == 1
    imported = tmp_path / "cases" / "mesh" / "node-test-1" / "command-test-abcdef0123456789" / "case" / "investigation.json"
    assert imported.read_text(encoding="utf-8") == '{"target":"10.0.0.5"}'
    assert any(event["operation"] == "case" for event in db.pending_graph_events())
    db.close()


def test_mesh_case_bundle_rejects_path_traversal(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    command = service.queue_command("node-test-1", "case.export", {"ip": "10.0.0.5"})
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../outside.txt", "nope")
    bundle = buffer.getvalue()
    envelope = TelemetryEnvelope("node-test-1", 40, "case_bundle", {
        "command_id": command["id"], "case_id": "command-test-path-traversal", "manifest_sha256": "b" * 64,
        "archive_sha256": sha256(bundle).hexdigest(),
        "total_chunks": 1, "chunk_index": 0, "chunk_sha256": sha256(bundle).hexdigest(),
        "data_base64": base64.b64encode(bundle).decode("ascii"),
    }, 120.0)
    with pytest.raises(ValueError, match="unsafe path"):
        service.ingest("node-test-1", envelope.to_dict())
    db.close()


def test_mesh_case_bundle_requires_controller_approval(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    envelope = TelemetryEnvelope("node-test-1", 41, "case_bundle", {
        "command_id": "not-issued", "case_id": "not-issued-abcdef012345", "manifest_sha256": "a" * 64,
        "archive_sha256": "b" * 64, "total_chunks": 1, "chunk_index": 0,
        "chunk_sha256": sha256(b"x").hexdigest(), "data_base64": base64.b64encode(b"x").decode("ascii"),
    }, 121.0)
    with pytest.raises(PermissionError, match="approved"):
        service.ingest("node-test-1", envelope.to_dict())
    db.close()


def test_mesh_grpc_enrollment_and_mtls_ingest(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    server = MeshGrpcServer(service, "127.0.0.1", enrollment_port=0, ingest_port=0)
    ports = server.start()
    try:
        private_key, csr = new_node_csr("node-grpc-1")
        token = service.create_enrollment(name="grpc-node")["token"]
        bootstrap = MeshGrpcClient("127.0.0.1", ports["enrollment_port"], ports["ingest_port"])
        enrolled = bootstrap.enroll({
            "token": token, "node_id": "node-grpc-1", "name": "grpc-node", "platform": "Linux",
            "agent_version": "1.0.0", "capabilities": {"capture": True}, "csr_pem": csr.decode("utf-8"),
        }, service.authority.ca_certificate())
        client = MeshGrpcClient(
            "127.0.0.1", ports["enrollment_port"], ports["ingest_port"], service.authority.ca_certificate(),
            private_key, enrolled["client_certificate_pem"].encode("utf-8"),
        )
        response = client.ingest(TelemetryEnvelope(
            "node-grpc-1", 1, "health", {"health": {"captured_at": 100.0}}, 100.0,
        ).to_dict())
        assert response["accepted"]
    finally:
        server.stop()
        db.close()


def test_mesh_join_package_is_self_contained_and_fingerprint_bound(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.setup(mode="vpn", address="100.64.0.10")

    created = service.create_enrollment(name="field-sensor")
    package = service.decode_join_package(created["join_code"])

    assert package["controller"] == "100.64.0.10"
    assert package["token"] == created["token"]
    assert package["ca_fingerprint"] == created["ca_fingerprint"]
    assert "BEGIN CERTIFICATE" in package["ca_certificate_pem"]

    corrupted = created["join_code"][:-1] + ("A" if created["join_code"][-1] != "A" else "B")
    with pytest.raises(ValueError):
        service.decode_join_package(corrupted)
    db.close()


def test_direct_public_controller_setup_requires_explicit_risk_acknowledgement(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)

    with pytest.raises(ValueError, match="explicit acknowledgement"):
        service.setup(mode="public", address="sensor.example.net")

    configured = service.setup(
        mode="public",
        address="sensor.example.net",
        acknowledge_public_risk=True,
    )
    assert configured["configuration"]["mode"] == "public"
    db.close()


def test_node_decommission_rejects_commands_and_preserves_node_history(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    service = MeshControllerService(db)
    service.initialize("127.0.0.1")
    _enroll(service)
    command = service.queue_command("node-test-1", "capture.start", {"interface": "eth0"})

    assert service.revoke("node-test-1", "retired by operator")
    node = db.get_sensor_node("node-test-1")
    persisted = db._get_session().query(MeshCommand).filter_by(id=command["id"]).one()

    assert node["status"] == "decommissioned"
    assert persisted.status == "rejected"
    assert "node_decommissioned" in persisted.result_json
    with pytest.raises(ValueError, match="unavailable"):
        service.queue_command("node-test-1", "capture.stop", {"interface": "eth0"})
    db.close()

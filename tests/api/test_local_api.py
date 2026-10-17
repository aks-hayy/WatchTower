from dataclasses import dataclass
from types import SimpleNamespace
import time

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from core.api.server import create_app
from core.capture_sources.base import CaptureSourceRegistry


@dataclass(frozen=True)
class FakeDevice:
    source_type: str = "network"
    device_id: str = "Ethernet"
    name: str = "Ethernet"
    description: str = "Test adapter"
    addresses: list = None
    backends: list = None
    available: bool = True
    unavailable_reason: str = ""

    def __post_init__(self):
        object.__setattr__(self, "addresses", self.addresses or ["192.168.50.10"])
        object.__setattr__(self, "backends", self.backends or ["python", "rust"])


class FakeRegistry:
    def list_devices(self):
        return [FakeDevice()]

    def list_sources(self):
        return [{
            "source_type": "network", "name": "FakeNetworkSource", "api_version": 1,
            "enabled": True, "valid": True, "errors": 0, "last_error": "",
            "device_count": 1, "backends": ["python", "rust"],
        }]


class FakeDaemon:
    def __init__(self, running=True):
        self.running = running
        self.started = []
        self.stopped = []

    def get_status(self):
        if not self.running:
            return {"running": False}
        return {
            "running": True,
            "healthy": True,
            "interfaces": ["Ethernet"],
            "engines": {
                "Ethernet": {
                    "backend": "python",
                    "source_type": "network",
                    "session_id": "session-1",
                    "received_packets": 12,
                    "dropped_packets": 0,
                }
            },
        }

    def start_engine(self, interface, backend, source_type):
        self.started.append((interface, backend, source_type))
        return {"status": "started", "interface": interface, "backend": backend}

    def stop_engine(self, interface):
        self.stopped.append(interface)
        return {"status": "stopped", "interface": interface}


class FakeDatabase:
    def __init__(self):
        self.reset = False

    def get_capture_sessions(self, interface=None, limit=100):
        return [{"id": "session-1", "interface": "Ethernet", "source": "live_Ethernet", "status": "RUNNING"}]

    def get_flows(self, source=None, limit=50, interface=None, capture_session_id=None):
        return [{
            "id": 1,
            "src_ip": "192.168.50.10",
            "dst_ip": "1.1.1.1",
            "src_port": 52100,
            "dst_port": 443,
            "protocol": "TCP",
            "start_time": 100.0,
            "last_seen": 101.0,
            "packet_count": 12,
            "byte_count": 2048,
            "duration": 1.0,
            "source": "live_Ethernet",
            "capture_session_id": "session-1",
            "capture_interface": "Ethernet",
            "capture_backend": "python",
            "capture_type": "network",
            "l7_metadata": '{"tls": {"sni": "one.one.one.one"}}',
        }]

    def get_entity_flows(self, ip, source=None, limit=50, interface=None, capture_session_id=None):
        return self.get_flows(source, limit, interface, capture_session_id)

    def get_endpoint_identities(self, source=None, interface=None, capture_session_id=None, limit=1000):
        return [
            {
                "entity_ip": "192.168.50.10", "source": "live_Ethernet", "capture_interface": "Ethernet",
                "capture_session_id": "session-1", "identity_type": "capture_host",
                "identity_label": "Capture host analyst-laptop (Ethernet)", "confidence": 1.0,
                "verification": "verified", "model_version": "endpoint-identity-v1", "updated_at": 100.0,
            },
            {
                "entity_ip": "1.1.1.1", "source": "live_Ethernet", "capture_interface": "Ethernet",
                "capture_session_id": "session-1", "identity_type": "network_organization",
                "identity_label": "Cloudflare network endpoint (AS13335)", "confidence": 0.93,
                "verification": "captured", "model_version": "endpoint-identity-v1", "updated_at": 100.0,
            },
        ]

    def get_alerts(self, entity_ip=None, source=None, limit=100, include_hidden=False, interface=None, capture_session_id=None):
        return [{
            "id": 7,
            "entity_ip": "192.168.50.10",
            "timestamp": 101.0,
            "type": "TLS Anomaly",
            "severity": "HIGH",
            "score": 60.0,
            "explanation": "Test detection",
            "evidence": '{"dst_ip": "1.1.1.1"}',
            "source": "live_Ethernet",
            "capture_session_id": "session-1",
            "capture_interface": "Ethernet",
            "capture_backend": "python",
            "capture_type": "network",
            "occurrence_count": 1,
        }]

    def get_all_entities(self, source=None):
        return [{
            "ip": "192.168.50.10",
            "mac": "00:11:22:33:44:55",
            "hostname": "analyst-laptop",
            "username": "analyst",
            "os": "Windows",
            "risk_score": 60.0,
            "confidence_score": 0.8,
            "identity_source": "DHCP",
            "alert_count": 1,
            "carved_file_count": 0,
            "total_packets": 12,
            "total_bytes": 2048,
            "source": "live_Ethernet",
        }]

    def get_carved_files(self, entity_ip=None, source=None):
        return []

    def get_today_stats(self, source="live"):
        return {
            "total_packets": 12,
            "total_bytes": 2048,
            "total_flows": 1,
            "protocol_distribution": {"TCP": 12},
            "port_distribution": {"443": 12},
            "top_talkers": {"192.168.50.10": 2048},
            "traffic_timeline": {"100": {"time": 100, "packets": 12, "bytes": 2048}},
        }

    def reset_all(self):
        self.reset = True
        return {"flows": 1, "alerts": 1}


@pytest.fixture
def components():
    return FakeDatabase(), FakeDaemon(), FakeRegistry()


@pytest.fixture
def client(components):
    db, daemon, registry = components
    with TestClient(create_app(db=db, daemon=daemon, registry=registry)) as test_client:
        yield test_client


def test_health_and_request_trace(client):
    response = client.get("/api/v1/health", headers={"X-Request-ID": "trace-123"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "trace-123"
    assert response.headers["Server-Timing"].startswith("app;dur=")
    assert response.json()["daemon"] == "online"


def test_sigma_hunt_api_exposes_partial_evidence_limits(client, monkeypatch):
    from core.forensics.sigma_engine import SigmaEngine

    monkeypatch.setattr(SigmaEngine, "run_hunt_report", lambda *args, **kwargs: {
        "alerts": [], "complete": False,
        "limitations": ["Flow evaluation reached the 1-record limit; matches may be missing."],
        "evaluated_flows": 1, "evaluated_identity_observations": None,
    })

    response = client.post("/api/v1/hunts/sigma", json={"persist": False})

    assert response.status_code == 200
    assert response.json()["complete"] is False
    assert response.json()["limitations"] == [
        "Flow evaluation reached the 1-record limit; matches may be missing."
    ]


def test_sigma_hunt_api_forwards_complete_operator_scope(client, monkeypatch):
    from core.api.service import WatchtowerApiService

    received = {}

    def run_hunt(self, source, interface, rule, persist, capture_session_id=None,
                 time_start=None, time_end=None, sensor_node_id=None):
        received.update(
            source=source, interface=interface, rule=rule, persist=persist,
            capture_session_id=capture_session_id, time_start=time_start,
            time_end=time_end, sensor_node_id=sensor_node_id,
        )
        return {
            "matched": 0, "persisted": False, "active_rules": 2, "rejected_rules": 0,
            "complete": True, "limitations": [], "evaluated_flows": 4,
            "evaluated_identity_observations": 0, "evaluated_rules": 2,
            "coverage_status": "covered",
        }

    monkeypatch.setattr(WatchtowerApiService, "run_hunt", run_hunt)
    response = client.post("/api/v1/hunts/sigma", json={
        "source": "pcap:fixture", "interface": "Ethernet", "rule": "rule-1",
        "persist": False, "capture_session_id": "session-7", "time_start": 10,
        "time_end": 20, "sensor_node_id": "sensor-2",
    })

    assert response.status_code == 200
    assert received == {
        "source": "pcap:fixture", "interface": "Ethernet", "rule": "rule-1",
        "persist": False, "capture_session_id": "session-7", "time_start": 10.0,
        "time_end": 20.0, "sensor_node_id": "sensor-2",
    }
    assert response.json()["coverage_status"] == "covered"


def test_topology_api_forwards_time_window(client, monkeypatch):
    from core.api.service import WatchtowerApiService

    received = {}

    def topology_page(self, source, interface, session, limit, cursor, node, time_start, time_end):
        received.update(time_start=time_start, time_end=time_end)
        return {"nodes": [], "edges": [], "next_cursor": None, "limit": 25}

    monkeypatch.setattr(WatchtowerApiService, "topology_page", topology_page)
    response = client.get(
        "/api/v2/topology?source=pcap:fixture&interface=Ethernet&session=s-1&node=n-2&limit=25&time_start=10&time_end=20"
    )

    assert response.status_code == 200
    assert received["time_start"] == 10
    assert received["time_end"] == 20


def test_sigma_hunt_rejects_reversed_time_window_without_running(client, monkeypatch):
    from core.api.service import WatchtowerApiService

    invoked = False

    def unexpected_run(*args, **kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("invalid scope must be rejected before starting the hunt")

    monkeypatch.setattr(WatchtowerApiService, "run_hunt", unexpected_run)
    response = client.post("/api/v1/hunts/sigma", json={
        "time_start": 20, "time_end": 10, "persist": False,
    })

    assert response.status_code == 422
    assert invoked is False


def test_health_calls_stopped_sensor_offline_with_specific_recovery(client, components):
    _db, daemon, _registry = components
    daemon.running = False

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "offline"
    assert response.json()["daemon"] == "offline"
    assert "tower start" in response.json()["next_action"]


def test_controller_health_reports_api_ready_without_a_local_capture_daemon(client, components, monkeypatch):
    _db, daemon, _registry = components
    daemon.running = False
    monkeypatch.setenv("WATCHTOWER_DEPLOYMENT_ROLE", "controller")

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    health = response.json()
    assert health["status"] in {"ok", "degraded"}
    assert health["deployment_role"] == "controller"
    assert health["daemon"] == "not_applicable"
    assert health["capture_state"] == "unavailable"
    assert "Pair a native sensor" in health["next_action"]


def test_flow_contract_preserves_capture_provenance(client):
    response = client.get("/api/v1/flows", params={"interface": "Ethernet", "session": "session-1"})
    assert response.status_code == 200
    flow = response.json()[0]
    assert flow["flow_id"] == "192.168.50.10:52100 -> 1.1.1.1:443/TCP"
    assert flow["capture_interface"] == "Ethernet"
    assert flow["capture_session_id"] == "session-1"
    assert flow["l7_metadata"]["tls"]["sni"] == "one.one.one.one"
    assert flow["src_identity"]["identity_type"] == "capture_host"
    assert flow["dst_identity"]["identity_label"] == "Cloudflare network endpoint (AS13335)"


def test_stats_and_alert_contracts_are_normalized(client):
    stats = client.get("/api/v1/stats").json()
    assert stats["total_packets"] == 12
    assert stats["alerts"]["high"] == 1
    assert stats["protocols"][0]["protocol"] == "TCP"
    alert = client.get("/api/v1/alerts").json()[0]
    assert alert["evidence"]["dst_ip"] == "1.1.1.1"


def test_capture_actions_are_delegated(client, components):
    _db, daemon, _registry = components
    started = client.post("/api/v1/capture/start", json={
        "interface": "Ethernet", "backend": "rust", "source_type": "network",
    })
    assert started.status_code == 200
    assert daemon.started == [("Ethernet", "rust", "network")]
    start_operation = started.json()["operation"]
    assert started.json()["status"] == "started"
    assert start_operation["state"] == "running"
    assert start_operation["effective_scope"] == {
        "interface": "Ethernet", "backend": "rust", "source_type": "network",
    }
    assert start_operation["next_actions"] == ["Refresh this operation to see progress."]
    stopped = client.post("/api/v1/capture/stop", json={"interface": "Ethernet"})
    assert stopped.status_code == 200
    assert daemon.stopped == ["Ethernet"]
    assert stopped.json()["operation"]["state"] == "complete"


def test_omitted_capture_backend_uses_source_policy(client, components, monkeypatch):
    _db, daemon, _registry = components
    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)

    network = client.post("/api/v1/capture/start", json={"interface": "Ethernet"})
    bluetooth = client.post("/api/v1/capture/start", json={
        "interface": "hci0", "source_type": "bluetooth",
    })
    unsupported = client.post("/api/v1/capture/start", json={
        "interface": "hci0", "source_type": "bluetooth", "backend": "rust",
    })

    assert network.status_code == 200
    assert bluetooth.status_code == 200
    assert unsupported.status_code == 422
    assert daemon.started == [
        ("Ethernet", "rust", "network"),
        ("hci0", "python", "bluetooth"),
    ]


def test_v2_capture_stop_returns_draining(client, components):
    _db, daemon, _registry = components
    response = client.post("/api/v2/captures/session-1/stop", json={"reason": "operator_stop"})
    assert response.status_code == 202
    assert response.json()["status"] == "draining"
    assert response.json()["operation"]["operation_id"] == "session-1"
    assert response.json()["operation"]["state"] == "running"
    deadline = time.time() + 1
    while not daemon.stopped and time.time() < deadline:
        time.sleep(0.01)
    assert daemon.stopped == ["Ethernet"]


def test_capture_session_projection_exposes_operation_without_replacing_legacy_state(client):
    response = client.get("/api/v2/captures/session-1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "RUNNING"
    assert payload["processing_state"] == "running"
    assert payload["operation"]["operation_id"] == "session-1"
    assert payload["operation"]["state"] == "running"
    assert payload["operation"]["effective_scope"] == {
        "source": "live_Ethernet", "interface": "Ethernet", "session_id": "session-1",
    }


def test_mesh_lifecycle_failure_is_projected_as_failed_operation(client, components, monkeypatch):
    components[0].data_dir = "fixture"
    monkeypatch.setattr("core.mesh.runtime.MeshRuntimeManager.__init__", lambda _self, _data_dir: None)
    monkeypatch.setattr(
        "core.mesh.runtime.MeshRuntimeManager.start_controller",
        lambda _self: {"state": "failed", "running": False, "error": "controller binary missing"},
    )

    response = client.post("/api/v2/mesh/controller/start")

    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "failed"
    assert payload["running"] is False
    assert payload["operation"]["state"] == "failed"
    assert payload["operation"]["completeness"] == "partial"
    assert payload["operation"]["error"]["detail"] == "controller binary missing"
    assert payload["operation"]["next_actions"] == [
        "Review the error and retry when resolved.",
    ]


@pytest.mark.parametrize(
    ("method_name", "arguments", "legacy_result", "expected_state", "next_action"),
    [
        (
            "initialize", ("127.0.0.1",), {"authority_ready": True}, "complete",
            "Review controller status and configure its advertised address.",
        ),
        (
            "setup", ("vpn", "10.0.0.1", 9443, 9444, False), {"configuration": {"mode": "vpn"}}, "complete",
            "Start the controller when ready to accept sensor connections.",
        ),
        (
            "rotate_certificate", (), {"rotated": True, "restart_required": True}, "complete",
            "Restart the controller to activate the rotated listener certificate.",
        ),
        (
            "create_enrollment", ("edge sensor", 3600, 1), {"id": "enrollment-1", "token": "secret"}, "complete",
            "Use the enrollment code to join the intended sensor securely.",
        ),
    ],
)
def test_mesh_configuration_operations_include_truthful_envelope(
    monkeypatch, method_name, arguments, legacy_result, expected_state, next_action,
):
    from core.api.service import WatchtowerApiService

    class FakeMesh:
        def __getattr__(self, name):
            assert name == method_name
            return lambda *args, **kwargs: dict(legacy_result)

    service = WatchtowerApiService(db=SimpleNamespace(data_dir="fixture"), daemon=object(), registry=object())
    monkeypatch.setattr(service, "mesh", lambda: FakeMesh())

    if method_name == "initialize":
        result = service.mesh_initialize(*arguments)
    elif method_name == "setup":
        result = service.mesh_setup(*arguments)
    elif method_name == "rotate_certificate":
        monkeypatch.setattr("core.mesh.runtime.MeshRuntimeManager.__init__", lambda _self, _data_dir: None)
        monkeypatch.setattr(
            "core.mesh.runtime.MeshRuntimeManager.controller_status",
            lambda _self: {"running": False},
        )
        result = service.mesh_rotate_certificate(*arguments)
    else:
        result = service.mesh_enrollment(*arguments)

    assert result["operation"]["state"] == expected_state
    assert result["operation"]["completeness"] == "complete"
    assert result["operation"]["next_actions"] == [next_action]
    assert all(result[key] == value for key, value in legacy_result.items())


def test_mesh_revoke_operation_is_reported_complete_and_retains_legacy_fields(monkeypatch):
    from core.api.service import WatchtowerApiService

    class FakeMesh:
        @staticmethod
        def revoke(node_id, reason):
            return node_id == "sensor-1" and reason == "retired"

    service = WatchtowerApiService(db=object(), daemon=object(), registry=object())
    monkeypatch.setattr(service, "mesh", lambda: FakeMesh())

    result = service.mesh_revoke("sensor-1", "retired")

    assert result["status"] == "decommissioned"
    assert result["historical_evidence_retained"] is True
    assert result["operation"]["state"] == "complete"
    assert result["operation"]["completeness"] == "complete"
    assert result["operation"]["effective_scope"] == {"node_id": "sensor-1"}


def test_capture_start_bootstraps_offline_daemon(client, components, monkeypatch):
    _db, daemon, _registry = components
    daemon.running = False
    monkeypatch.setattr("core.daemon.manager.DaemonManager.ensure_running", lambda silent=False: True)

    response = client.post("/api/v1/capture/start", json={
        "interface": "Ethernet", "backend": "python", "source_type": "network",
    })

    assert response.status_code == 200
    assert daemon.started == [("Ethernet", "python", "network")]


def test_plugin_inventory_includes_forensic_and_hardware_plugins(client):
    response = client.get("/api/v1/plugins")
    assert response.status_code == 200
    payload = response.json()
    assert payload["parsers"]
    assert payload["detectors"]
    assert payload["hardware"][0]["source_type"] == "network"


def test_plugin_calibration_api_returns_ui_summaries(client, monkeypatch):
    from core.api.service import WatchtowerApiService
    from core.calibration.service import CalibrationService

    target = {
        "detector_id": "watchtower.credential.ftp",
        "detector_version": "2.0.0",
        "finding_type": "credential.cleartext.ftp",
        "calibration_level": "UNCALIBRATED",
        "effective_cap": 5.0,
        "attestation_digest": "",
        "stale_reason": "",
        "report_count": 0,
    }
    report = {
        "report_path": "data/calibration/reports/report.json",
        "digest": "abc123",
        "created_at": 100.0,
        "backend_selection": "all",
        "passed": True,
        "awarded_level": "CORPUS_VALIDATED",
        "failures": [],
        "field_failures": ["requires 30 relevant benign host-days"],
        "metrics": {"precision": 1.0, "recall": 1.0, "false_positive": 0},
        "target": {
            "detector_id": "watchtower.credential.ftp",
            "detector_version": "2.0.0",
            "finding_type": "credential.cleartext.ftp",
        },
        "cases": [{"large": "hidden from UI response"}],
    }

    monkeypatch.setattr(CalibrationService, "status", lambda self, detector_id=None: {
        "model_version": "behavioral-v2.1",
        "targets": [target],
    })
    monkeypatch.setattr(CalibrationService, "run", lambda self, detector_id, finding_type=None, backend="all": {
        "detector_id": detector_id,
        "passed": True,
        "reports": [report],
    })
    monkeypatch.setattr(CalibrationService, "promote", lambda self, report_path, reviewer, reason: {
        "promoted": True,
        "calibration_level": "CORPUS_VALIDATED",
        "target": report["target"],
    })
    monkeypatch.setattr(WatchtowerApiService, "_latest_calibration_report", lambda self, detector_id, finding_type: None)

    status = client.get("/api/v1/plugins/calibration/status")
    assert status.status_code == 200
    assert status.json()["targets"][0]["trust_basis"] == "uncalibrated"
    assert status.json()["targets"][0]["trust_label"] == "UNCALIBRATED"
    assert status.json()["targets"][0]["latest_report"] is None

    run = client.post("/api/v1/plugins/calibration/run", json={
        "detector_id": "watchtower.credential.ftp",
        "finding_type": "credential.cleartext.ftp",
        "backend": "all",
    })
    assert run.status_code == 200
    payload = run.json()
    assert payload["passed"] is True
    assert payload["reports"][0]["trust_basis"] == "corpus"
    assert payload["reports"][0]["metrics"]["precision"] == 1.0
    assert "cases" not in payload["reports"][0]

    promoted = client.post("/api/v1/plugins/calibration/promote", json={
        "report_path": "data/calibration/reports/report.json",
        "reviewer": "analyst",
        "reason": "reviewed in UI",
    })
    assert promoted.status_code == 200
    assert promoted.json()["promoted"] is True
    assert promoted.json()["status"]["targets"][0]["finding_type"] == "credential.cleartext.ftp"


def test_plugin_calibration_verify_api_marks_stale_attestations_untrusted(client, monkeypatch):
    from core.calibration.service import CalibrationService

    # Verification is about the API's stale-trust presentation contract, not
    # whether this checkout's mutable, content-addressed attestations happen
    # to be stale today.
    monkeypatch.setattr(CalibrationService, "verify", lambda self: {
        "valid": False,
        "errors": [
            "watchtower.application.abuse/credential.cleartext.generic: "
            "stale calibration dependency: core/calibration/service.py"
        ],
        "targets": [{
            "detector_id": "watchtower.application.abuse",
            "finding_type": "credential.cleartext.generic",
            "level": "FIELD_CALIBRATED",
            "valid": False,
            "reason": "stale calibration dependency: core/calibration/service.py",
        }],
    })

    response = client.post("/api/v1/plugins/calibration/verify")

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
    targets = payload["targets"]
    stale = next(
        item for item in targets
        if item["detector_id"] == "watchtower.application.abuse"
        and item["finding_type"] == "credential.cleartext.generic"
    )
    assert stale["valid"] is False
    assert stale["level"] == "FIELD_CALIBRATED"  # Declared policy level, not effective trust.
    assert stale["trust_basis"] == "unknown"
    assert stale["trust_label"] == "TRUST UNKNOWN"
    assert stale["reason"] == "stale calibration dependency: core/calibration/service.py"
    assert stale["attestation_digest"]

def test_validation_errors_are_structured(client):
    response = client.post("/api/v1/capture/start", json={"interface": "", "backend": "python"})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "validation_error"
    assert payload["request_id"]


def test_graph_rejects_invalid_target_scope_without_running_a_widened_query(client):
    from core.graph.service import EvidenceGraphService, GraphConfig

    graph = EvidenceGraphService(
        db=SimpleNamespace(local_sensor_node_id=lambda: "node-a"),
        config=GraphConfig(enabled=False),
    )
    graph._require_available = lambda: None
    graph.status = lambda: {"freshness": "current"}
    queries = []
    graph._run = lambda query, parameters: (queries.append(parameters) or [{
        "node_rows": [], "edge_rows": [], "items": [],
    }])
    client.app.state.service._graph = graph

    response = client.get("/api/v2/graph/neighborhood/203.0.113.10?target_ips=not-an-ip")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_scope"
    assert queries == []


def test_reset_requires_phrase_and_idle_capture(client, components):
    db, daemon, _registry = components
    response = client.post("/api/v1/database/reset", json={"confirmation": "yes"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "confirmation_required"
    daemon.running = False
    response = client.post("/api/v1/database/reset", json={"confirmation": "RESET WATCHTOWER"})
    assert response.status_code == 200
    assert db.reset is True

from dataclasses import dataclass
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
    stopped = client.post("/api/v1/capture/stop", json={"interface": "Ethernet"})
    assert stopped.status_code == 200
    assert daemon.stopped == ["Ethernet"]


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
    deadline = time.time() + 1
    while not daemon.stopped and time.time() < deadline:
        time.sleep(0.01)
    assert daemon.stopped == ["Ethernet"]


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
    assert status.json()["targets"][0]["latest_report"] is None

    run = client.post("/api/v1/plugins/calibration/run", json={
        "detector_id": "watchtower.credential.ftp",
        "finding_type": "credential.cleartext.ftp",
        "backend": "all",
    })
    assert run.status_code == 200
    payload = run.json()
    assert payload["passed"] is True
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


def test_validation_errors_are_structured(client):
    response = client.post("/api/v1/capture/start", json={"interface": "", "backend": "python"})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "validation_error"
    assert payload["request_id"]


def test_reset_requires_phrase_and_idle_capture(client, components):
    db, daemon, _registry = components
    response = client.post("/api/v1/database/reset", json={"confirmation": "yes"})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "confirmation_required"
    daemon.running = False
    response = client.post("/api/v1/database/reset", json={"confirmation": "RESET WATCHTOWER"})
    assert response.status_code == 200
    assert db.reset is True

from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import subprocess
import sys
from threading import Thread

import pytest

import core.forensics.engine as engine_module
from core.forensics.engine import ForensicsEngine
from core.cli.modules.forensics import ForensicsModule
from core.daemon.client import DaemonClient
from core.investigation.export import CaseExporter
from core.investigation.service import InvestigationService
from core.operations.health import HealthService
from core.operations.capabilities import CapabilityRegistry
from core.packet_engine.config import PacketEngineConfig
from core.packet_engine.schemas import FlowAggregate
from core.storage.database import WatchtowerDB


def test_packet_engine_config_rejects_unsafe_values(tmp_path):
    config = PacketEngineConfig(
        window_size=0,
        step_size=5,
        worker_count=0,
        monitoring_mode="INVALID",
        max_flow_table_size=10,
        data_dir=str(tmp_path.resolve()),
    )

    errors = config.validate(raise_on_error=False)

    assert len(errors) == 5
    with pytest.raises(ValueError, match="Invalid packet engine configuration"):
        config.validate()


def test_health_service_checks_database_schema_and_storage(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))

    report = HealthService(db).run()

    checks = {check["name"]: check for check in report["checks"]}
    assert report["status"] in {"pass", "warn"}
    assert checks["configuration"]["status"] == "pass"
    assert checks["database_integrity"]["detail"] == "ok"
    assert checks["database_schema"]["status"] == "pass"
    assert checks["data_directory"]["status"] == "pass"
    db.close()


def test_health_service_preserves_capability_recovery_actions(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    monkeypatch.setattr(CapabilityRegistry, "summary", lambda self: {
        "ollama": {
            "available": False,
            "state": "needs_test",
            "reason": "provider has not been tested",
            "next_action": "Run tower ai provider test.",
        },
    })

    report = HealthService(db).run()

    check = next(item for item in report["checks"] if item["name"] == "capability:ollama")
    assert check["status"] == "warn"
    assert check["detail"] == "provider has not been tested"
    assert check["next_action"] == "Run tower ai provider test."
    db.close()


def test_doctor_json_fails_overall_when_daemon_is_stopped(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    monkeypatch.setattr(DaemonClient, "get_status", lambda self: {
        "running": False,
        "healthy": False,
        "interfaces": [],
    })
    module = ForensicsModule.__new__(ForensicsModule)
    module.db = db

    report = module.doctor(json_output=True)

    assert report["daemon"]["status"] == "fail"
    assert report["daemon"]["next_action"] == "Start WatchTower with 'tower start'."
    assert report["status"] == "fail"
    db.close()


def test_controller_doctor_checks_local_api_and_marks_native_daemon_not_applicable(tmp_path, monkeypatch):
    class ControllerHealthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = json.dumps({
                "status": "ok",
                "version": "test",
                "database": "ok",
                "daemon": "not_applicable",
                "deployment_role": "controller",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), ControllerHealthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("WATCHTOWER_DEPLOYMENT_ROLE", "controller")
    monkeypatch.setattr("core.context.context.ui_port", server.server_port)
    daemon_calls = []
    monkeypatch.setattr(DaemonClient, "get_status", lambda self: daemon_calls.append(True) or {"running": False})
    db = WatchtowerDB(data_dir=str(tmp_path))
    module = ForensicsModule.__new__(ForensicsModule)
    module.db = db

    try:
        report = module.doctor(json_output=True)
    finally:
        db.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    checks = {check["name"]: check for check in report["checks"]}
    assert checks["controller_api"]["status"] == "pass"
    assert report["daemon"]["status"] == "not_applicable"
    assert report["daemon"]["state"] == "not_applicable"
    assert report["status"] != "fail"
    assert daemon_calls == []


def test_doctor_install_check_treats_stopped_daemon_as_expected(tmp_path):
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "core.packet_engine.main", "doctor", "--install-check", "--json"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["daemon"]["status"] == "warn"
    assert report["daemon"]["state"] == "not_started"
    assert "expected during installation" in report["daemon"]["detail"]
    assert report["daemon"]["next_action"] == "Start WatchTower with 'tower start'."
    assert report["status"] == "warn"


@pytest.mark.parametrize(
    ("arguments", "expected_exit", "expected_status"),
    [
        (["--install-check"], 0, "WARN"),
        ([], 1, "FAIL"),
    ],
)
def test_doctor_human_mode_returns_health_report_to_cli(
    tmp_path, arguments, expected_exit, expected_status
):
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "core.packet_engine.main", "doctor", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
        check=False,
    )

    combined_output = result.stdout + result.stderr
    assert result.returncode == expected_exit, combined_output
    assert "Watchtower Operational Health" in combined_output
    assert expected_status in combined_output
    assert "Traceback" not in combined_output


def test_doctor_exit_code_fails_when_operational_checks_fail(tmp_path):
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "core.packet_engine.main", "doctor", "--json"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 1, result.stderr
    report = json.loads(result.stdout)
    assert report["daemon"]["state"] == "stopped"
    assert report["status"] == "fail"


def test_case_export_manifest_hashes_all_evidence_files(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    db.upsert_entity("192.168.1.30", hostname="analyst-pc", timestamp=10.0)
    db.upsert_flow(
        src_ip="192.168.1.30", dst_ip="8.8.8.8", src_port=53000, dst_port=53,
        protocol="UDP", start_time=10.0, last_seen=11.0,
        packet_count=2, byte_count=180, source="live",
    )
    investigation = InvestigationService(db).investigate("192.168.1.30")

    case_dir = CaseExporter(str(tmp_path / "cases")).export(investigation, "case-001")
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["format"] == "watchtower-case-v1"
    assert set(manifest["files"]) == {"investigation.json", "timeline.csv", "evidence.csv"}
    for filename, expected_hash in manifest["files"].items():
        assert sha256((case_dir / filename).read_bytes()).hexdigest() == expected_hash
    db.close()


def test_stream_accumulation_and_reassembly_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_module, "MAX_STREAM_BYTES", 10)
    monkeypatch.setattr(engine_module, "MAX_STREAM_SEGMENTS", 2)
    monkeypatch.setattr(engine_module, "MAX_REASSEMBLY_GAP", 4)
    engine = ForensicsEngine(data_dir=str(tmp_path), silent=True)
    flow_id = ("10.0.0.1", "10.0.0.2", 50000, 443, "TCP")
    engine._raw_streams[flow_id] = {"to_server": [], "to_client": []}

    engine._append_stream_segment(flow_id, "to_server", 1, b"12345678", 1.0)
    engine._append_stream_segment(flow_id, "to_server", 9, b"ABCDEFGH", 2.0)
    engine._append_stream_segment(flow_id, "to_server", 17, b"ignored", 3.0)

    segments = engine._raw_streams[flow_id]["to_server"]
    assert len(segments) == 2
    assert sum(len(segment["payload"]) for segment in segments) == 10

    # A large sequence gap is not padded into memory during reassembly.
    segments[:] = [
        {"seq": 1, "payload": b"abc", "time": 1.0},
        {"seq": 100, "payload": b"def", "time": 2.0},
    ]
    flow = FlowAggregate(flow_id, 1.0, 2.0)
    engine.flow_table[flow_id] = flow
    engine.report.streams[flow_id] = flow
    engine._reassemble_and_carve()
    assert flow.reassembled_to_server == b"abc"
    engine.db.close()

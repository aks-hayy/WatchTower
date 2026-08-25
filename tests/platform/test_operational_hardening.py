from hashlib import sha256
import json

import pytest

import core.forensics.engine as engine_module
from core.forensics.engine import ForensicsEngine
from core.investigation.export import CaseExporter
from core.investigation.service import InvestigationService
from core.operations.health import HealthService
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

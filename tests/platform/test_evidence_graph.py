import json

import pytest
from sqlalchemy import event

from core.graph.service import EvidenceGraphService
from core.storage.database import WatchtowerDB
from core.storage.models import GraphOutbox, HardwareObservation


def test_flow_and_endpoint_observations_enqueue_durable_graph_events(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443, protocol="TCP",
        start_time=10.0, last_seen=11.0, packet_count=2, byte_count=120, source="live_Ethernet#one",
        capture_interface="Ethernet", capture_session_id="one", l7_metadata={"server_name": "dns.google"},
    )
    db.upsert_endpoint_process_observations([{
        "id": "endpoint-test-1", "sensor_node_id": db.local_sensor_node_id(), "event_record_id": "1",
        "event_type": "network_connect", "observed_at": 11.0, "pid": 123, "image": "C:\\agent.exe",
        "protocol": "TCP", "local_ip": "10.0.0.10", "local_port": 50000, "remote_ip": "8.8.8.8",
        "remote_port": 443, "evidence_ref": "sysmon:1", "service_names": ["Agent"],
    }])
    events = db.pending_graph_events(limit=10)
    assert {event["operation"] for event in events} == {"flow", "process_observation"}
    assert db.graph_outbox_status()["pending"] == 2
    db.close()


def test_graph_outbox_batch_uses_one_insert_statement(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    insert_statements = 0

    def count_graph_inserts(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        nonlocal insert_statements
        normalized = statement.lower()
        if normalized.startswith("insert") and "graph_outbox" in normalized:
            insert_statements += 1

    event.listen(db.engine, "before_cursor_execute", count_graph_inserts)
    try:
        events = [
            {
                "event_key": f"flow:test:{index}",
                "operation": "flow",
                "payload": {"index": index},
            }
            for index in range(250)
        ]
        assert db.enqueue_graph_events(events) == 250
        stored = db.pending_graph_events(limit=250)
        assert len(stored) == 250
        assert {item["event_key"] for item in stored} == {
            item["event_key"] for item in events
        }
        assert insert_statements == 1
    finally:
        event.remove(db.engine, "before_cursor_execute", count_graph_inserts)
        db.close()


def test_hardware_observations_and_outbox_are_bulk_persisted(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    insert_statements = 0

    def count_inserts(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        nonlocal insert_statements
        normalized = statement.lower()
        if normalized.startswith("insert") and (
            "hardware_observations" in normalized
            or "graph_outbox" in normalized
        ):
            insert_statements += 1

    event.listen(db.engine, "before_cursor_execute", count_inserts)
    try:
        bulk_insert = getattr(db, "bulk_insert_hardware_observations", None)
        assert callable(bulk_insert)
        observations = [
            {
                "timestamp": float(index),
                "source_type": "bluetooth",
                "device_id": "adapter-1",
                "observation_type": "advertisement",
                "subject": f"device-{index}",
                "metadata": {"rssi": -40 - index},
            }
            for index in range(100)
        ]
        assert bulk_insert(observations) == 100
        stored = db.pending_graph_events(limit=100)
        assert len(stored) == 100
        assert {item["operation"] for item in stored} == {
            "hardware_observation"
        }
        assert insert_statements == 2
    finally:
        event.remove(db.engine, "before_cursor_execute", count_inserts)
        db.close()


@pytest.mark.parametrize("write_mode", ["single", "bulk"])
def test_hardware_and_outbox_rollback_together_on_outbox_failure(
    tmp_path,
    write_mode,
):
    db = WatchtowerDB(data_dir=str(tmp_path))

    def fail_outbox_insert(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        normalized = statement.lower()
        if normalized.startswith("insert") and "graph_outbox" in normalized:
            raise RuntimeError("outbox insert failed")

    event.listen(db.engine, "before_cursor_execute", fail_outbox_insert)
    observation = {
        "timestamp": 10.0,
        "source_type": "bluetooth",
        "device_id": "adapter-1",
        "observation_type": "advertisement",
        "subject": "device-atomic",
        "metadata": {"rssi": -42},
    }
    try:
        with pytest.raises(RuntimeError, match="outbox insert failed"):
            if write_mode == "single":
                db.insert_hardware_observation(observation)
            else:
                db.bulk_insert_hardware_observations([observation])

        session = db._get_session()
        assert session.query(HardwareObservation).count() == 0
        assert session.query(GraphOutbox).count() == 0
    finally:
        event.remove(db.engine, "before_cursor_execute", fail_outbox_insert)
        db.close()


def test_bulk_hardware_returning_is_correlated_and_payload_ids_match_rows(
    tmp_path,
    monkeypatch,
):
    db = WatchtowerDB(data_dir=str(tmp_path))
    session = db._get_session()
    original_execute = session.execute

    def require_ordered_returning(statement, *args, **kwargs):
        table = getattr(statement, "table", None)
        if (
            getattr(table, "name", None) == "hardware_observations"
            and getattr(statement, "_returning", ())
        ):
            returned_names = {
                getattr(column, "name", None)
                for column in statement._returning
            }
            assert (
                getattr(statement, "_sort_by_parameter_order", False)
                or "ingest_token" in returned_names
            ), (
                "bulk hardware RETURNING must preserve order or return a "
                "client correlation key"
            )
        return original_execute(statement, *args, **kwargs)

    monkeypatch.setattr(session, "execute", require_ordered_returning)
    observations = [
        {
            "timestamp": float(index + 1),
            "source_type": "bluetooth",
            "device_id": "adapter-1",
            "observation_type": "advertisement",
            "subject": f"device-{index}",
            "peer": f"peer-{index}",
            "metadata": {"rssi": -40 - index},
        }
        for index in range(12)
    ]
    try:
        assert db.bulk_insert_hardware_observations(observations) == 12
        rows = {
            row.id: row
            for row in session.query(HardwareObservation).all()
        }
        events = db.pending_graph_events(limit=20)
        assert len(events) == len(rows) == 12
        for graph_event in events:
            payload = graph_event["payload"]
            row = rows[payload["id"]]
            assert graph_event["event_key"] == (
                f"hardware:{row.sensor_node_id}:{row.id}"
            )
            assert payload["sensor_node_id"] == row.sensor_node_id
            assert payload["subject"] == row.subject
            assert payload["peer"] == row.peer
            assert payload["metadata"] == json.loads(row.metadata_json)
    finally:
        db.close()


def test_disabled_graph_preserves_outbox_and_reports_actionable_status(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    graph = EvidenceGraphService(db)
    status = graph.status()
    assert not status["enabled"]
    assert not status["available"]
    assert "evidence_graph.yaml" in status["reason"]
    result = graph.materialize()
    assert result["materialized"] == 0
    db.close()


def test_graph_projection_models_scoped_evidence_without_raw_payloads(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    graph = EvidenceGraphService(db)
    writes = []
    graph._run_write = lambda query, parameters: writes.append((query, parameters))
    node = db.local_sensor_node_id()
    graph._apply("flow", {
        "sensor_node_id": node, "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "src_port": 50000,
        "dst_port": 443, "protocol": "TCP", "start_time": 10.0, "last_seen": 11.0,
        "packet_count": 2, "byte_count": 120, "capture_interface": "Ethernet", "capture_session_id": "one",
        "l7_metadata": {"server_name": "dns.google", "geoip": {"asn": "AS15169"}},
    })
    graph._apply("identity", {
        "sensor_node_id": node, "entity_ip": "10.0.0.10", "identity_type": "hostname",
        "identity_label": "workstation", "model_version": "identity-v2", "confidence": 0.9,
    })
    graph._apply("artifact", {
        "sensor_node_id": node, "entity_ip": "10.0.0.10", "sha256": "a" * 64,
        "filename": "sample.exe", "extension": "exe", "size": 100,
    })
    graph._apply("hardware_observation", {
        "sensor_node_id": node, "id": 7, "subject": "AA:BB:CC:DD:EE:FF", "source_type": "bluetooth",
        "observation_type": "advertisement", "timestamp": 11.0,
    })
    graph._apply("finding", {
        "sensor_node_id": node, "id": 9, "subject": "10.0.0.10", "finding_type": "rule.sigma.match",
        "category": "THREAT", "impact": "MEDIUM", "confidence": 0.9, "first_seen": 10.0, "last_seen": 11.0,
        "fingerprint": "f", "evidence": {"rule_id": "sigma-rule-1"},
    })
    graph._apply("case", {
        "sensor_node_id": node, "id": "case-1", "target": "10.0.0.10", "source": "live",
        "generated_at": 11.0, "manifest_sha256": "a" * 64,
    })
    projection = "\n".join(query for query, _parameters in writes)
    assert "FlowConversation" in projection
    assert "Interface" in projection
    assert "Domain" in projection
    assert "Identity" in projection
    assert "Artifact" in projection
    assert "HardwareObservation" in projection
    assert "SigmaRule" in projection
    assert "Case" in projection
    assert "payload" not in projection.lower()
    db.close()

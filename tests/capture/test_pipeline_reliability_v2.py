import time
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from core.api.server import create_app
from core.daemon.client import DaemonClient
from core.detection.contracts import DetectionFindingV2
from core.packet_engine.conversations import ConversationTracker
from core.packet_engine.flow_worker import build_snapshot
from core.packet_engine.schemas import FlowAggregate, PacketEvent
from core.detection.streams import LiveTCPStreamTracker
from core.forensics.engine import ForensicsEngine
from core.forensics.plugins.parsers.ftp_parser import FTPParser
from core.storage.database import WatchtowerDB
import scapy.all as scapy
from sqlalchemy import text


class OfflineDaemon:
    def get_status(self):
        return {"running": False, "interfaces": [], "engines": {}}


class LaggedLiveDaemon:
    def get_status(self):
        return {
            "running": True,
            "engines": {
                "Ethernet": {
                    "session_id": "live-session",
                    "received_packets": 100,
                    "emitted_packets": 100,
                    "processed_packets": 75,
                    "pending_packets": 25,
                    "dropped_packets": 0,
                    "detector_errors": 0,
                    "evidence_dropped": 0,
                    "snapshot_dropped": 0,
                "queue_lag_ms": 6000.0,
                    "queue_lag_max_ms": 7000.0,
                    "last_packet_at": time.time(),
                    "processing_state": "running",
                }
            },
        }


class EmptyRegistry:
    def list_devices(self):
        return []

    def list_sources(self):
        return []


def test_ambiguous_daemon_start_response_is_verified_idempotently():
    class AmbiguousClient(DaemonClient):
        def __init__(self):
            self.calls = 0

        def _send_command(self, command):
            self.calls += 1
            if command["action"] == "start":
                return {"status": "error", "message": "Empty command response from daemon"}
            return {
                "running": True,
                "engines": {
                    "Ethernet": {
                        "capture_alive": True, "backend": "rust", "session_id": "session-rust",
                    }
                },
            }

    result = AmbiguousClient().start_engine("Ethernet", "rust")
    assert result == {
        "status": "started", "interface": "Ethernet", "backend": "rust",
        "session_id": "session-rust", "response_recovered": True,
    }


def event(src, sport, dst, dport, flags, size=100):
    return PacketEvent(
        timestamp=time.time(), src_ip=src, dst_ip=dst, src_port=sport,
        dst_port=dport, protocol="TCP", size=size, flags=flags,
        interface="Ethernet", session_id="session-a",
    )


def test_conversation_tracker_is_session_scoped_and_directional():
    tracker = ConversationTracker(maximum=100)
    outbound = tracker.update(event("10.0.0.5", 50000, "10.0.0.8", 443, "S", 60))
    inbound = tracker.update(event("10.0.0.8", 443, "10.0.0.5", 50000, "SA", 80))
    assert outbound["conversation_direction"] == "to_responder"
    assert inbound["conversation_direction"] == "to_initiator"
    assert inbound["reverse_byte_count"] == 60
    assert inbound["conversation_established"] is True

    other_session = event("10.0.0.5", 50000, "10.0.0.8", 443, "S", 70)
    other_session.session_id = "session-b"
    tracker.update(other_session)
    assert len(tracker.states) == 2


def test_conversation_counters_replace_scalars_in_flow_metadata():
    aggregate = FlowAggregate(("10.0.0.5", "10.0.0.8", 50000, 443, "TCP"), 1.0, 1.0)
    for count in range(1, 10_001):
        aggregate.update(
            100, float(count), "A",
            l7_info={
                "conversation_to_responder_bytes": count * 100,
                "conversation_to_responder_packets": count,
                "reverse_byte_count": 0,
                "peer_novelty": count == 1,
            },
        )
    assert aggregate.l7_metadata["conversation_to_responder_bytes"] == 1_000_000
    assert aggregate.l7_metadata["conversation_to_responder_packets"] == 10_000
    assert aggregate.l7_metadata["reverse_byte_count"] == 0
    assert aggregate.l7_metadata["peer_novelty"] is True
    assert not isinstance(aggregate.l7_metadata["conversation_to_responder_bytes"], list)


def test_dirty_flow_snapshot_only_runs_changed_flow_detectors():
    first = FlowAggregate(("10.0.0.5", "10.0.0.8", 50000, 443, "TCP"), 1.0, 2.0)
    second = FlowAggregate(("10.0.0.5", "10.0.0.9", 50001, 443, "TCP"), 1.0, 2.0)
    first.packet_count = second.packet_count = 1
    first.byte_count = second.byte_count = 100

    class Forensics:
        def __init__(self):
            self.calls = []
            self.db = object()

        def process_live_flow(self, flow, **_kwargs):
            self.calls.append(flow.flow_id)
            return []

    forensics = Forensics()
    table = {first.flow_id: first, second.flow_id: second}
    build_snapshot(
        table, 0.0, 3.0, forensics_engine=forensics, source="live_Ethernet#session",
        detection_flow_ids={first.flow_id},
    )
    assert forensics.calls == [first.flow_id]


def test_flow_novelty_remains_sticky_after_pair_is_learned():
    flow = FlowAggregate(("10.0.0.5", "9.9.9.9", 50000, 9443, "UDP"), 1.0, 2.0)
    flow.packet_count = 1
    flow.byte_count = 100
    flow.l7_metadata["peer_novelty"] = True

    class LearnedBehavior:
        def check_peer_anomaly(self, _source, _destination):
            return 0.0

    build_snapshot(
        {flow.flow_id: flow}, 0.0, 3.0, behavioral_engine=LearnedBehavior(),
        detection_flow_ids={flow.flow_id},
    )
    assert flow.l7_metadata["peer_novelty"] is True


def test_capture_completion_distinguishes_complete_and_partial(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        db.create_capture_session("complete", "network", "Ethernet", "python")
        db.finish_capture_session(
            "complete", metrics={"emitted_packets": 10, "processed_packets": 10},
            processing_state="complete", completion_reason="drained",
        )
        db.create_capture_session("partial", "network", "Ethernet", "python")
        db.finish_capture_session(
            "partial", metrics={"emitted_packets": 10, "processed_packets": 7, "pending_packets": 3},
            processing_state="partial", completion_reason="worker_drain_timeout",
            error="worker_drain_timeout",
        )
        rows = {item["id"]: item for item in db.get_capture_sessions()}
        assert rows["complete"]["complete"] is True
        assert rows["complete"]["processing_state"] == "complete"
        assert rows["partial"]["complete"] is False
        assert rows["partial"]["pending_packets"] == 3
    finally:
        db.close()


def test_legacy_stopped_session_is_migrated_to_explicit_partial(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.create_capture_session("legacy", "network", "Ethernet", "python")
    with db.engine.begin() as connection:
        connection.execute(text(
            "UPDATE capture_sessions SET status='STOPPED', ended_at=2, emitted_packets=10, "
            "processed_packets=0, processing_state='running' WHERE id='legacy'"
        ))
    db.close()

    reopened = WatchtowerDB(data_dir=str(tmp_path))
    try:
        session = reopened.get_capture_session("legacy")
        assert session["processing_state"] == "partial"
        assert session["pending_packets"] == 10
        assert session["completion_reason"] == "legacy_session_without_processing_ack"
    finally:
        reopened.close()


def test_api_requests_release_database_connections(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=db, daemon=OfflineDaemon(), registry=EmptyRegistry())
    try:
        with TestClient(app) as client:
            for _ in range(500):
                assert client.get("/api/v1/health").status_code == 200
            with ThreadPoolExecutor(max_workers=32) as executor:
                statuses = list(
                    executor.map(
                        lambda _: client.get("/api/v2/dashboard/summary").status_code,
                        range(320),
                    )
                )
            assert statuses == [200] * 320
        assert db.engine.pool.checkedout() == 0
        pool = db.pool_status()
        assert pool["checked_out"] == 0
        assert pool["timeouts"] == 0
        assert pool["sqlite_lock_contention"] == 0
        assert pool["checkins"] == pool["checkouts"]
    finally:
        db.close()


def test_v2_details_alert_projection_and_opaque_flow_cursor(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=db, daemon=OfflineDaemon(), registry=EmptyRegistry())
    now = time.time()
    try:
        for index in range(3):
            db.upsert_flow(
                src_ip="10.0.0.5",
                dst_ip=f"10.0.0.{10 + index}",
                src_port=50000 + index,
                dst_port=443,
                protocol="TCP",
                start_time=now + index,
                last_seen=now + index,
                packet_count=10 - index,
                byte_count=1000 - index,
                source="live_Ethernet#session-a",
                capture_interface="Ethernet",
                capture_session_id="session-a",
            )
        db.upsert_detection_finding(DetectionFindingV2(
            finding_type="credential.cleartext.ftp",
            detector_id="watchtower.credential.ftp",
            detector_version="2.1.0",
            category="EXPOSURE",
            impact="HIGH",
            confidence=0.9,
            evidence_quality=1.0,
            calibration_state="UNCALIBRATED",
            signal_family="credential",
            correlation_group="cleartext-credential",
            subject="10.0.0.5",
            target="10.0.0.10",
            observed_at=now,
            source="live_Ethernet#session-a",
            capture_interface="Ethernet",
            capture_session_id="session-a",
            explanation="A test-only FTP credential marker was observed.",
            evidence={"protocol": "FTP", "dst_ip": "10.0.0.10", "dst_port": 21},
        ))
        db.recompute_risk("10.0.0.5", source="live_Ethernet#session-a", persist=True)

        with TestClient(app) as client:
            first = client.get("/api/v2/flows", params={"source": "live", "limit": 2})
            assert first.status_code == 200
            first_page = first.json()
            assert len(first_page["items"]) == 2
            assert first_page["next_cursor"]
            assert not str(first_page["next_cursor"]).isdigit()

            second = client.get(
                "/api/v2/flows",
                params={"source": "live", "limit": 2, "cursor": first_page["next_cursor"]},
            )
            assert second.status_code == 200
            assert len(second.json()["items"]) == 1

            flow_id = first_page["items"][0]["id"]
            detail = client.get(f"/api/v2/flows/{flow_id}")
            assert detail.status_code == 200
            assert detail.json()["risk"]["priority_score"] >= 0
            assert "process_attribution" in detail.json()

            alerts = client.get("/api/v2/alerts", params={"source": "live", "limit": 10})
            assert alerts.status_code == 200
            alert = alerts.json()["items"][0]
            assert alert["finding_type"] == "credential.cleartext.ftp"
            assert alert["impact"] == "HIGH"
            assert "effective_contribution" in alert
            assert "current_entity_priority" in alert

            finding = client.get(f"/api/v2/findings/{alert['id']}")
            assert finding.status_code == 200
            assert finding.json()["risk"]["priority_score"] >= 0

            dashboard = client.get("/api/v2/dashboard/summary")
            assert dashboard.status_code == 200
            assert set(dashboard.json()) >= {"traffic", "risk", "alerts", "capture", "pipeline"}
    finally:
        db.close()


def test_live_stream_tracker_deduplicates_retransmissions_and_reassembles():
    tracker = LiveTCPStreamTracker(maximum_streams=64)
    first_event = event("10.0.0.5", 50000, "10.0.0.8", 21, "PA", 16)
    first_event.l7_info = {"conversation_direction": "to_responder"}
    first = scapy.IP(src=first_event.src_ip, dst=first_event.dst_ip) / scapy.TCP(
        sport=first_event.src_port, dport=first_event.dst_port, flags="PA", seq=1,
    ) / b"USER analyst\r\n"
    first_event.raw = bytes(scapy.Ether() / first)
    snapshot = tracker.update(first, first_event)
    assert snapshot.payload == b"USER analyst\r\n"
    assert tracker.update(first, first_event) is None

    second_event = event("10.0.0.5", 50000, "10.0.0.8", 21, "PA", 16)
    second_event.l7_info = {"conversation_direction": "to_responder"}
    second = scapy.IP(src=second_event.src_ip, dst=second_event.dst_ip) / scapy.TCP(
        sport=second_event.src_port, dport=second_event.dst_port, flags="PA", seq=15,
    ) / b"PASS test-only\r\n"
    snapshot = tracker.update(second, second_event)
    assert snapshot.payload == b"USER analyst\r\nPASS test-only\r\n"


def test_specific_stream_detector_suppresses_generic_secret(tmp_path):
    engine = ForensicsEngine(data_dir=str(tmp_path), silent=True)
    flow = FlowAggregate(("10.0.0.5", "10.0.0.8", 50000, 21, "TCP"), 1.0, 2.0)
    try:
        alerts = engine.process_live_stream(
            flow, b"USER analyst\r\nPASS test-only\r\n", "to_responder", 2.0,
            capture_interface="Ethernet", capture_session_id="session-a",
            capture_backend="python",
        )
        assert [alert.type for alert in alerts] == ["CLEARTEXT_CREDENTIALS"]
        findings = engine.db.get_detection_findings(subject="10.0.0.5")
        assert [item["finding_type"] for item in findings] == ["credential.cleartext.ftp"]
        assert "test-only" not in str(findings).lower()
    finally:
        engine.db.close()


def test_specific_packet_detector_suppresses_generic_secret(tmp_path):
    engine = ForensicsEngine(data_dir=str(tmp_path), silent=True)
    packet = (
        scapy.IP(src="10.0.0.5", dst="10.0.0.8")
        / scapy.TCP(sport=50000, dport=21, flags="PA")
        / b"USER analyst\r\nPASS test-only\r\n"
    )
    packet.time = 2.0
    flow = FlowAggregate(("10.0.0.5", "10.0.0.8", 50000, 21, "TCP"), 2.0, 2.0)
    try:
        _identities, alerts = engine.process_live_packet(
            packet,
            flow,
            capture_interface="Ethernet",
            capture_session_id="session-a",
            capture_backend="python",
        )

        assert [alert.type for alert in alerts] == ["CLEARTEXT_CREDENTIALS"]
        findings = engine.db.get_detection_findings(subject="10.0.0.5")
        assert [item["finding_type"] for item in findings] == [
            "credential.cleartext.ftp"
        ]
    finally:
        engine.db.close()


def test_offline_final_stream_pass_suppresses_generic_ftp_secret(tmp_path):
    pcap = tmp_path / "fragmented-ftp.pcap"
    first_payload = b"USER analyst\r\nPA"
    first = (
        scapy.Ether()
        / scapy.IP(src="10.0.0.5", dst="10.0.0.8")
        / scapy.TCP(sport=50000, dport=21, flags="PA", seq=1)
        / first_payload
    )
    second = (
        scapy.Ether()
        / scapy.IP(src="10.0.0.5", dst="10.0.0.8")
        / scapy.TCP(sport=50000, dport=21, flags="PA", seq=1 + len(first_payload))
        / b"SS test-only\r\n"
    )
    first.time = 1.0
    second.time = 2.0
    scapy.wrpcap(str(pcap), [first, second])

    engine = ForensicsEngine(data_dir=str(tmp_path / "runtime"), silent=True)
    try:
        report = engine.analyze_pcap(str(pcap), backend="python")
        findings = engine.db.get_detection_findings(subject="10.0.0.5")

        assert report.status == "COMPLETE"
        assert [item["finding_type"] for item in findings] == [
            "credential.cleartext.ftp"
        ]
        assert "test-only" not in str(findings).lower()
    finally:
        engine.db.close()


def test_offline_packet_and_stream_paths_coalesce_the_same_ftp_finding(tmp_path):
    pcap = tmp_path / "complete-ftp.pcap"
    packet = (
        scapy.Ether()
        / scapy.IP(src="10.0.0.5", dst="10.0.0.8")
        / scapy.TCP(sport=50000, dport=21, flags="PA", seq=1)
        / b"USER analyst\r\nPASS test-only\r\n"
    )
    packet.time = 1.0
    scapy.wrpcap(str(pcap), [packet])

    engine = ForensicsEngine(data_dir=str(tmp_path / "runtime"), silent=True)
    try:
        engine.analyze_pcap(str(pcap), backend="python")
        findings = engine.db.get_detection_findings(
            subject="10.0.0.5", finding_type="credential.cleartext.ftp"
        )

        assert len(findings) == 1
        assert findings[0]["occurrence_count"] == 1
    finally:
        engine.db.close()


def test_ftp_identity_and_database_never_persist_password_lines(tmp_path):
    packet = scapy.IP(src="10.0.0.5", dst="10.0.0.8") / scapy.TCP(
        sport=50000, dport=21,
    ) / b"USER analyst\r\nPASS test-only\r\n"
    parsed = FTPParser().parse(packet)
    assert parsed["identities"]["username"] == "ftp://analyst"

    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        db.upsert_entity("10.0.0.5", username="ftp://analyst\r\nPASS test-only")
        entity = db.get_entity("10.0.0.5")
        assert entity["username"] == "ftp://analyst"
        assert "test-only" not in str(entity)
    finally:
        db.close()


def test_legacy_flow_metadata_migration_redacts_secret_lines(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.bulk_upsert_flows([{
        "src_ip": "10.0.0.5", "dst_ip": "10.0.0.8", "src_port": 50000,
        "dst_port": 21, "protocol": "TCP", "start_time": 1.0, "last_seen": 1.0,
        "source": "live_Ethernet#legacy", "l7_metadata": {"username": "ftp://analyst"},
    }])
    with db.engine.begin() as connection:
        connection.execute(text(
            "UPDATE flows SET l7_metadata='{\"username\":\"ftp://analyst\\r\\nPASS test-only\","
            "\"authorization\":\"Basic test-only\"}'"
        ))
        connection.execute(text("DELETE FROM schema_migrations WHERE version='behavioral-v2-003'"))
    db.close()

    reopened = WatchtowerDB(data_dir=str(tmp_path))
    try:
        flow = reopened.get_flows(source="live", limit=10)[0]
        assert flow["l7_metadata"]["username"] == "ftp://analyst"
        assert flow["l7_metadata"]["authorization"]["redacted"] is True
        assert "test-only" not in str(flow)
    finally:
        reopened.close()


def test_v2_risk_list_and_pipeline_health_contracts(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.recompute_risk("10.0.0.5", source="live", persist=True)
    app = create_app(db=db, daemon=OfflineDaemon(), registry=EmptyRegistry())
    try:
        with TestClient(app) as client:
            response = client.get("/api/v2/risk/entities", params={"source": "live", "limit": 25})
            assert response.status_code == 200
            payload = response.json()
            assert payload["items"][0]["subject"] == "10.0.0.5"
            assert payload["items"][0]["priority_score"] == 0
            assert payload["items"][0]["scope"] == {"type": "source", "id": "live"}
            health = client.get("/api/v2/pipeline/health").json()
            assert health["pending_packets"] == 0
            assert health["drop_stages"] == {"capture": 0, "snapshot": 0, "evidence": 0}
    finally:
        db.close()


def test_live_daemon_metrics_overlay_exact_session_and_degrade_health(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.create_capture_session("live-session", "network", "Ethernet", "python")
    db.create_capture_session("other-session", "network", "Wi-Fi", "python")
    app = create_app(db=db, daemon=LaggedLiveDaemon(), registry=EmptyRegistry())
    try:
        with TestClient(app) as client:
            sessions = client.get("/api/v1/sessions", params={"limit": 10}).json()
            live = next(item for item in sessions if item["id"] == "live-session")
            other = next(item for item in sessions if item["id"] == "other-session")
            assert live["received_packets"] == 100
            assert live["processed_packets"] == 75
            assert live["pending_packets"] == 25
            assert other["received_packets"] == 0

            health = client.get("/api/v2/pipeline/health").json()
            assert health["status"] == "degraded"
            assert health["pending_packets"] == 25
            assert health["queue_lag_ms"] == 6000.0
            assert health["queue_lag_max_ms"] == 7000.0
    finally:
        db.close()

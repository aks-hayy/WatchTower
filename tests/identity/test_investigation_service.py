from core.investigation.service import InvestigationService
from core.storage.database import WatchtowerDB


def test_investigation_correlates_and_persists_stable_evidence(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "pcap:incident.pcap"
    ip = "10.0.0.50"
    db.upsert_entity(
        ip, hostname="suspect-01", mac="00:11:22:33:44:55",
        confidence=0.9, identity_source="DHCP Parser", timestamp=100.0, source=source,
    )
    db.upsert_flow(
        src_ip=ip, dst_ip="198.51.100.20", src_port=50000, dst_port=443,
        protocol="TCP", start_time=100.0, last_seen=200.0,
        packet_count=40, byte_count=8000, source=source,
    )
    db.insert_alert(
        ip, 150.0, "KNOWN_BAD", "HIGH", 60.0, "Known fingerprint matched",
        evidence={"ja3": "abc123"}, source=source,
    )
    db.insert_carved_file(
        ip, "payload.exe", ".exe", "a" * 64, 2048,
        flow_src=f"{ip}:50000", flow_dst="198.51.100.20:443",
        timestamp=160.0, source=source,
    )
    # This record must not leak into a source-isolated investigation.
    db.upsert_flow(
        src_ip=ip, dst_ip="8.8.8.8", src_port=53000, dst_port=53,
        protocol="UDP", start_time=300.0, last_seen=301.0,
        packet_count=2, byte_count=200, source="pcap:other.pcap",
    )
    db.insert_alert(
        ip, 300.0, "OTHER_SOURCE_ALERT", "CRITICAL", 100.0, "belongs elsewhere",
        source="pcap:other.pcap",
    )

    service = InvestigationService(db)
    result = service.investigate(ip, source=source)

    assert result.verdict == "CRITICAL"
    assert result.risk_score == 90.0
    assert result.alert_groups[0]["max_severity"] == "CRITICAL"
    assert result.alert_groups[0]["refs"] == ["alert:1"]
    assert {item["evidence_ref"] for item in result.evidence} >= {"alert:1", "flow:1", "file:1"}
    correlation = result.correlations[0]
    assert correlation["evidence_ref"] == "alert:1->flow:1"
    assert correlation["confidence"] == 0.9
    assert all("8.8.8.8" not in item["summary"] for item in result.evidence)
    assert result.timeline[0]["ref"] == "flow:1"
    assert {item["ref"] for item in result.timeline} == {"flow:1", "alert:1", "file:1"}
    assert [item["timestamp"] for item in result.timeline] == sorted(
        (item["timestamp"] for item in result.timeline), reverse=True
    )

    first_count = len(db.get_evidence_links(ip, source=source))
    service.investigate(ip, source=source)
    second_count = len(db.get_evidence_links(ip, source=source))
    assert second_count == first_count
    db.close()


def test_investigation_without_alerts_states_low_observed_risk(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity("192.168.1.25", hostname="laptop", timestamp=10.0)

    result = InvestigationService(db).investigate("192.168.1.25")

    assert result.verdict == "LOW OBSERVED RISK"
    assert result.risk_score == 0.0
    assert result.next_actions
    assert "support a low observed risk assessment" in result.summary
    db.close()


def test_investigation_does_not_mix_capture_session_evidence(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    ip = "10.20.0.9"
    db.upsert_entity(
        ip, hostname="name-from-another-capture", username="other-user",
        timestamp=10.0, source="live",
    )
    db.upsert_flow(
        src_ip=ip, dst_ip="198.51.100.9", src_port=51000, dst_port=443,
        protocol="TCP", start_time=100.0, last_seen=110.0,
        packet_count=3, byte_count=300, source="live",
        capture_session_id="session-current", capture_interface="Wi-Fi",
    )
    db.upsert_flow(
        src_ip=ip, dst_ip="203.0.113.77", src_port=51001, dst_port=22,
        protocol="TCP", start_time=200.0, last_seen=210.0,
        packet_count=99, byte_count=9900, source="live",
        capture_session_id="session-other", capture_interface="Ethernet",
    )
    # Session provenance is already represented by the storage model, but the
    # investigation path must apply it instead of returning all files for IP.
    db.insert_carved_file(
        ip, "current.bin", ".bin", "a" * 64, 3, timestamp=105.0,
        source="live", capture_session_id="session-current", capture_interface="Wi-Fi",
    )
    db.insert_carved_file(
        ip, "other.bin", ".bin", "b" * 64, 99, timestamp=205.0,
        source="live", capture_session_id="session-other", capture_interface="Ethernet",
    )

    result = InvestigationService(db).investigate(
        ip, source="live", persist=False, interface="Wi-Fi",
        capture_session_id="session-current", time_start=90.0, time_end=120.0,
    )

    assert len([item for item in result.evidence if item["evidence_type"] == "flow"]) == 1
    assert "198.51.100.9" in result.evidence[0]["summary"]
    assert all("203.0.113.77" not in item["summary"] for item in result.evidence)
    assert {item["details"].get("filename") for item in result.evidence if item["evidence_type"] == "file"} == {
        "current.bin",
    }
    assert result.asset_profile["outbound_bytes"] == 300
    assert result.asset_profile["identity_completeness"] == 0.0
    assert result.confidence < 0.6
    assert result.limitations
    db.close()

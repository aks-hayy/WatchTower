import pytest

from core.intelligence.ip_lookup import IpLookupService
from core.intelligence.local_assets import LocalAssetProfiler, classify_ip
from core.storage.database import WatchtowerDB
from core.storage.models import EndpointProcessObservation


def test_ip_scope_classification_uses_ipaddress_semantics():
    assert classify_ip("10.20.30.40") == ("private", "10.20.30.0/24")
    assert classify_ip("169.254.10.5") == ("link-local", "169.254.10.0/24")
    assert classify_ip("8.8.8.8") == ("global", None)
    with pytest.raises(ValueError):
        classify_ip("not-an-ip")


def test_local_profile_infers_services_role_peers_and_domains(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "pcap:office.pcap"
    db.upsert_entity(
        "10.0.0.10", hostname="files-01", username="ACME\\alice",
        confidence=0.92, identity_source="NTLM Parser", timestamp=100.0, source=source,
    )
    db.upsert_flow(
        src_ip="10.0.0.20", dst_ip="10.0.0.10", src_port=51000, dst_port=445,
        protocol="TCP", start_time=101.0, last_seen=103.0, packet_count=20,
        byte_count=4000, source=source,
    )
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="8.8.8.8", src_port=53000, dst_port=53,
        protocol="UDP", start_time=104.0, last_seen=105.0, packet_count=5,
        byte_count=600, l7_metadata={"dns_query": "updates.example.com"}, source=source,
    )

    profile = LocalAssetProfiler(db).build("10.0.0.10", source=source)

    assert profile.scope == "private"
    assert profile.subnet == "10.0.0.0/24"
    assert profile.role == "File Server"
    assert profile.served_services[0]["name"] == "SMB"
    assert profile.consumed_services[0]["name"] == "DNS"
    assert profile.internal_peers[0]["ip"] == "10.0.0.20"
    assert profile.external_peers[0]["ip"] == "8.8.8.8"
    assert "updates.example.com" in profile.domains
    assert profile.inbound_bytes == 4000
    assert profile.outbound_bytes == 600

    stored = db.get_asset_profile("10.0.0.10", source=source)
    assert stored["role"] == "File Server"
    entity = db.get_entity("10.0.0.10")
    assert entity["asset_role"] is None
    assert entity["username"] == "ACME\\alice"
    assert entity["confidence_score"] == 0.92
    assert entity["first_seen"] == 100.0
    db.close()


def test_empty_local_profile_is_explicit_about_missing_evidence(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity("192.168.50.7", timestamp=50.0)

    profile = LocalAssetProfiler(db).build("192.168.50.7")

    assert profile.role == "Unclassified"
    assert profile.role_confidence == 0.25
    assert profile.identity_completeness == 0.0
    assert any("Insufficient" in reason for reason in profile.role_reasons)
    assert any("incomplete" in insight for insight in profile.insights)
    db.close()


def test_ip_lookup_keeps_every_projection_inside_capture_scope(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    ip = "10.20.0.44"
    node_id = db.local_sensor_node_id()
    db.upsert_entity(ip, hostname="lifetime-name-from-other-capture", timestamp=5.0, source="live")
    for session_id, interface, peer, timestamp, byte_count in (
        ("session-a", "Wi-Fi", "198.51.100.8", 100.0, 120),
        ("session-b", "Ethernet", "203.0.113.8", 200.0, 9900),
    ):
        db.upsert_flow(
            src_ip=ip, dst_ip=peer, src_port=50000, dst_port=443,
            protocol="TCP", start_time=timestamp, last_seen=timestamp + 1,
            packet_count=2, byte_count=byte_count, source="live",
            capture_session_id=session_id, capture_interface=interface,
        )
        db.insert_carved_file(
            ip, f"{session_id}.bin", ".bin", ("a" if session_id == "session-a" else "b") * 64,
            12, timestamp=timestamp, source="live", capture_session_id=session_id,
            capture_interface=interface,
        )
    db.upsert_endpoint_identities([
        {
            "entity_ip": ip, "source": "live", "capture_interface": "Wi-Fi",
            "capture_session_id": "session-a", "model_version": "test-v1",
            "identity_type": "capture_host", "identity_label": "current-host",
            "confidence": 0.8, "verification": "observed", "first_seen": 100.0,
            "last_seen": 101.0,
        },
        {
            "entity_ip": ip, "source": "live", "capture_interface": "Ethernet",
            "capture_session_id": "session-b", "model_version": "test-v1",
            "identity_type": "capture_host", "identity_label": "other-host",
            "confidence": 0.8, "verification": "observed", "first_seen": 200.0,
            "last_seen": 201.0,
        },
    ])
    db._get_session().add(EndpointProcessObservation(
        id="proc-a", sensor_node_id=node_id, event_type="network_connect",
        observed_at=100.5, evidence_ref="process:test", created_at=100.5,
        local_ip=ip, remote_ip="198.51.100.8",
    ))
    db._get_session().commit()

    result = IpLookupService(db).lookup(
        ip, source="live", interface="Wi-Fi", capture_session_id="session-a",
        time_start=90.0, time_end=120.0,
    )

    assert result["asset_profile"]["outbound_bytes"] == 120
    assert result["asset_profile"]["identity_completeness"] == 0.0
    assert result["flow_intelligence"]["total_flows"] == 1
    assert result["endpoint_identity"]["identity_label"] == "current-host"
    assert result["endpoint_processes"] == []
    assert "lifetime-name-from-other-capture" not in str(result["identity"])
    assert result["scope_limitations"]
    db.close()


def test_build_many_uses_cached_source_flows_with_optional_scope_arguments(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_flow(
        src_ip="10.30.0.1", dst_ip="10.30.0.2", src_port=50000, dst_port=445,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=2,
        byte_count=200, source="pcap:fixture.pcap",
    )

    profiles = LocalAssetProfiler(db).build_many(
        ["10.30.0.1", "10.30.0.2"], source="pcap:fixture.pcap",
    )

    assert profiles["10.30.0.1"].outbound_bytes == 200
    assert profiles["10.30.0.2"].inbound_bytes == 200
    db.close()


def test_endpoint_identity_query_applies_target_and_time_scope_before_limit(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    base = {
        "source": "pcap:scope", "capture_interface": "eth0", "capture_session_id": "capture-a",
        "sensor_node_id": "node-a", "model_version": "endpoint-identity-v2",
        "identity_type": "hostname", "identity_state": "probable", "confidence": 0.8,
    }
    db.upsert_endpoint_identities([
        {**base, "entity_ip": "10.0.0.1", "identity_label": "inside-window", "first_seen": 95.0, "last_seen": 105.0},
        {**base, "entity_ip": "10.0.0.2", "identity_label": "wrong-endpoint", "first_seen": 95.0, "last_seen": 105.0},
        {**base, "capture_session_id": "capture-old", "entity_ip": "10.0.0.1",
         "identity_label": "old-observation", "first_seen": 10.0, "last_seen": 20.0},
        {**base, "capture_session_id": "capture-undated", "entity_ip": "10.0.0.1",
         "identity_label": "undated", "first_seen": None, "last_seen": None},
        {**base, "capture_session_id": "capture-start-only", "entity_ip": "10.0.0.1",
         "identity_label": "start-proves-overlap", "first_seen": 95.0, "last_seen": None},
        {**base, "capture_session_id": "capture-end-only", "entity_ip": "10.0.0.1",
         "identity_label": "end-proves-overlap", "first_seen": None, "last_seen": 105.0},
        {**base, "capture_session_id": "capture-ambiguous", "entity_ip": "10.0.0.1",
         "identity_label": "ambiguous", "first_seen": 10.0, "last_seen": None},
    ])

    rows = db.get_endpoint_identities(
        source="pcap:scope", interface="eth0",
        sensor_node_id="node-a", target_ips=["10.0.0.1"],
        time_start=90.0, time_end=110.0, limit=10,
    )

    assert {row["identity_label"] for row in rows} == {
        "inside-window", "start-proves-overlap", "end-proves-overlap",
    }
    db.close()

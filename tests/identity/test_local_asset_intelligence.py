import pytest

from core.intelligence.local_assets import LocalAssetProfiler, classify_ip
from core.storage.database import WatchtowerDB


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
    assert entity["asset_role"] == "File Server"
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

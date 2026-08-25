from core.intelligence.ip_lookup import IpLookupService
from core.storage.database import WatchtowerDB


def test_public_ip_lookup_combines_geo_dns_and_observed_domains(tmp_path, monkeypatch):
    monkeypatch.setattr("core.intelligence.ip_lookup.get_reverse_dns", lambda ip: "dns.google")
    monkeypatch.setattr("core.intelligence.ip_lookup.get_geoip_info", lambda ip: {
        "country": "United States",
        "city": "Mountain View",
        "asn": "AS15169 Google LLC",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "lat": 37.4,
        "lng": -122.0,
    })
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity("8.8.8.8", timestamp=100.0, source="live_Ethernet")
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="8.8.8.8", src_port=53000, dst_port=53,
        protocol="UDP", start_time=101.0, last_seen=102.0, packet_count=5,
        byte_count=600, l7_metadata={"dns_query": "dns.google"}, source="live_Ethernet",
    )

    result = IpLookupService(db).lookup("8.8.8.8", source="live")

    assert result["identity"]["reverse_dns"] == "dns.google"
    assert result["identity"]["company"] == "Google Public DNS"
    assert result["location"]["label"] == "Mountain View, United States"
    assert result["enrichment"]["asn"] == "AS15169 Google LLC"
    assert result["activity"]["flow_count"] == 1
    assert any(item["value"] == "dns.google" for item in result["observed_names"])
    db.close()


def test_sparse_local_ip_lookup_explains_missing_context(tmp_path, monkeypatch):
    monkeypatch.setattr("core.intelligence.ip_lookup.get_reverse_dns", lambda ip: None)
    monkeypatch.setattr("core.intelligence.ip_lookup.get_geoip_info", lambda ip: {
        "country": "Local Network", "city": "Internal", "asn": "Private", "lat": 0.0, "lng": 0.0,
    })
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity("192.168.50.7", timestamp=100.0, source="live_Wi-Fi")

    result = IpLookupService(db).lookup("192.168.50.7", source="live")

    assert result["scope"] == "private"
    assert result["identity"]["company"] is None
    assert result["location"]["label"] == "Local network"
    assert any("No MAC address" in gap for gap in result["gaps"])
    assert any("hostname evidence" in gap for gap in result["gaps"])
    assert result["next_actions"]
    db.close()


def test_lookup_activity_uses_selected_flow_scope_not_lifetime_entity_totals(tmp_path, monkeypatch):
    monkeypatch.setattr("core.intelligence.ip_lookup.get_reverse_dns", lambda ip: None)
    monkeypatch.setattr("core.intelligence.ip_lookup.get_geoip_info", lambda ip: {})
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity("203.0.113.9", packets=9999, bytes_count=999999, timestamp=1.0, source="pcap:old")
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="203.0.113.9", src_port=50000, dst_port=443,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=4, byte_count=400,
        source="pcap:selected",
    )

    result = IpLookupService(db).lookup("203.0.113.9", source="pcap:selected")

    assert result["activity"]["flow_count"] == 1
    assert result["activity"]["total_packets"] == 4
    assert result["activity"]["total_bytes"] == 400
    db.close()


def test_lookup_exposes_flow_service_context_and_action(tmp_path, monkeypatch):
    monkeypatch.setattr("core.intelligence.ip_lookup.get_reverse_dns", lambda ip: None)
    monkeypatch.setattr("core.intelligence.ip_lookup.get_geoip_info", lambda ip: {})
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "live_Ethernet#selected"
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="10.0.0.20", src_port=51000, dst_port=7680,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=4, byte_count=400,
        source=source,
    )

    result = IpLookupService(db).lookup("10.0.0.20", source=source)

    assert result["flow_intelligence"]["services"] == [{
        "name": "Windows Delivery Optimization", "port": 7680, "protocol": "TCP",
        "basis": "well_known_port", "flow_count": 1,
    }]
    assert result["flow_intelligence"]["recommended_actions"]
    db.close()

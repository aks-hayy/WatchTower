import json

import pytest

from core.forensics.plugins.parsers.dns_parser import DNSParser
from core.intelligence.evidence import CaptureEvidence
from core.intelligence.ip_lookup import IpLookupService
from core.intelligence.reindex import EnrichmentReindexer
from core.storage.database import WatchtowerDB


def test_capture_evidence_refuses_generic_ethernet_mac_and_keeps_arp_binding():
    flows = [
        {
            "src_ip": "8.8.8.8", "dst_ip": "10.0.0.10", "protocol": "TCP",
            "l7_metadata": {"mac": "aa:bb:cc:dd:ee:ff"},
        },
        {
            "src_ip": "10.0.0.10", "dst_ip": "255.255.255.255", "protocol": "ARP",
            "l7_metadata": {
                "arp_sender_ip": "10.0.0.10", "arp_sender_mac": "00:11:22:33:44:55",
            },
        },
    ]

    evidence = CaptureEvidence(flows)

    assert evidence.endpoint("8.8.8.8")["mac"] is None
    assert evidence.endpoint("10.0.0.10")["mac"] == {
        "mac": "00:11:22:33:44:55", "source": "arp",
    }
    context = evidence.flow_context(flows[0])
    assert context["purpose"] == "TCP transport observed (0 -> 0)"
    assert context["traffic_direction"] == "external_to_private_network"
    assert context["recommended_action"].startswith("Retain this transport observation")


def test_flow_context_marks_port_context_without_promoting_it_to_identity():
    evidence = CaptureEvidence([
        {
            "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "src_port": 50000,
            "dst_port": 443, "protocol": "TCP", "l7_metadata": {},
        },
    ])

    context = evidence.flow_context({
        "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "src_port": 50000,
        "dst_port": 443, "protocol": "TCP", "l7_metadata": {},
    })

    assert context["purpose"] == "HTTPS service transport observed (443/TCP)"
    assert context["service"] == {
        "name": "HTTPS", "port": 443, "endpoint": "destination", "basis": "well_known_port",
    }
    assert "well_known_port" in context["evidence"]
    assert "identity" not in context["recommended_action"].lower()


def test_flow_context_treats_known_local_directed_broadcast_as_control(monkeypatch):
    monkeypatch.setattr(
        "core.intelligence.evidence._local_address_index",
        lambda: ({"192.168.250.107": {"interface": "Ethernet", "mac": "00:11:22:33:44:55"}}, {"192.168.250.255"}),
    )
    evidence = CaptureEvidence([])

    context = evidence.flow_context({
        "src_ip": "192.168.250.107", "dst_ip": "192.168.250.255", "src_port": 40000,
        "dst_port": 15600, "protocol": "UDP", "l7_metadata": {},
    })

    assert context["traffic_direction"] == "control_or_discovery"
    assert context["purpose"] == "Network control or discovery traffic"
    assert context["recommended_action"].startswith("Treat as local control")


def test_flow_context_labels_standard_delivery_optimization_and_echo_ports():
    evidence = CaptureEvidence([])

    delivery = evidence.flow_context({
        "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 51000,
        "dst_port": 7680, "protocol": "TCP", "l7_metadata": {},
    })
    echo = evidence.flow_context({
        "src_ip": "10.0.0.20", "dst_ip": "10.0.0.10", "src_port": 50000,
        "dst_port": 7, "protocol": "UDP", "l7_metadata": {},
    })

    assert delivery["service"]["name"] == "Windows Delivery Optimization"
    assert delivery["service"]["basis"] == "well_known_port"
    assert echo["service"]["name"] == "Echo"
    assert echo["service"]["basis"] == "well_known_port"


def test_dns_parser_emits_bounded_address_answers():
    import scapy.all as scapy

    packet = (
        scapy.IP(src="10.0.0.10", dst="10.0.0.1")
        / scapy.UDP(sport=53, dport=53000)
        / scapy.DNS(
            qr=1, qd=scapy.DNSQR(qname="api.example.test"),
            an=scapy.DNSRR(rrname="api.example.test", type="A", ttl=120, rdata="203.0.113.8"),
            ancount=1,
        )
    )

    result = DNSParser().parse(packet)

    assert result["metadata"]["dns_is_response"] is True
    assert result["metadata"]["dns_answers"] == [{
        "name": "api.example.test", "address": "203.0.113.8", "type": "A", "ttl": 120,
    }]


def test_lookup_prefers_capture_time_geoip_over_provider(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "live_Ethernet#abc123"
    db.upsert_entity("8.8.8.8", mac="aa:bb:cc:dd:ee:ff", timestamp=1.0, source=source)
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=2, byte_count=200,
        source=source, l7_metadata={"geoip": {
            "country": "United States", "city": "Mountain View", "asn": "AS15169 Google LLC",
            "isp": "Google LLC", "org": "Google LLC", "lat": 1.0, "lng": 2.0,
        }},
    )
    monkeypatch.setattr("core.intelligence.ip_lookup.get_reverse_dns", lambda ip: None)
    monkeypatch.setattr(
        "core.intelligence.ip_lookup.get_geoip_info",
        lambda ip: pytest.fail("provider fallback must not run when capture metadata is present"),
    )

    result = IpLookupService(db).lookup("8.8.8.8", source=source)

    assert result["enrichment"]["org"] == "Google LLC"
    assert result["enrichment"]["evidence_source"] == "capture_flow_metadata"
    assert result["identity"]["mac"] is None
    assert result["asset_profile"]["role"] == "External service endpoint"
    db.close()


def test_lookup_never_uses_public_enrichment_for_private_address(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "live_Ethernet#abc123"
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="10.0.0.20", src_port=50000, dst_port=445,
        protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=2, byte_count=200,
        source=source, l7_metadata={},
    )
    monkeypatch.setattr(
        "core.intelligence.ip_lookup.get_reverse_dns",
        lambda ip: pytest.fail("private addresses must not trigger reverse DNS"),
    )
    monkeypatch.setattr(
        "core.intelligence.ip_lookup.get_geoip_info",
        lambda ip: pytest.fail("private addresses must not trigger GeoIP"),
    )

    result = IpLookupService(db).lookup("10.0.0.20", source=source)

    assert result["enrichment"]["evidence_source"] == "not_applicable"
    assert result["location"]["country"] == "Local Network"
    db.close()


def test_reindex_repairs_derived_identity_without_deleting_flow_evidence(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "live_Ethernet#abc123"
    db.upsert_entity("8.8.8.8", mac="aa:bb:cc:dd:ee:ff", asset_role="Web Server", timestamp=1.0, source=source)
    db.upsert_entity("10.0.0.10", mac="aa:bb:cc:dd:ee:ff", timestamp=1.0, source=source)
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=2, byte_count=200,
        source=source, l7_metadata={"mac": "aa:bb:cc:dd:ee:ff", "geoip": {
            "country": "United States", "asn": "AS15169 Google LLC", "org": "Google LLC",
        }},
    )
    db.upsert_flow(
        src_ip="10.0.0.10", dst_ip="255.255.255.255", src_port=0, dst_port=0,
        protocol="ARP", start_time=1.0, last_seen=2.0, packet_count=1, byte_count=42,
        source=source, l7_metadata={
            "mac": "00:11:22:33:44:55", "arp_sender_ip": "10.0.0.10",
            "arp_sender_mac": "00:11:22:33:44:55", "arp_operation": 2,
        },
    )

    service = EnrichmentReindexer(db)
    preview = service.rebuild(source=source, dry_run=True)
    assert preview["flows"] == 2
    assert db.get_entity("8.8.8.8")["mac"] == "aa:bb:cc:dd:ee:ff"

    result = service.rebuild(source=source)
    public = db.get_entity("8.8.8.8")
    local = db.get_entity("10.0.0.10")
    flows = db.get_flows(source=source, limit=10)

    assert result["backup"] and result["backup"]["sha256"]
    assert public["mac"] is None
    assert public["asset_role"] is None
    assert local["mac"] == "00:11:22:33:44:55"
    assert len(flows) == 2
    assert all("watchtower_intel_v1" in flow["l7_metadata"] for flow in flows)
    assert all(flow["l7_metadata"].get("mac") != "aa:bb:cc:dd:ee:ff" for flow in flows)
    db.close()

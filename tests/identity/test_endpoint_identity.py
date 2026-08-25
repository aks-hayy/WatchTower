from core.intelligence.endpoint_identity import EndpointIdentityResolver
from core.intelligence.host_inventory import HostNetworkInventory
from core.intelligence.reindex import EndpointIdentityReindexer
from core.storage.database import WatchtowerDB


def _inventory():
    return HostNetworkInventory(
        hostname="analyst-host",
        observed_at=200.0,
        local_addresses={"10.0.0.10": {"interface": "Ethernet", "mac": "00:11:22:33:44:55"}},
        neighbors={"10.0.0.1": "aa:bb:cc:dd:ee:ff"},
        roles={"10.0.0.1": {"default_gateway", "dhcp_server", "dns_server"}},
    )


def _flows(source="live_Ethernet#identity"):
    return [
        {
            "src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "src_port": 50000, "dst_port": 443,
            "protocol": "TCP", "start_time": 10.0, "last_seen": 11.0, "source": source,
            "capture_interface": "Ethernet", "capture_session_id": "session-1",
            "l7_metadata": {"geoip": {"org": "Google LLC", "asn": "AS15169 Google LLC", "country": "US"}},
        },
        {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.10", "src_port": 67, "dst_port": 68,
            "protocol": "UDP", "start_time": 12.0, "last_seen": 13.0, "source": source,
            "capture_interface": "Ethernet", "capture_session_id": "session-1",
            "l7_metadata": {"arp_sender_ip": "10.0.0.1", "arp_sender_mac": "aa:bb:cc:dd:ee:ff"},
        },
        {
            "src_ip": "10.0.0.10", "dst_ip": "239.255.255.250", "src_port": 1900, "dst_port": 1900,
            "protocol": "UDP", "start_time": 14.0, "last_seen": 15.0, "source": source,
            "capture_interface": "Ethernet", "capture_session_id": "session-1", "l7_metadata": {},
        },
        {
            "src_ip": "0.0.0.0", "dst_ip": "255.255.255.255", "src_port": 68, "dst_port": 67,
            "protocol": "UDP", "start_time": 16.0, "last_seen": 17.0, "source": source,
            "capture_interface": "Ethernet", "capture_session_id": "session-1", "l7_metadata": {},
        },
    ]


def test_host_inventory_parses_neighbor_and_ipconfig_roles():
    neighbors = HostNetworkInventory.parse_arp_output("  192.168.1.1    00-11-22-33-44-55  dynamic\n")
    roles = HostNetworkInventory.parse_ipconfig_output(
        "Default Gateway . . . . . . . . . : fe80::1\n"
        "                                      192.168.1.1\n"
        "DHCP Server . . . . . . . . . . . : 192.168.1.1\n"
        "DNS Servers . . . . . . . . . . . : 192.168.1.1\n"
    )

    assert neighbors == {"192.168.1.1": "00:11:22:33:44:55"}
    assert roles["192.168.1.1"] == {"default_gateway", "dhcp_server", "dns_server"}
    assert roles["fe80::1"] == {"default_gateway"}


def test_endpoint_identity_resolver_covers_host_public_neighbor_and_special_addresses():
    records = EndpointIdentityResolver(_flows(), inventory=_inventory()).resolve(
        "live_Ethernet#identity", "Ethernet", "session-1",
    )
    by_ip = {record.entity_ip: record for record in records}

    assert by_ip["10.0.0.10"].identity_type == "capture_host"
    assert by_ip["10.0.0.10"].identity_label == "Capture host analyst-host (Ethernet)"
    assert by_ip["8.8.8.8"].identity_type == "network_organization"
    assert "Google LLC" in by_ip["8.8.8.8"].identity_label
    assert by_ip["10.0.0.1"].identity_type == "direct_network_neighbor"
    assert "Default gateway / DHCP server / DNS server" in by_ip["10.0.0.1"].identity_label
    assert by_ip["239.255.255.250"].identity_type == "multicast_group"
    assert by_ip["0.0.0.0"].identity_type == "special_address"
    assert EndpointIdentityResolver.coverage(records)["identified"] == len(records)


def test_identity_reindex_persists_additive_scoped_records_without_changing_flows(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    source = "live_Ethernet#identity"
    for flow in _flows(source):
        db.upsert_flow(
            src_ip=flow["src_ip"], dst_ip=flow["dst_ip"], src_port=flow["src_port"], dst_port=flow["dst_port"],
            protocol=flow["protocol"], start_time=flow["start_time"], last_seen=flow["last_seen"],
            packet_count=1, byte_count=60, source=source, capture_interface="Ethernet",
            capture_session_id="session-1", l7_metadata=flow["l7_metadata"],
        )
    before = len(db.get_flows(source=source, limit=20))

    reindexer = EndpointIdentityReindexer(db, inventory_factory=_inventory)
    result = reindexer.rebuild(source=source)

    identity = db.get_endpoint_identity("8.8.8.8", source=source)
    assert result["identities"] == 6
    assert result["changed_identities"] == 6
    assert result["backup"]["sha256"]
    assert len(db.get_flows(source=source, limit=20)) == before
    assert identity["identity_type"] == "network_organization"
    assert identity["evidence"][0]["kind"] == "capture_geoip"
    db.close()


def test_identity_card_promotes_protocol_names_and_services_to_actionable_evidence():
    flows = [{
        "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 51000, "dst_port": 445,
        "protocol": "TCP", "start_time": 10.0, "last_seen": 11.0,
        "l7_metadata": {"tls_sni": "fileserver.example.test"},
    }]
    record = next(record for record in EndpointIdentityResolver(flows, inventory=_inventory()).resolve(
        "live_Ethernet#identity", "Ethernet", "session-1",
    ) if record.entity_ip == "10.0.0.20")
    assert record.identity_type == "network_service_endpoint"
    assert "SMB" in record.identity_label
    assert any(item["kind"] == "observed_service" for item in record.evidence)

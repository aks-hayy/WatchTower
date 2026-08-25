from core.intelligence.confirmation import IdentityConfirmationService
from core.intelligence.endpoint_identity import EndpointIdentityResolver
from core.intelligence.host_inventory import HostNetworkInventory
from core.storage.database import WatchtowerDB


def _target_flow():
    return [{
        "id": 11, "src_ip": "192.168.29.10", "dst_ip": "192.168.29.77",
        "src_port": 0, "dst_port": 0, "protocol": "ARP", "start_time": 1.0,
        "last_seen": 1.0, "packet_count": 1, "byte_count": 42,
        "l7_metadata": {"arp_target_ip": "192.168.29.77"},
    }]


def test_arp_request_is_unconfirmed_target_not_device():
    record = next(item for item in EndpointIdentityResolver(_target_flow(), inventory=HostNetworkInventory("test", 1.0)).resolve("live_Ethernet#x", "Ethernet", "session") if item.entity_ip == "192.168.29.77")

    assert record.identity_state == "unconfirmed_target"
    assert record.identity_type == "private_endpoint"
    assert record.confidence < 0.5
    assert record.next_action
    assert any(item["kind"] == "arp_target_observation" for item in record.evidence)


def test_arp_binding_promotes_same_subject_to_confirmed_endpoint():
    flows = _target_flow() + [{
        "id": 12, "src_ip": "192.168.29.77", "dst_ip": "192.168.29.10",
        "src_port": 0, "dst_port": 0, "protocol": "ARP", "start_time": 2.0,
        "last_seen": 2.0, "l7_metadata": {
            "arp_sender_ip": "192.168.29.77", "arp_sender_mac": "aa:bb:cc:dd:ee:ff",
        },
    }]
    records = EndpointIdentityResolver(flows).resolve("live_Ethernet#x", "Ethernet", "session")
    record = next(item for item in records if item.entity_ip == "192.168.29.77")

    assert record.identity_state == "confirmed_endpoint"
    assert record.identity_type == "direct_network_neighbor"


def test_confirmation_is_private_subnet_bounded_and_dry_run(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_identity_observations([{
        "subject_ip": "192.168.29.77", "source": "live", "capture_interface": "Ethernet",
        "observation_type": "arp_target", "confidence": 0.2, "evidence_ref": "flow:11",
        "first_seen": 1.0, "last_seen": 1.0, "value": {"confirmation_required": True},
    }])
    monkeypatch.setattr(IdentityConfirmationService, "_attached_networks", staticmethod(lambda: [("Ethernet", "192.168.29.0/24")]))
    result = IdentityConfirmationService(db).confirm(interface="Ethernet", dry_run=True)
    db.close()

    assert result["eligible"] == 1
    assert result["requested"] == 1
    assert result["results"] == []

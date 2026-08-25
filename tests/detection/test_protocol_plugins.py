import os

import pytest
import scapy.all as scapy
from scapy.layers.inet6 import IPv6

from core.forensics.plugins.detectors.coverage_detector import (
    ApplicationAbuseDetector, IoTOTSafetyDetector, LANTrustDetector,
    ReconLateralDetector,
)
from core.forensics.plugins.detectors.file_detector import FileTransferDetector
from core.forensics.plugins.parsers.enterprise_protocol_parser import (
    LDAPParser, MailProtocolParser, NTPParser, RDPParser, SNMPParser, SSHParser,
)
from core.forensics.plugins.parsers.iot_ot_parser import CoAPParser, MQTTParser, ModbusParser
from core.forensics.plugins.parsers.network_foundation_parser import (
    ARPNDPParser, DHCPv6Parser, ICMPMetadataParser, LinkDiscoveryParser, QUICMetadataParser,
)
from core.forensics.engine import (
    OFFLINE_HARDWARE_PENDING_LIMIT,
    ForensicsEngine,
)
from core.packet_engine.schemas import FlowAggregate


def _tcp(payload, sport=12345, dport=80):
    packet = scapy.Ether()/scapy.IP(src="10.0.0.2", dst="10.0.0.3")/scapy.TCP(sport=sport, dport=dport)/scapy.Raw(payload)
    packet.time = 1.0
    return packet


def _udp(payload, sport=12345, dport=53):
    packet = scapy.Ether()/scapy.IP(src="10.0.0.2", dst="10.0.0.3")/scapy.UDP(sport=sport, dport=dport)/scapy.Raw(payload)
    packet.time = 1.0
    return packet


@pytest.mark.parametrize("parser,packet,key", [
    (ARPNDPParser(), scapy.Ether()/scapy.ARP(op=2, psrc="10.0.0.2", hwsrc="00:11:22:33:44:55"), "arp_operation"),
    (ICMPMetadataParser(), scapy.IP()/scapy.ICMP(type=8, id=7, seq=1), "icmp_type"),
    (DHCPv6Parser(), IPv6()/scapy.UDP(sport=546, dport=547)/scapy.Raw(b"\x01\x01\x02\x03"), "dhcpv6_message"),
    (LinkDiscoveryParser(), scapy.Ether(type=0x88CC)/scapy.Raw(b"switch-01"), "discovery_protocol"),
    (QUICMetadataParser(), _udp(b"\xc0\x00\x00\x00\x01\x04abcd\x02ef", dport=443), "quic_version"),
    (SSHParser(), _tcp(b"SSH-2.0-OpenSSH_9.6\r\n", dport=2222), "ssh_banner"),
    (LDAPParser(), _tcp(b"\x30\x05\x02\x01\x01\x60\x00", dport=389), "ldap_operation"),
    (RDPParser(), _tcp(b"\x03\x00\x00\x0b", dport=3389), "rdp_transport"),
    (MailProtocolParser(), _tcp(b"MAIL FROM:<a@example.test>\r\n", dport=25), "mail_from"),
    (SNMPParser(), _udp(b"\x30\x03\x02\x01\x00", dport=161), "application_protocol"),
    (NTPParser(), _udp(b"\x23\x02\x00\x00" + b"\x00" * 44, dport=123), "ntp_mode"),
    (MQTTParser(), _tcp(b"\x10\x08" + b"\x00" * 8, dport=1883), "mqtt_packet_type"),
    (CoAPParser(), _udp(b"\x40\x01\x12\x34", dport=5683), "coap_message_id"),
    (ModbusParser(), _tcp(b"\x00\x01\x00\x00\x00\x02\x01\x03", dport=502), "modbus_function"),
])
def test_parser_positive_and_truncated(parser, packet, key):
    packet.time = 1.0
    assert key in parser.parse(packet).get("metadata", {})
    assert parser.parse(scapy.Ether()/scapy.Raw(b"\x00")) == {}
    parser.reset("next-source")


def test_offline_hardware_observations_are_queued_for_a_bounded_bulk_flush():
    class HardwareDatabase:
        def __init__(self):
            self.immediate = []
            self.batches = []

        def insert_hardware_observation(self, observation):
            self.immediate.append(observation)

        def bulk_insert_hardware_observations(self, observations):
            self.batches.append(list(observations))
            return len(observations)

    engine = object.__new__(ForensicsEngine)
    engine.db = HardwareDatabase()
    engine._batch_hardware_observations = True
    engine._pending_hardware_observations = []
    persist = getattr(engine, "_persist_hardware_observation", None)
    flush = getattr(engine, "_flush_pending_hardware_observations", None)
    assert callable(persist)
    assert callable(flush)

    observations = [{"subject": f"device-{index}"} for index in range(100)]
    for observation in observations:
        persist(observation)

    assert engine.db.immediate == []
    assert engine.db.batches == []
    flush()
    assert engine.db.batches == [observations]
    assert engine._pending_hardware_observations == []

    engine._batch_hardware_observations = False
    persist({"subject": "live-device"})
    assert engine.db.immediate == [{"subject": "live-device"}]


def test_failed_capacity_flush_keeps_retryable_hardware_data_bounded():
    class FailingHardwareDatabase:
        def bulk_insert_hardware_observations(self, _observations):
            raise OSError("hardware write failed")

    engine = object.__new__(ForensicsEngine)
    engine.db = FailingHardwareDatabase()
    engine._batch_hardware_observations = True
    engine._pending_hardware_observations = []

    for index in range(OFFLINE_HARDWARE_PENDING_LIMIT - 1):
        engine._persist_hardware_observation({"subject": f"device-{index}"})
    with pytest.raises(OSError, match="hardware write failed"):
        engine._persist_hardware_observation({"subject": "at-capacity"})
    assert len(engine._pending_hardware_observations) == (
        OFFLINE_HARDWARE_PENDING_LIMIT
    )

    with pytest.raises(OSError, match="hardware write failed"):
        engine._persist_hardware_observation({"subject": "must-not-overflow"})
    assert len(engine._pending_hardware_observations) == (
        OFFLINE_HARDWARE_PENDING_LIMIT
    )
    assert engine._pending_hardware_observations[-1]["subject"] == "at-capacity"


@pytest.mark.parametrize(
    ("read_outcome", "expected_status"),
    [
        ("complete", "PARTIAL"),
        ("partial", "PARTIAL"),
        ("cancelled", "CANCELLED"),
    ],
)
def test_failed_final_hardware_flush_preserves_terminal_state_and_cleanup(
    tmp_path,
    monkeypatch,
    read_outcome,
    expected_status,
):
    pcap = tmp_path / f"hardware-{read_outcome}.pcap"
    packets = []
    for index in range(3):
        packet = scapy.Ether() / scapy.ARP(
            op=2,
            psrc=f"10.0.0.{index + 2}",
            pdst="10.0.0.1",
            hwsrc=f"00:11:22:33:44:{index:02x}",
        )
        packet.time = float(index + 1)
        packets.append(packet)
    scapy.wrpcap(str(pcap), packets)

    engine = ForensicsEngine(data_dir=tmp_path / read_outcome, silent=True)
    monkeypatch.setattr(
        engine.db,
        "bulk_insert_hardware_observations",
        lambda _observations: (_ for _ in ()).throw(
            OSError("hardware write failed")
        ),
    )
    if read_outcome == "partial":
        original_process = engine._process_packet_offline
        processed = 0

        def fail_during_read(packet, fast_path=False):
            nonlocal processed
            original_process(packet, fast_path=fast_path)
            processed += 1
            if processed == 2:
                raise RuntimeError("packet read failed")

        monkeypatch.setattr(
            engine,
            "_process_packet_offline",
            fail_during_read,
        )

    cancel_checks = 0

    def cancelled():
        nonlocal cancel_checks
        cancel_checks += 1
        return read_outcome == "cancelled" and cancel_checks > 1

    report = engine.analyze_pcap(
        str(pcap),
        mode="streaming",
        cancel_event=cancelled,
    )

    assert report.status == expected_status
    assert engine.db.get_reports()[0]["status"] == expected_status
    assert "hardware write failed" in report.error
    if read_outcome == "partial":
        assert "packet read failed" in report.error
    assert 0 < len(engine._pending_hardware_observations) <= (
        OFFLINE_HARDWARE_PENDING_LIMIT
    )
    assert engine._segment_spool is None
    assert engine._batch_entity_observations is False
    assert engine._batch_hardware_observations is False
    assert engine._batch_flow_persistence is False


def test_lan_spoofing_state_and_reset():
    detector = LANTrustDetector()
    one = scapy.Ether()/scapy.ARP(op=2, psrc="10.0.0.9", hwsrc="00:11:22:33:44:55")
    two = scapy.Ether()/scapy.ARP(op=2, psrc="10.0.0.9", hwsrc="00:11:22:33:44:66")
    one.time = two.time = 1.0
    assert detector.detect(packet=one) == []
    assert detector.detect(packet=two) == []
    two.time = 2.0
    assert detector.detect(packet=two) == []
    two.time = 3.0
    assert detector.detect(packet=two)[0].type == "ARP_SPOOFING"
    detector.reset("new")
    assert detector.detect(packet=two) == []


def test_scan_state_is_bounded_and_thresholded():
    detector = ReconLateralDetector()
    alerts = []
    for port in range(1, 30):
        flow = FlowAggregate(("10.0.0.2", "10.0.0.3", 50000, port, "TCP"), 1.0, 1.0)
        flow.tcp_syn_count = 1
        alerts.extend(detector.detect(flow=flow))
    assert any(alert.type == "PORT_SCAN" for alert in alerts)
    for port in range(600):
        flow = FlowAggregate(("10.0.0.2", "10.0.0.3", 50000, port, "TCP"), 2.0, 2.0)
        flow.tcp_syn_count = 1
        detector.detect(flow=flow)
    assert len(detector.events["10.0.0.2"]) <= detector.MAX_EVENTS_PER_HOST


def test_application_and_ot_detectors_require_evidence():
    application = ApplicationAbuseDetector()
    assert application.detect(packet=_tcp(b"ordinary request")) == []
    assert application.detect(packet=_tcp(b"password=secret"))[0].type == "CLEARTEXT_SECRET"
    assert application.detect(packet=_tcp(b"\x15\x03\x03\x00\x02\x02\x28", dport=443)) == []
    icmp_alerts = []
    for index in range(10):
        icmp = scapy.IP(src="10.0.0.2", dst="10.0.0.3")/scapy.ICMP()/scapy.Raw(os.urandom(7000))
        icmp.time = 3.0 + index
        icmp_alerts.extend(application.detect(packet=icmp))
    assert any(alert.type == "ICMP_TUNNELING" for alert in icmp_alerts)
    modbus = _tcp(b"\x00\x01\x00\x00\x00\x02\x01\x10", dport=502)
    policy = {"enabled": True, "authorized_masters": ["10.0.0.99"]}
    assert IoTOTSafetyDetector(policy=policy).detect(packet=modbus)[0].type == "UNSAFE_OT_COMMAND"
    assert IoTOTSafetyDetector().detect(packet=modbus) == []


def test_file_detector_hashes_only_the_required_pe_signature_evidence():
    detector = FileTransferDetector()
    marker = b"MZ-header--This program cannot be run in DOS mode"

    first = detector.detect(stream=marker + b"first harmless trailer")[0]
    second = detector.detect(stream=marker + b"different harmless trailer")[0]

    assert first.evidence["signature_evidence_hash"] == second.evidence[
        "signature_evidence_hash"
    ]
    assert "content_hash" not in first.evidence


def test_tls_mismatch_requires_observed_connection_start():
    detector = ApplicationAbuseDetector()
    midstream = _tcp(b"not tls but capture began midstream", dport=443)
    midstream[scapy.TCP].flags = "PA"
    assert detector.detect(packet=midstream) == []

    syn = scapy.IP(src="10.0.0.2", dst="10.0.0.3")/scapy.TCP(sport=50000, dport=443, flags="S")
    syn.time = 1.0
    detector.detect(packet=syn)
    first_payload = _tcp(b"GET / HTTP/1.1\r\n\r\n", dport=443)
    first_payload[scapy.TCP].sport = 50000
    first_payload[scapy.TCP].flags = "PA"
    assert detector.detect(packet=first_payload)[0].type == "TLS_PROTOCOL_MISMATCH"
    assert detector.detect(packet=first_payload) == []


def test_detector_malformed_packets_do_not_raise():
    for detector in (LANTrustDetector(), ReconLateralDetector(), ApplicationAbuseDetector(), IoTOTSafetyDetector()):
        assert detector.detect(packet=scapy.Ether()/scapy.Raw(os.urandom(3))) == []
        detector.reset("next-source")

import hashlib

import pytest
from scapy.all import DNS, DNSQR, Dot1Q, Ether, IP, TCP, UDP, wrpcap
from scapy.layers.inet6 import ICMPv6NDOptSrcLLAddr, ICMPv6ND_RA, IPv6

import core.forensics.engine as engine_module
from core.forensics.engine import ForensicsEngine
from core.forensics.fast_packet import FastPacket
from core.packet_engine.capture import packet_to_event
from core.packet_engine.rust_capture import rust_sensor_available


def test_fast_packet_exposes_l2_l4_and_application_payload():
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src="10.10.0.1", dst="10.10.0.2"
    ) / TCP(sport=50123, dport=8080, flags="PA", seq=42) / b"GET / HTTP/1.1\r\n\r\n"
    event = packet_to_event(packet)
    fast = FastPacket(event)

    assert fast.valid
    assert fast.src_ip == "10.10.0.1"
    assert fast.dst_ip == "10.10.0.2"
    assert (fast.sport, fast.dport, fast.flags, fast.sequence) == (50123, 8080, "PA", 42)
    assert fast.application_payload.startswith(b"GET /")
    assert len(fast) == len(bytes(packet))


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_offline_analysis_does_not_rehydrate_each_frame_with_scapy(tmp_path, monkeypatch):
    pcap = tmp_path / "fast-path.pcap"
    packet = Ether() / IP(src="10.20.0.10", dst="10.20.0.20") / TCP(
        sport=51000, dport=8080, flags="PA", seq=1
    ) / b"GET /health HTTP/1.1\r\nHost: internal.example\r\n\r\n"
    packet.time = 100.0
    wrpcap(str(pcap), [packet])

    # The accelerated replay must not build ``scapy.Ether(event.raw)`` for
    # every event.  The HTTP parser still runs through FastPacket's small,
    # Scapy-compatible surface.
    monkeypatch.setattr("core.forensics.engine.scapy.Ether", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected Scapy rehydration")))
    engine = ForensicsEngine(data_dir=tmp_path, silent=True)
    try:
        report = engine.analyze_pcap(str(pcap), backend="rust")
        assert report.status == "COMPLETE"
        assert len(engine.flow_table) == 1
        assert "10.20.0.10" in report.entities
    finally:
        engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_repeated_analysis_resets_stateful_packet_detectors(tmp_path):
    pcap = tmp_path / "tls-mismatch.pcap"
    syn = Ether() / IP(src="10.43.0.10", dst="10.43.0.20") / TCP(
        sport=56020, dport=443, flags="S", seq=1
    )
    payload = Ether() / IP(src="10.43.0.10", dst="10.43.0.20") / TCP(
        sport=56020, dport=443, flags="PA", seq=2
    ) / b"GET / HTTP/1.1\r\n\r\n"
    syn.time = 100.0
    payload.time = 100.1
    wrpcap(str(pcap), [syn, payload])

    engine = ForensicsEngine(data_dir=tmp_path / "data", silent=True)
    try:
        for mode in ("memory", "streaming"):
            engine.analyze_pcap(
                str(pcap), backend="rust", mode=mode,
                source_name="calibration:tls-repeated",
            )
            findings = engine.db.get_detection_findings(
                source="calibration:tls-repeated",
                finding_type="tls.protocol_mismatch",
            )
            assert len(findings) == 1, mode
    finally:
        engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_terminal_aggregation_does_not_replay_every_flow_sample(tmp_path):
    pcap = tmp_path / "terminal-samples.pcap"
    packets = []
    for index in range(100):
        packet = Ether() / IP(src="10.44.0.10", dst="10.44.0.20") / UDP(
            sport=56030, dport=65000,
        ) / b"data"
        packet.time = 100.0 + index
        packets.append(packet)
    wrpcap(str(pcap), packets)

    engine = ForensicsEngine(data_dir=tmp_path / "data", silent=True)
    calls = 0
    original = engine.process_live_conversation

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    engine.process_live_conversation = counted
    try:
        engine.analyze_pcap(str(pcap), backend="rust", mode="memory")
        assert calls <= 3
    finally:
        engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_rehydrates_only_non_fast_parser_ports_with_python_parity(tmp_path, monkeypatch):
    pcap = tmp_path / "selective-decode.pcap"
    dns_packets = []
    for index in range(20):
        label = hashlib.sha256(f"selective-{index}".encode()).hexdigest()
        dns = (
            Ether()
            / IP(src="10.30.0.10", dst="8.8.8.8")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example", qtype="TXT"))
        )
        dns.time = 100.0 + index
        dns_packets.append(dns)
    http = (
        Ether()
        / IP(src="10.30.0.20", dst="10.30.0.30")
        / TCP(sport=51000, dport=8080, flags="PA", seq=1)
        / b"GET / HTTP/1.1\r\nHost: internal.example\r\n\r\n"
    )
    http.time = 200.0
    wrpcap(str(pcap), [*dns_packets, http])

    python_engine = ForensicsEngine(data_dir=tmp_path / "python", silent=True)
    try:
        python_report = python_engine.analyze_pcap(str(pcap), backend="python")
        python_dns = python_engine.flow_table[("10.30.0.10", "8.8.8.8", 53000, 53, "UDP")]
        python_alert = next(
            alert
            for entity in python_report.entities.values()
            for alert in entity.alerts
            if alert.type == "SUSPICIOUS_DNS"
        )
        python_finding = python_engine.db.get_detection_findings(
            finding_type="dns.tunnel.suspected"
        )[0]
    finally:
        python_engine.db.close()

    original_ether = engine_module.scapy.Ether
    rehydrated = []

    def counted_ether(raw, *args, **kwargs):
        packet = original_ether(raw, *args, **kwargs)
        rehydrated.append(packet)
        return packet

    monkeypatch.setattr(engine_module.scapy, "Ether", counted_ether)
    rust_engine = ForensicsEngine(data_dir=tmp_path / "rust", silent=True)
    try:
        rust_report = rust_engine.analyze_pcap(str(pcap), backend="rust")
        rust_dns = rust_engine.flow_table[("10.30.0.10", "8.8.8.8", 53000, 53, "UDP")]
        rust_alert = next(
            alert
            for entity in rust_report.entities.values()
            for alert in entity.alerts
            if alert.type == "SUSPICIOUS_DNS"
        )
        rust_finding = rust_engine.db.get_detection_findings(
            finding_type="dns.tunnel.suspected"
        )[0]

        assert rust_dns.l7_metadata["dns_domain"] == python_dns.l7_metadata["dns_domain"]
        assert (rust_dns.start_time, rust_dns.last_seen) == (
            python_dns.start_time,
            python_dns.last_seen,
        ) == (100.0, 119.0)
        assert rust_alert.timestamp == python_alert.timestamp == 119.0
        assert (rust_finding["first_seen"], rust_finding["last_seen"]) == (
            python_finding["first_seen"],
            python_finding["last_seen"],
        ) == (119.0, 119.0)
        assert [bytes(packet) for packet in rehydrated] == [
            bytes(packet) for packet in dns_packets
        ]
        assert all(
            packet.watchtower_origin == {
                "session_id": str(rust_report.report_id),
                "source_type": "network",
                "device_id": "pcap",
                "backend": "rust",
                "link_type": "ethernet",
                "sensor_node_id": "local",
                "source": "pcap:selective-decode.pcap",
            }
            for packet in rehydrated
        )
    finally:
        rust_engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_vlan_selective_decode_preserves_event_time_and_origin_through_normalization(
    tmp_path,
):
    pcap = tmp_path / "vlan-selective-decode.pcap"
    packet = (
        Ether()
        / Dot1Q(vlan=42)
        / IP(src="10.60.0.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="vlan.selective.example", qtype="TXT"))
    )
    packet.time = 321.0
    wrpcap(str(pcap), [packet])

    engine = ForensicsEngine(data_dir=tmp_path / "rust", silent=True)
    dns_parser = next(
        parser
        for parser in engine.plugin_loader.get_parsers()
        if parser.name == "DNS Parser"
    )
    original_parse = dns_parser.parse
    observed = []

    def observe_normalized_packet(normalized, context=None):
        observed.append({
            "timestamp": float(normalized.time),
            "origin": getattr(normalized, "watchtower_origin", None),
            "has_vlan": normalized.haslayer(Dot1Q),
        })
        return original_parse(normalized, context=context)

    dns_parser.parse = observe_normalized_packet
    try:
        report = engine.analyze_pcap(str(pcap), backend="rust")
        flow = engine.flow_table[("10.60.0.10", "8.8.8.8", 53000, 53, "UDP")]

        assert observed == [{
            "timestamp": 321.0,
            "origin": {
                "session_id": str(report.report_id),
                "source_type": "network",
                "device_id": "pcap",
                "backend": "rust",
                "link_type": "ethernet",
                "sensor_node_id": "local",
                "source": "pcap:vlan-selective-decode.pcap",
            },
            "has_vlan": False,
        }]
        assert (flow.start_time, flow.last_seen) == (321.0, 321.0)
        assert flow.l7_metadata["dns_domain"] == "vlan.selective.example"
    finally:
        engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_router_advertisement_metadata_and_timestamps_match_python(tmp_path):
    pcap = tmp_path / "router-advertisement.pcap"
    packet = (
        Ether(src="02:00:00:00:00:01", dst="33:33:00:00:00:01")
        / IPv6(src="fe80::1", dst="ff02::1")
        / ICMPv6ND_RA(routerlifetime=1800, M=1, O=0)
        / ICMPv6NDOptSrcLLAddr(lladdr="02:00:00:00:00:01")
    )
    packet.time = 200.0
    wrpcap(str(pcap), [packet])

    expected_keys = {
        "ndp_event",
        "icmpv6_type",
        "target",
        "ndp_sender_ip",
        "ndp_sender_mac",
        "router_lifetime",
        "managed",
        "other",
    }
    results = {}
    for backend in ("python", "rust"):
        engine = ForensicsEngine(data_dir=tmp_path / backend, silent=True)
        try:
            report = engine.analyze_pcap(str(pcap), backend=backend)
            flow = next(iter(engine.flow_table.values()))
            results[backend] = {
                "metadata": {key: flow.l7_metadata[key] for key in expected_keys},
                "times": (flow.start_time, flow.last_seen),
                "mac": report.entities["fe80::1"].mac,
            }
        finally:
            engine.db.close()

    assert results["rust"] == results["python"]
    assert results["rust"]["times"] == (200.0, 200.0)


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_rust_terminal_aggregates_preserve_non_candidate_flow_totals(tmp_path):
    pcap = tmp_path / "terminal-flow.pcap"
    packets = []
    for index in range(20):
        packet = (
            Ether()
            / IP(src="10.90.0.1", dst="10.90.0.2")
            / UDP(sport=40000, dport=40001)
            / b"ordinary-unclassified-payload"
        )
        packet.time = 500.0 + index
        packets.append(packet)
    wrpcap(str(pcap), packets)

    engine = ForensicsEngine(data_dir=tmp_path / "rust", silent=True)
    try:
        engine.analyze_pcap(str(pcap), backend="rust")
        flow = engine.flow_table[("10.90.0.1", "10.90.0.2", 40000, 40001, "UDP")]

        assert flow.packet_count == 20
        assert flow.byte_count == sum(len(packet) for packet in packets)
        assert flow.start_time == 500.0
        assert flow.last_seen == 519.0
        assert len(flow.packet_sizes) == 20
    finally:
        engine.db.close()

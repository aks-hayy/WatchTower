from scapy.all import Ether, IP, TCP, wrpcap

from core.forensics.engine import ForensicsEngine


def generate_test_pcap(filename):
    sport = 12345
    dport = 445
    src = "10.0.0.1"
    dst = "10.0.0.2"
    payload = b"MZ" + b"A" * 100 + b"This program cannot be run in DOS mode" + b"B" * 50
    packets = [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=1000) / payload[:20],
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=1020) / payload[20:],
    ]
    wrpcap(str(filename), packets)


def test_carving(tmp_path):
    pcap_file = tmp_path / "carve_test.pcap"
    generate_test_pcap(pcap_file)
    engine = ForensicsEngine(data_dir=str(tmp_path / "runtime"), silent=True)
    try:
        report = engine.analyze_pcap(str(pcap_file))
        carved_files = [item for entity in report.entities.values() for item in entity.carved_files]
        assert carved_files
        assert all(item.sha256 and item.size > 0 for item in carved_files)
    finally:
        engine.db.close()

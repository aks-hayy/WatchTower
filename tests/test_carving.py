import os
import sys
from scapy.all import IP, TCP, Ether, wrpcap
from core.forensics.engine import ForensicsEngine

def generate_test_pcap(filename):
    # Create a TCP stream with a "PE" header (MZ...)
    packets = []
    
    # 3-way handshake
    sport = 12345
    dport = 445
    src = "10.0.0.1"
    dst = "10.0.0.2"
    
    # Payload with MZ header
    payload1 = b"MZ" + b"A" * 100 + b"This program cannot be run in DOS mode" + b"B" * 50
    # Split across two packets to test reassembly
    
    p1 = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, seq=1000)/payload1[:20]
    p2 = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, seq=1020)/payload1[20:]
    
    packets.extend([p1, p2])
    wrpcap(filename, packets)
    print(f"Generated {filename}")

def test_carving():
    pcap_file = "tests/carve_test.pcap"
    generate_test_pcap(pcap_file)
    
    engine = ForensicsEngine()
    report = engine.analyze_pcap(pcap_file)
    
    found_carved = False
    for ip, entity in report.entities.items():
        if entity.carved_files:
            print(f"Found {len(entity.carved_files)} carved files for {ip}")
            for cf in entity.carved_files:
                print(f" - {cf.filename} ({cf.size} bytes), Hash: {cf.sha256}")
                found_carved = True
    
    if found_carved:
        print("SUCCESS: File carving and reassembly verified.")
    else:
        print("FAILURE: No files carved.")
        sys.exit(1)

if __name__ == "__main__":
    if not os.path.exists("tests"):
        os.makedirs("tests")
    test_carving()

# tests/test_forensics_rebuild.py

import sys
import os
import unittest
import time
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

# Ensure local imports work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.forensics.engine import ForensicsEngine

class TestForensicsRebuild(unittest.TestCase):
    def setUp(self):
        self.test_pcap = "test_forensics.pcap"
        self.engine = ForensicsEngine()

    def tearDown(self):
        if os.path.exists(self.test_pcap):
            os.remove(self.test_pcap)

    def test_beaconing_detection(self):
        print("Testing beaconing detection...")
        packets = []
        start_time = time.time()
        for i in range(25): # More packets for better stats
            p = Ether()/IP(src="192.168.1.50", dst="8.8.8.8")/TCP(sport=1234, dport=80)
            p.time = start_time + i * 1.0 
            packets.append(p)
        
        wrpcap(self.test_pcap, packets)
        report = self.engine.analyze_pcap(self.test_pcap)
        
        found_beacon = False
        for entity in report.entities.values():
            for alert in entity.alerts:
                if alert.type == "BEACONING":
                    found_beacon = True
                    print(f"Found Beaconing: {alert.explanation}")
        
        self.assertTrue(found_beacon)

    def test_dns_entropy(self):
        print("Testing DNS entropy detection...")
        domain = "vjks92lmsn02lsmd02-x-z-y-1-2-3-q-w-e-r-t-y.com"

        # Dynamically find the DNS detector from the engine's plugin loader
        dns_detector = next(d for d in self.engine.plugin_loader.get_detectors() if "DNS" in d.name)

        entropy = dns_detector.calculate_entropy(domain)
        print(f"Domain: {domain}, Entropy: {entropy:.2f}")
        
        self.assertEqual(len(dns_detector.detect(domain="google.com")), 0)
        
        alerts = dns_detector.detect(domain=domain)
        self.assertTrue(len(alerts) > 0)
        print(f"Found Suspicious DNS: {alerts[0].explanation}")

    def test_identity_extraction(self):
        print("Testing identity extraction...")
        packets = []
        domain = "qweasdzxc-1234567890-random-dga.net"
        # DNS Packet
        p1 = Ether(src="00:11:22:33:44:55")/IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        p1.time = time.time()
        packets.append(p1)
        
        # Craft a valid-ish NTLM Type 3 message
        # 0-8: Sig
        # 8-12: Type 3
        # 12-28: Lm/Nt Resp (16 bytes)
        # 28-36: Domain (8 bytes: len, max_len, offset)
        # 36-44: User (8 bytes: len, max_len, offset)
        # 44-52: Workstation (8 bytes: len, max_len, offset)
        
        user_name = "akshay".encode('utf-16le')
        user_len = len(user_name)
        user_offset = 64 # Start after headers
        
        payload = b"NTLMSSP\x00"
        payload += b"\x03\x00\x00\x00"
        payload += b"\x00" * 16 # Resps
        payload += b"\x00" * 8  # Domain
        payload += user_len.to_bytes(2, 'little') + user_len.to_bytes(2, 'little') + user_offset.to_bytes(4, 'little')
        payload += b"\x00" * 20 # Rest of headers
        payload = payload.ljust(user_offset, b"\x00")
        payload += user_name
        
        p2 = Ether(src="00:11:22:33:44:55")/IP(src="192.168.1.10", dst="1.2.3.4")/TCP(sport=1024, dport=80)/payload
        p2.time = time.time() + 0.1
        packets.append(p2)

        # Kerberos Packet (CNameString)
        payload_kerb = b"\x1b\x05brolf"
        p4 = Ether(src="00:11:22:33:44:55")/IP(src="192.168.1.10", dst="10.1.21.1")/UDP(sport=88, dport=88)/payload_kerb
        p4.time = time.time() + 0.3
        packets.append(p4)
        
        # SMB Unicode Packet (Full Name)
        full_name_unicode = "Becka Rolf".encode('utf-16le')
        p5 = Ether(src="00:11:22:33:44:55")/IP(src="192.168.1.10", dst="10.1.21.1")/TCP(sport=445, dport=445)/full_name_unicode
        p5.time = time.time() + 0.4
        packets.append(p5)

        wrpcap(self.test_pcap, packets)
        report = self.engine.analyze_pcap(self.test_pcap)
        
        profile = report.entities.get("192.168.1.10")
        self.assertIsNotNone(profile)
        self.assertEqual(profile.user, "brolf")
        self.assertEqual(profile.full_name, "Becka Rolf")
        print(f"Verified Profile: IP={profile.ip}, User={profile.user}, FullName={profile.full_name}")


        
    def test_multi_suspect_profiles(self):
        print("Testing multiple suspect profiles...")
        packets = []
        
        # Suspect 1: Beaconing
        start_time = time.time()
        for i in range(20):
            p = Ether(src="00:11:22:33:44:55")/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=1234, dport=80)
            p.time = start_time + i * 1.0
            packets.append(p)
            
        # Suspect 2: Suspicious DNS
        p2 = Ether(src="AA:BB:CC:DD:EE:FF")/IP(src="192.168.1.20", dst="8.8.8.8")/UDP(sport=53, dport=53)/DNS(rd=1, qd=DNSQR(qname="vjks92lmsn02lsmd02-x-z-y-1-2-3-q-w-e-r-t-y.com"))
        p2.time = start_time
        packets.append(p2)

        wrpcap(self.test_pcap, packets)
        report = self.engine.analyze_pcap(self.test_pcap)
        
        alerted_ips = [ip for ip, e in report.entities.items() if e.risk_score > 0]
        print(f"Alerted IPs: {alerted_ips}")
        self.assertIn("192.168.1.10", alerted_ips)
        self.assertIn("192.168.1.20", alerted_ips)
        self.assertEqual(len(alerted_ips), 2)




if __name__ == "__main__":
    unittest.main()

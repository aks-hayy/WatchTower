import unittest
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
from core.forensics.plugin_loader import PluginLoader
from core.forensics.models import ForensicAlert
from core.packet_engine.schemas import FlowAggregate

class TestForensicPlugins(unittest.TestCase):
    def setUp(self):
        self.loader = PluginLoader()
        self.parsers = self.loader.get_parsers()
        self.detectors = self.loader.get_detectors()

    def test_dns_parser(self):
        # Create a mock DNS packet
        pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname=b"malicious.com."))
        
        # Find DNS parser
        dns_parser = next((p for p in self.parsers if "DNS" in p.name), None)
        self.assertIsNotNone(dns_parser, "DNS parser not loaded")
        
        # Test parsing
        result = dns_parser.parse(pkt)
        self.assertIn("identities", result)
        self.assertEqual(result["identities"]["remote_hostname"], "malicious.com")

    def test_dhcp_parser(self):
        # Create mock DHCP packet
        # Setting up a minimal DHCP request with hostname option
        pkt = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", "request"), ("hostname", b"DESKTOP-ABC"), "end"])
        
        dhcp_parser = next((p for p in self.parsers if "DHCP" in p.name), None)
        self.assertIsNotNone(dhcp_parser, "DHCP parser not loaded")
        
        result = dhcp_parser.parse(pkt)
        self.assertIn("identities", result)
        self.assertEqual(result["identities"]["local_hostname"], "DESKTOP-ABC")

    def test_http_parser(self):
        # Create mock HTTP packet
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=12345, dport=80) / payload
        
        http_parser = next((p for p in self.parsers if "HTTP" in p.name), None)
        self.assertIsNotNone(http_parser, "HTTP parser not loaded")
        
        result = http_parser.parse(pkt)
        self.assertIn("identities", result)
        self.assertEqual(result["identities"]["remote_hostname"], "example.com")

    def test_exfiltration_detector(self):
        # Mock FlowAggregate with large byte count
        flow = FlowAggregate(flow_id=("192.168.1.10", "8.8.8.8", 1234, 443, "TCP"), start_time=10.0, last_seen=20.0)
        flow.byte_count = 15 * 1024 * 1024 # 15 MB
        
        exfil_detector = next((d for d in self.detectors if "Exfiltration" in d.name), None)
        self.assertIsNotNone(exfil_detector, "Exfiltration detector not loaded")
        
        alerts = exfil_detector.detect(flow=flow)
        self.assertGreater(len(alerts), 0, "Failed to detect exfiltration")
        self.assertEqual(alerts[0].type, "EXFILTRATION")

    def test_beaconing_detector(self):
        # Create an array of perfectly uniform arrival times
        arrival_times = [float(i) for i in range(1, 20)] # Every 1 second
        
        beacon_detector = next((d for d in self.detectors if "Beaconing" in d.name), None)
        self.assertIsNotNone(beacon_detector, "Beaconing detector not loaded")
        
        alerts = beacon_detector.detect(arrival_times=arrival_times)
        self.assertGreater(len(alerts), 0, "Failed to detect beaconing")
        self.assertEqual(alerts[0].type, "BEACONING")

    def test_dns_anomaly_detector(self):
        dns_detector = next((d for d in self.detectors if "DNS Anomaly" in d.name), None)
        self.assertIsNotNone(dns_detector, "DNS anomaly detector not loaded")
        
        # High entropy domain
        alerts = dns_detector.detect(domain="vpxqzkxwrytghjklmnbvcxz.com")
        self.assertGreater(len(alerts), 0, "Failed to detect high entropy domain")
        self.assertEqual(alerts[0].type, "SUSPICIOUS_DNS")
        
        # Normal domain
        alerts_normal = dns_detector.detect(domain="google.com")
        self.assertEqual(len(alerts_normal), 0, "False positive on normal domain")

if __name__ == '__main__':
    unittest.main()

import unittest
from types import SimpleNamespace
from unittest.mock import patch
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dhcp import DHCP, BOOTP
from core.forensics.plugin_loader import PluginLoader
from core.operations.coverage import build_coverage_matrix
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
        # A cold-start alert requires a genuinely large, strongly directional
        # transfer to a destination not previously seen for this host.
        flow = FlowAggregate(flow_id=("192.168.1.10", "8.8.8.8", 1234, 443, "TCP"), start_time=10.0, last_seen=20.0)
        flow.byte_count = 120 * 1024 * 1024
        flow.l7_metadata = {"reverse_byte_count": 1024 * 1024, "peer_novelty": True}
        
        exfil_detector = next((d for d in self.detectors if "Exfiltration" in d.name), None)
        self.assertIsNotNone(exfil_detector, "Exfiltration detector not loaded")
        
        alerts = exfil_detector.detect(flow=flow)
        self.assertGreater(len(alerts), 0, "Failed to detect exfiltration")
        self.assertEqual(alerts[0].type, "EXFILTRATION")

    def test_beaconing_detector(self):
        arrival_times = [float(i * 10) for i in range(20)]
        flow = FlowAggregate(flow_id=("192.168.1.10", "8.8.8.8", 1234, 443, "TCP"), start_time=0.0, last_seen=190.0)
        for timestamp in arrival_times:
            flow.update(128, timestamp)
        flow.l7_metadata = {"peer_novelty": True, "reverse_packet_count": 0}
        
        beacon_detector = next((d for d in self.detectors if "Beaconing" in d.name), None)
        self.assertIsNotNone(beacon_detector, "Beaconing detector not loaded")
        
        alerts = beacon_detector.detect(arrival_times=arrival_times, flow=flow)
        self.assertGreater(len(alerts), 0, "Failed to detect beaconing")
        self.assertEqual(alerts[0].type, "BEACONING")

    def test_dns_anomaly_detector(self):
        dns_detector = next((d for d in self.detectors if "DNS Anomaly" in d.name), None)
        self.assertIsNotNone(dns_detector, "DNS anomaly detector not loaded")
        
        alerts = []
        for index in range(20):
            label = f"a0b1c2d3e4f5g6h7i8j9k{index:02x}q"
            domain = f"{label}.tunnel.example"
            packet = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname=domain, qtype="TXT"))
            packet.time = float(index)
            alerts.extend(dns_detector.detect(domain=domain, packet=packet))
        self.assertGreater(len(alerts), 0, "Failed to detect high entropy domain")
        self.assertEqual(alerts[0].type, "SUSPICIOUS_DNS")
        
        # Normal domain
        alerts_normal = dns_detector.detect(domain="google.com")
        self.assertEqual(len(alerts_normal), 0, "False positive on normal domain")

    def test_plugin_health_reports_stale_calibration_and_legacy_replacements(self):
        from core.detection import scoring

        # Keep this health-contract test independent of content-addressed
        # attestations in the developer's checkout. The trust outcome is a
        # fixture; detector manifests and calibration policy remain untouched.
        config = SimpleNamespace(
            uncalibrated_finding_cap=5.0,
            corpus_validated_finding_cap=20.0,
            profile_for=lambda *_args: SimpleNamespace(
                calibration_level="UNCALIBRATED",
                attestation_digest="",
                max_contribution=5.0,
                stale_reason="stale calibration dependency: core/calibration/service.py",
            ),
        )
        with patch.object(scoring, "ScoringConfig", return_value=config):
            loader = PluginLoader()
        plugins = loader.list_plugins()
        ftp = plugins["BaseDetector:Cleartext FTP Credential Detector"]
        self.assertFalse(ftp["calibrated"])
        self.assertEqual(ftp["calibration_level"], "UNCALIBRATED")
        self.assertEqual(ftp["calibration"][0]["finding_type"], "credential.cleartext.ftp")
        self.assertEqual(
            ftp["calibration"][0]["stale_reason"],
            "stale calibration dependency: core/calibration/service.py",
        )
        beacon = plugins["BaseDetector:Beaconing Detector"]
        self.assertFalse(beacon["calibrated"])
        self.assertEqual(beacon["calibration_level"], "UNCALIBRATED")
        matrix = build_coverage_matrix(list(plugins.values()))
        legacy = {
            item["detector_id"]: item
            for item in matrix["items"]
            if item["detector_id"] in {
                "watchtower.recon",
                "watchtower.behavior.beacon",
                "watchtower.exfiltration",
            }
        }
        self.assertEqual(
            set(legacy),
            {"watchtower.recon", "watchtower.behavior.beacon", "watchtower.exfiltration"},
        )
        for item in legacy.values():
            self.assertEqual(item["replacement"], "watchtower.stateful.host")
            self.assertIn("do not enable", item["next_action"])


def test_plugin_loader_builds_and_verifies_scoring_configuration_once(monkeypatch):
    from core.detection.scoring import ScoringConfig as RealScoringConfig

    constructions = []

    def counting_scoring_config(*args, **kwargs):
        constructions.append(1)
        return RealScoringConfig(*args, **kwargs)

    monkeypatch.setattr("core.detection.scoring.ScoringConfig", counting_scoring_config)

    PluginLoader()

    assert len(constructions) == 1


def test_calibration_status_builds_scoring_configuration_once_per_request(monkeypatch, tmp_path):
    from core.calibration.service import CalibrationService
    from core.detection.scoring import ScoringConfig as RealScoringConfig

    constructions = []

    def counting_scoring_config(*args, **kwargs):
        constructions.append(1)
        return RealScoringConfig(*args, **kwargs)

    monkeypatch.setattr("core.detection.scoring.ScoringConfig", counting_scoring_config)

    CalibrationService(data_dir=tmp_path).status()

    # PluginLoader creates one config for its own detector metadata. Calibration
    # status should share one additional config across all detector targets.
    assert len(constructions) == 2

if __name__ == '__main__':
    unittest.main()

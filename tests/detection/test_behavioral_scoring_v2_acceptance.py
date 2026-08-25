import json
import hashlib
import os
from pathlib import Path
import time

import pytest
import scapy.all as scapy
from fastapi.testclient import TestClient

from core.api.server import create_app
from core.detection.baseline import MAX_QUANTILE_SAMPLES, OnlineFeatureStats, baseline_maturity, learning_allowed
from core.detection.contracts import DetectionFindingV2
from core.detection.operations import ScoringOperations
from core.detection.payload import application_payload
from core.detection.stateful import StatefulHostDetector
from core.forensics.engine import ForensicsEngine
from core.forensics.plugins.detectors.coverage_detector import LANTrustDetector
from core.forensics.plugins.detectors.coverage_detector import IoTOTSafetyDetector, ReconLateralDetector
from core.forensics.plugins.detectors.dns_detector import DNSDetector
from core.forensics.plugins.detectors.file_detector import FileTransferDetector
from core.packet_engine.schemas import FlowAggregate
from core.storage.database import WatchtowerDB
from core.packet_engine.rust_capture import rust_sensor_available


def finding(source="live_Ethernet#a", session="a", occurrences=1, observed_at=1000.0):
    return DetectionFindingV2(
        finding_type="behavior.beacon.suspected", detector_id="watchtower.behavior.beacon",
        detector_version="2.0.0", category="ANOMALY", impact="MEDIUM", confidence=0.8,
        evidence_quality=1.0, calibration_state="CALIBRATED", signal_family="behavior",
        correlation_group="beacon", subject="10.0.0.8", observed_at=observed_at,
        explanation="periodic callbacks", evidence={"dst_ip": "1.1.1.1", "sample_count": 20},
        source=source, capture_interface="Ethernet", capture_session_id=session,
        occurrence_count=occurrences,
    )


def test_ethernet_padding_is_not_application_payload():
    packet = scapy.Ether()/scapy.IP(src="10.0.0.2", dst="1.1.1.1", len=40)/scapy.TCP(sport=50000, dport=443, flags="A")/scapy.Padding(b"not tls padding")
    assert application_payload(packet) == b""


def test_fragmented_ftp_is_found_after_reassembly_without_secret_persistence(tmp_path):
    pcap = tmp_path / "fragmented-ftp.pcap"
    packets = []
    for index, payload in enumerate((b"USER analyst\r\nPA", b"SS swordfish\r\n")):
        packet = scapy.Ether()/scapy.IP(src="10.0.0.8", dst="10.0.0.20")/scapy.TCP(
            sport=50000, dport=21, flags="PA", seq=1 + index * 16,
        )/payload
        packet.time = 100.0 + index
        packets.append(packet)
    scapy.wrpcap(str(pcap), packets)
    engine = ForensicsEngine(data_dir=str(tmp_path), silent=True)
    try:
        engine.analyze_pcap(str(pcap))
        findings = engine.db.get_detection_findings(subject="10.0.0.8")
        assert any(item["finding_type"] == "credential.cleartext.ftp" for item in findings)
        persisted = json.dumps(findings).lower()
        assert "swordfish" not in persisted
    finally:
        engine.db.close()


@pytest.mark.skipif(not rust_sensor_available(), reason="Rust sensor is not built")
def test_python_and_rust_replay_produce_identical_canonical_findings(tmp_path):
    pcap = tmp_path / "parity.pcap"
    packets = []
    for index, payload in enumerate((b"USER analyst\r\nPA", b"SS parity-secret\r\n")):
        packet = scapy.Ether()/scapy.IP(src="10.0.0.8", dst="10.0.0.20")/scapy.TCP(
            sport=50000, dport=21, flags="PA", seq=1 + index * 16,
        )/payload
        packet.time = 100.0 + index
        packets.append(packet)
    scapy.wrpcap(str(pcap), packets)

    findings = {}
    for backend in ("python", "rust"):
        data_dir = tmp_path / backend
        engine = ForensicsEngine(data_dir=str(data_dir), silent=True)
        try:
            engine.analyze_pcap(str(pcap), backend=backend)
            findings[backend] = [
                (item["fingerprint"], item["finding_type"], item["subject"], item["evidence"])
                for item in engine.db.get_detection_findings()
            ]
        finally:
            engine.db.close()
    assert findings["python"] == findings["rust"]


def test_global_rollup_deduplicates_equivalent_session_findings(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        first = finding()
        second = finding(source="live_Ethernet#b", session="b", occurrences=100)
        assert first.fingerprint == second.fingerprint
        db.upsert_detection_finding(first)
        single = db.recompute_risk("10.0.0.8", persist=False, as_of=1000.0)
        db.upsert_detection_finding(second)
        global_score = db.recompute_risk("10.0.0.8", persist=False, as_of=1000.0)
        assert global_score["priority_score"] >= single["priority_score"]
        assert global_score["priority_score"] < single["priority_score"] * 1.4
        repeated = db.recompute_risk("10.0.0.8", source="live_Ethernet#b", persist=False, as_of=1000.0)
        assert repeated["priority_score"] < 40
    finally:
        db.close()


def test_syn_flood_and_cold_start_exfiltration_require_corroboration():
    flood = FlowAggregate(("10.0.0.5", "10.0.0.20", 50000, 443, "TCP"), 0.0, 3.0)
    flood.tcp_syn_count = 3000
    flood.tcp_syn_ack_count = 100
    assert any(alert.type == "SYN_FLOOD" for _, alert in StatefulHostDetector().analyze({flood.flow_id: flood}))
    flood.tcp_syn_ack_count = 1000
    assert not any(alert.type == "SYN_FLOOD" for _, alert in StatefulHostDetector().analyze({flood.flow_id: flood}))

    backup = FlowAggregate(("10.0.0.5", "8.8.8.8", 50000, 443, "TCP"), 0.0, 300.0)
    backup.byte_count = 200 * 1024 * 1024
    backup.l7_metadata = {"reverse_byte_count": 1024, "peer_novelty": False}
    assert not any(alert.type == "POTENTIAL_EXFILTRATION" for _, alert in StatefulHostDetector().analyze({backup.flow_id: backup}))

    million = FlowAggregate(("10.0.0.5", "10.0.0.20", 50000, 443, "TCP"), 0.0, 1000.0)
    million.tcp_syn_count = 1_000_000
    assert any(alert.type == "SYN_FLOOD" for alert in ReconLateralDetector().detect(flow=million))


def test_redundant_lan_services_are_observations_without_policy():
    detector = LANTrustDetector()
    offers = []
    for server in ("10.0.0.1", "10.0.0.2"):
        packet = scapy.IP(src=server, dst="255.255.255.255")/scapy.UDP(sport=67, dport=68)/scapy.BOOTP(siaddr=server)/scapy.DHCP(options=[("message-type", "offer"), ("server_id", server), "end"])
        offers.extend(detector.detect(packet=packet))
    assert offers == []


def test_benign_corpus_controls_do_not_create_high_priority_findings():
    dns = DNSDetector()
    for index in range(100):
        packet = scapy.IP(src="10.0.0.5", dst="8.8.8.8")/scapy.UDP(dport=53)/scapy.DNS(qd=scapy.DNSQR(qname=f"edge{index}.google.com"))
        packet.time = float(index)
        assert dns.detect(domain=f"edge{index}.google.com", packet=packet) == []

    vpn = scapy.IP(src="10.0.0.5", dst="1.1.1.1")/scapy.UDP(sport=51820, dport=51820)/scapy.Raw(os.urandom(128))
    discovery = scapy.IP(src="10.0.0.5", dst="224.0.0.251")/scapy.UDP(sport=5353, dport=5353)/scapy.Raw(b"service discovery")
    assert LANTrustDetector().detect(packet=vpn) == []
    assert LANTrustDetector().detect(packet=discovery) == []

    modbus = scapy.IP(src="10.0.0.10", dst="10.0.0.20")/scapy.TCP(dport=502)/scapy.Raw(b"\x00\x01\x00\x00\x00\x02\x01\x10")
    policy = {"enabled": True, "authorized_masters": ["10.0.0.10"], "authorized_units": [1], "authorized_write_functions": [16]}
    assert IoTOTSafetyDetector(policy=policy).detect(packet=modbus) == []

    admin_detector = ReconLateralDetector()
    alerts = []
    for index in range(8):
        flow = FlowAggregate(("10.0.0.5", f"10.0.0.{20 + index}", 50000 + index, 445, "TCP"), 0.0, 10.0)
        flow.tcp_syn_count = 1
        alerts.extend(admin_detector.detect(flow=flow))
    assert not any(alert.type == "LATERAL_MOVEMENT" for alert in alerts)

    download = scapy.IP(src="1.1.1.1", dst="10.0.0.5")/scapy.TCP(sport=443, dport=50000)/scapy.Raw(b"MZ" + b"x" * 64 + b"This program cannot be run in DOS mode")
    file_alert = FileTransferDetector().detect(packet=download)[0]
    assert file_alert.severity == "LOW"


def test_dns_tunnel_accepts_realistic_random_hex_entropy():
    detector = DNSDetector()
    alerts = []
    labels = [
        hashlib.sha256(f"watchtower-{index}".encode()).hexdigest()[:48]
        for index in range(20)
    ]
    for index, label in enumerate(labels):
        domain = f"{label}.acceptance.invalid"
        packet = (
            scapy.IP(src="10.0.0.5", dst="8.8.8.8")
            / scapy.UDP(sport=53000 + index, dport=53)
            / scapy.DNS(qd=scapy.DNSQR(qname=domain, qtype="TXT"))
        )
        packet.time = float(index)
        alerts.extend(detector.detect(domain=domain, packet=packet))
    assert [alert.type for alert in alerts] == ["SUSPICIOUS_DNS"]


def test_live_pipeline_wires_dns_parser_metadata_to_detector(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    engine = ForensicsEngine(db=db, data_dir=str(tmp_path), silent=True)
    alerts = []
    try:
        for index in range(20):
            label = hashlib.sha256(f"watchtower-live-{index}".encode()).hexdigest()[:48]
            domain = f"{label}.acceptance.invalid"
            packet = (
                scapy.Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:55")
                / scapy.IP(src="10.0.0.5", dst="8.8.8.8")
                / scapy.UDP(sport=53000 + index, dport=53)
                / scapy.DNS(qd=scapy.DNSQR(qname=domain, qtype="TXT"))
            )
            packet.time = float(index + 1)
            flow = FlowAggregate(("10.0.0.5", "8.8.8.8", 53000 + index, 53, "UDP"), packet.time, packet.time)
            _identities, found = engine.process_live_packet(
                packet, flow, capture_interface="Ethernet", capture_session_id="dns-live-session",
                capture_backend="python", persist_identity=False,
            )
            alerts.extend(found)
        assert [alert.type for alert in alerts] == ["SUSPICIOUS_DNS"]
    finally:
        db.close()


def test_baseline_is_bounded_and_maturity_is_explicit():
    stats = OnlineFeatureStats()
    for value in range(10_000):
        stats.update(value)
    assert stats.count == 10_000
    assert len(stats.samples) == MAX_QUANTILE_SAMPLES
    assert stats.p50 if hasattr(stats, "p50") else stats.percentile(0.5) > 0
    immature = baseline_maturity(199, 0, 8 * 86400)
    mature = baseline_maturity(200, 0, 8 * 86400)
    assert immature["mature"] is False and immature["contribution_cap"] == 10
    assert mature["mature"] is True
    assert learning_allowed(generated_probe=True) is False
    assert learning_allowed(sensor_drop_ratio=0.02) is False


class OfflineDaemon:
    def get_status(self):
        return {"running": False, "interfaces": []}


class EmptyRegistry:
    def list_devices(self):
        return []

    def list_sources(self):
        return []


def test_api_v2_scoring_explain_and_disposition(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    created = db.upsert_detection_finding(finding(observed_at=time.time()))
    with TestClient(create_app(db=db, daemon=OfflineDaemon(), registry=EmptyRegistry())) as client:
        findings = client.get("/api/v2/findings", params={"subject": "10.0.0.8"})
        assert findings.status_code == 200
        assert findings.json()["items"][0]["finding_type"] == "behavior.beacon.suspected"
        explanation = client.get("/api/v2/risk/entities/10.0.0.8/explain")
        assert explanation.status_code == 200
        assert explanation.json()["priority_score"] > 0
        assert "assessment_confidence" in explanation.json()
        disposition = client.post(f"/api/v2/findings/{created['id']}/disposition", json={
            "verdict": "false_positive", "reason": "validated maintenance traffic",
        })
        assert disposition.status_code == 200
        assert disposition.json()["assessment"]["priority_score"] == 0


def test_verified_backup_purge_and_restore(tmp_path):
    data = tmp_path / "data"
    db = WatchtowerDB(data_dir=str(data))
    db.upsert_entity("10.0.0.8", timestamp=1.0)
    db.insert_alert("10.0.0.8", 1.0, "TEST", "HIGH", 50, "legacy")
    operations = ScoringOperations(db)
    result = operations.backup_and_purge()
    backup = Path(result["database"])
    assert backup.exists() and Path(result["manifest"]).exists()
    assert db.get_alerts(include_hidden=True) == []
    db.close()

    restored = ScoringOperations.restore_backup(str(backup), str(data / "watchtower.db"))
    assert restored["sha256"] == result["sha256"]
    restored_db = WatchtowerDB(data_dir=str(data))
    try:
        assert len(restored_db.get_alerts(include_hidden=True)) == 1
    finally:
        restored_db.close()

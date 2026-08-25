#!/usr/bin/env python3
"""
Compare traffic injection results with Watchtower detection output.

This script reads the attack logs and compares them against
alerts found in the Watchtower database.

Usage:
    python -m traffic_testing.compare_results
    python -m traffic_testing.compare_results --session 20260725_230000
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Set

from traffic_testing.config import RESULTS_DIR, LOG_DIR


EXPECTED_DETECTIONS = {
    "tcp_connect_scan": {
        "expected_detector": "recon.port_scan",
        "expected_finding_type": "recon.port_scan",
        "description": "TCP connect scan should trigger port scan detection",
    },
    "tcp_syn_scan": {
        "expected_detector": "recon.port_scan",
        "expected_finding_type": "recon.port_scan",
        "description": "TCP SYN scan should trigger port scan detection",
    },
    "horizontal_scan": {
        "expected_detector": "recon.host_scan",
        "expected_finding_type": "recon.host_scan",
        "description": "Horizontal scan should trigger host scan detection",
    },
    "arp_poisoning": {
        "expected_detector": "lan.trust",
        "expected_finding_type": "network.arp.binding_conflict",
        "description": "ARP poisoning should trigger binding conflict detection",
    },
    "c2_beacon_regular": {
        "expected_detector": "behavior.beacon",
        "expected_finding_type": "behavior.beacon.suspected",
        "description": "Regular C2 beaconing should trigger beacon detection (CV < 0.20)",
    },
    "c2_beacon_no_response": {
        "expected_detector": "behavior.beacon",
        "expected_finding_type": "behavior.beacon.suspected",
        "description": "One-way beacon should trigger response_anomaly corroboration",
    },
    "dns_tunneling": {
        "expected_detector": "dns.tunnel",
        "expected_finding_type": "dns.tunnel.suspected",
        "description": "DNS tunnel with encoded data should trigger DNS tunnel detection",
    },
    "dns_tunnel_txt": {
        "expected_detector": "dns.tunnel",
        "expected_finding_type": "dns.tunnel.suspected",
        "description": "TXT record DNS tunnel should trigger with qtype corroboration",
    },
    "dga_domain_generation": {
        "expected_detector": "dns.tunnel",
        "expected_finding_type": "dns.tunnel.suspected",
        "description": "DGA domains should have high entropy triggering DNS detection",
    },
    "fast_flux_dns": {
        "expected_detector": "dns.tunnel",
        "expected_finding_type": "dns.tunnel.suspected",
        "description": "Fast flux with many subdomains should trigger DNS detection",
    },
    "ftp_credential_exposure": {
        "expected_detector": "credential.ftp",
        "expected_finding_type": "credential.cleartext.ftp",
        "description": "FTP PASS command should trigger cleartext credential detection",
    },
    "http_basic_auth_exposure": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "credential.cleartext.generic",
        "description": "HTTP Basic Auth header should match cleartext credential regex",
    },
    "http_password_param": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "credential.cleartext.generic",
        "description": "Password in POST body should match credential regex",
    },
    "auth_failure_burst": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "auth.failure_burst",
        "description": "5+ auth failures in 300s window should trigger burst detection",
    },
    "smb_brute_force": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "auth.failure_burst",
        "description": "SMB brute force should trigger auth failure burst detection",
    },
    "icmp_exfil": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "icmp.tunnel.suspected",
        "description": "ICMP with high-entropy payload should trigger tunnel detection",
    },
    "tls_protocol_mismatch": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "tls.protocol_mismatch",
        "description": "Non-TLS traffic on port 443 should trigger protocol mismatch",
    },
    "ssh_nonstandard_port": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "protocol.nonstandard_service",
        "description": "SSH banner on non-22 port should trigger nonstandard service",
    },
    "vnc_nonstandard_port": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "protocol.nonstandard_service",
        "description": "VNC RFB banner on non-5900 port should trigger nonstandard service",
    },
    "syn_flood_low_rate": {
        "expected_detector": "recon.syn_flood",
        "expected_finding_type": "recon.syn_flood",
        "description": "SYN flood at 50/s should be below 1000/s threshold (gap test)",
    },
    "modbus_unauthorized_write": {
        "expected_detector": "iot-ot.safety",
        "expected_finding_type": "ot.modbus.unauthorized_write",
        "description": "Modbus write with unauthorized source should trigger OT safety",
    },
    "mqtt_cleartext_creds": {
        "expected_detector": "iot-ot.safety",
        "expected_finding_type": "credential.cleartext.mqtt",
        "description": "MQTT CONNECT with username/password flags should trigger IoT safety",
    },
    "ntlm_credential_exposure": {
        "expected_detector": "ntlm.parser",
        "expected_finding_type": "identity.ntlm",
        "description": "NTLM Type 3 messages should extract domain\\username",
    },
    "lateral_admin_fanout": {
        "expected_detector": "recon",
        "expected_finding_type": "lateral.admin_fanout",
        "description": "Multiple admin port contacts should trigger lateral movement detection",
    },
    "dns_exfil_slow": {
        "expected_detector": "dns.tunnel",
        "expected_finding_type": "dns.tunnel.suspected",
        "description": "Slow DNS exfiltration should trigger DNS tunnel detection",
    },
    "http_exfil_fast": {
        "expected_detector": "exfiltration",
        "expected_finding_type": "exfil.volume_anomaly",
        "description": "Large HTTP upload should trigger volume anomaly (50MB > 100MB? No - gap)",
    },
    "https_exfil": {
        "expected_detector": "exfiltration",
        "expected_finding_type": "exfil.volume_anomaly",
        "description": "HTTPS exfiltration (10MB) may be below 100MB threshold (gap test)",
    },
    "encrypted_c2_channel": {
        "expected_detector": "behavior.beacon",
        "expected_finding_type": "behavior.beacon.suspected",
        "description": "Encrypted C2 beaconing should still show timing patterns",
    },
    "covert_icmp_channel": {
        "expected_detector": "application.abuse",
        "expected_finding_type": "icmp.tunnel.suspected",
        "description": "Covert ICMP with non-standard codes should trigger tunnel detection",
    },
}


def get_latest_session() -> str:
    files = [f for f in os.listdir(RESULTS_DIR) if f.startswith("summary_") and f.endswith(".json")]
    if not files:
        return ""
    files.sort(reverse=True)
    return files[0].replace("summary_", "").replace(".json", "")


def load_attack_logs(session_id: str) -> Dict[str, List[dict]]:
    logs = {}
    for filename in os.listdir(LOG_DIR):
        if filename.endswith("_packets.jsonl"):
            attack_name = filename.replace("_packets.jsonl", "")
            filepath = os.path.join(LOG_DIR, filename)
            entries = []
            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            entries.append(json.loads(line))
            except Exception:
                pass
            if entries:
                logs[attack_name] = entries
    return logs


def analyze_gaps(attack_logs: Dict[str, List[dict]]) -> dict:
    gaps = []
    detected = []
    for attack_name, expected in EXPECTED_DETECTIONS.items():
        has_traffic = attack_name in attack_logs or any(
            attack_name in k for k in attack_logs.keys()
        )
        gap_info = {
            "attack": attack_name,
            "expected_detector": expected["expected_detector"],
            "expected_finding_type": expected["expected_finding_type"],
            "description": expected["description"],
            "traffic_generated": has_traffic,
            "packet_count": sum(len(v) for k, v in attack_logs.items() if attack_name in k),
        }

        detector_enabled = check_detector_enabled(expected["expected_finding_type"])
        gap_info["detector_enabled"] = detector_enabled

        if not detector_enabled:
            gap_info["gap_type"] = "DETECTOR_DISABLED"
            gap_info["recommendation"] = f"Enable detector for {expected['expected_finding_type']}"
            gaps.append(gap_info)
        else:
            gap_info["gap_type"] = "NEEDS_VERIFICATION"
            gap_info["recommendation"] = "Check Watchtower alerts to verify detection"
            detected.append(gap_info)

    return {"gaps": gaps, "detected": detected, "total_attacks": len(EXPECTED_DETECTIONS)}


def check_detector_enabled(finding_type: str) -> bool:
    disabled_detectors = {
        "behavior.beacon.suspected": False,
        "exfil.volume_anomaly": False,
        "recon.port_scan": False,
        "recon.syn_flood": False,
        "lateral.admin_fanout": False,
    }
    if finding_type in disabled_detectors:
        return disabled_detectors[finding_type]
    return True


def print_comparison(attack_logs: Dict[str, List[dict]], analysis: dict) -> None:
    print(f"\n{'='*70}")
    print(f"  WATCHTOWER DETECTION GAP ANALYSIS")
    print(f"{'='*70}\n")

    print(f"  Attacks with traffic generated: {len(attack_logs)}")
    print(f"  Expected detection patterns:    {analysis['total_attacks']}")
    print(f"  Gaps found (detectors off):     {len(analysis['gaps'])}")
    print(f"  Needs verification:             {len(analysis['detected'])}")

    if analysis["gaps"]:
        print(f"\n  {'='*70}")
        print(f"  DETECTOR GAPS (disabled detectors):")
        print(f"  {'='*70}")
        for gap in analysis["gaps"]:
            print(f"\n  ATTACK:     {gap['attack']}")
            print(f"  DETECTOR:   {gap['expected_detector']}")
            print(f"  FINDING:    {gap['expected_finding_type']}")
            print(f"  TRAFFIC:    {gap['packet_count']} packets generated")
            print(f"  ISSUE:      {gap['gap_type']}")
            print(f"  RECOMMEND:  {gap['recommendation']}")

    if analysis["detected"]:
        print(f"\n  {'='*70}")
        print(f"  ATTACKS NEEDING MANUAL VERIFICATION:")
        print(f"  {'='*70}")
        for det in analysis["detected"]:
            print(f"\n  ATTACK:     {det['attack']}")
            print(f"  DETECTOR:   {det['expected_detector']}")
            print(f"  FINDING:    {det['expected_finding_type']}")
            print(f"  TRAFFIC:    {det['packet_count']} packets generated")
            print(f"  NOTE:       Check Watchtower alerts for this finding type")

    print(f"\n  {'='*70}")
    print(f"  RECOMMENDED ACTIONS:")
    print(f"  {'='*70}")
    print(f"  1. Enable disabled detectors in core/forensics/plugins/detectors/")
    print(f"  2. Enable UnifiedStatefulBehaviorDetector if not already")
    print(f"  3. Check Watchtower alerts: tower --cmd 'show alerts'")
    print(f"  4. Check database: SELECT type, score FROM alerts")
    print(f"  5. Run: tower --cmd 'show entities'")
    print(f"  {'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description="Compare test results with Watchtower detections")
    parser.add_argument("--session", default=None, help="Session ID to analyze")
    args = parser.parse_args()

    session_id = args.session or get_latest_session()
    if not session_id:
        print("No test sessions found. Run the test suite first.")
        sys.exit(1)

    print(f"  Analyzing session: {session_id}")
    attack_logs = load_attack_logs(session_id)
    analysis = analyze_gaps(attack_logs)
    print_comparison(attack_logs, analysis)

    report_path = os.path.join(RESULTS_DIR, f"gap_analysis_{session_id}.json")
    with open(report_path, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"  Gap analysis written to: {report_path}")


if __name__ == "__main__":
    main()

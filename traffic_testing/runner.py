#!/usr/bin/env python3
"""
Main runner for Watchtower traffic injection tests.

Orchestrates all attack modules over a ~2 hour window.
Some attacks run quickly (scans, credential exposure) while others
run continuously (beaconing, DNS tunneling) in the background.

Usage:
    python -m traffic_testing.runner
    python -m traffic_testing.runner --target 192.168.1.100
    python -m traffic_testing.runner --phase quick
    python -m traffic_testing.runner --phase extended
    python -m traffic_testing.runner --phase all
"""

import argparse
import os
import sys
import time
import threading
from datetime import datetime, timezone

from traffic_testing.config import TARGET_IP, LOCAL_IP, RESULTS_DIR
from traffic_testing.monitor import TrafficMonitor, AttackRunnerMonitor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Watchtower Traffic Injection Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Phase options:
  quick      - Run only fast tests (~5 minutes)
  extended   - Run long-running tests (beaconing, DNS tunneling) (~90 minutes)
  exfil      - Run exfiltration tests only (~30 minutes)
  dos        - Run DoS pattern tests only (~5 minutes)
  ot         - Run OT/IoT tests only (~5 minutes)
  discovery  - Run network discovery tests only (~5 minutes)
  evasion    - Run defense evasion tests only (~10 minutes)
  all        - Run everything (~2 hours)
        """,
    )
    parser.add_argument("--target", default=TARGET_IP,
                        help=f"Target IP (default: {TARGET_IP})")
    parser.add_argument("--phase", default="all",
                        choices=["quick", "extended", "exfil", "dos", "ot", "discovery", "evasion", "all"],
                        help="Test phase to run")
    parser.add_argument("--no-beacon", action="store_true",
                        help="Skip long-running beaconing tests")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Skip port scanning tests")
    return parser.parse_args()


def run_quick_tests(target_ip: str, monitor: TrafficMonitor,
                    runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.scanning import (
        TCPConnectScan, TCPSYNScan, TCPXMASScan, TCPNullScan,
        HorizontalScan, ServiceEnumeration, ARPScan,
        SSHPortScan, RDPNonstandardPort,
    )
    from traffic_testing.attacks.credential_attacks import (
        FTPCredentialExposure, HTTPBasicAuthExposure,
        HTTPPasswordParamExposure, SMTPCredentialExposure,
        AuthFailureBurst, SNMPCommunityStringExposure,
    )
    from traffic_testing.attacks.lateral_movement import (
        LateralAdminFanout, SMBBruteForce,
    )
    from traffic_testing.attacks.discovery import (
        SSDPDiscovery, MDNSDiscovery, NBNSDiscovery,
        DHCPDiscovery,         ARPPoisoning,
    )

    attacks = [
        ("TCP Connect Scan", TCPConnectScan(target_ip=target_ip, ports=list(range(1, 66)))),
        ("TCP SYN Scan", TCPSYNScan(target_ip=target_ip, ports=list(range(1, 66)))),
        ("XMAS Scan", TCPXMASScan(target_ip=target_ip, ports=list(range(1, 40)))),
        ("Null Scan", TCPNullScan(target_ip=target_ip, ports=list(range(1, 40)))),
        ("Horizontal Scan", HorizontalScan(base_ip=target_ip, port=80, count=25)),
        ("Service Enumeration", ServiceEnumeration(target_ip=target_ip)),
        ("ARP Scan", ARPScan(base_ip=target_ip)),
        ("SSH Nonstandard Ports", SSHPortScan(target_ip=target_ip)),
        ("RDP Nonstandard Ports", RDPNonstandardPort(target_ip=target_ip)),
        ("FTP Credential Exposure", FTPCredentialExposure(target_ip=target_ip)),
        ("HTTP Basic Auth Exposure", HTTPBasicAuthExposure(target_ip=target_ip)),
        ("HTTP Password Param", HTTPPasswordParamExposure(target_ip=target_ip)),
        ("SMTP Credential Exposure", SMTPCredentialExposure(target_ip=target_ip)),
        ("Auth Failure Burst (SSH)", AuthFailureBurst(target_ip=target_ip, port=22, protocol="SSH")),
        ("SNMP Community Strings", SNMPCommunityStringExposure(target_ip=target_ip)),
        ("Lateral Admin Fanout", LateralAdminFanout(base_ip=target_ip)),
        ("SMB Brute Force", SMBBruteForce(target_ip=target_ip)),
        ("SSDP Discovery", SSDPDiscovery(target_ip=target_ip)),
        ("mDNS Discovery", MDNSDiscovery(target_ip=target_ip)),
        ("NBNS Discovery", NBNSDiscovery(target_ip=target_ip)),
        ("DHCP Discovery", DHCPDiscovery(target_ip=target_ip)),
        ("ARP Poisoning", ARPPoisoning(target_ip=target_ip)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    for name, attack in started:
        attack.wait(timeout=120)
        attack.stop()
        runner_monitor.on_attack_complete(name)

    return started


def run_extended_tests(target_ip: str, monitor: TrafficMonitor,
                       runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.malware_c2 import (
        C2BeaconRegular, C2BeaconJittered, C2BeaconNoResponse,
        DNSTunneling, DGADomainGeneration, FastFluxDNS, DNSTunnelTXTExfil,
    )
    from traffic_testing.attacks.lateral_movement import (
        WMIExecution, PowerShellRemoting, Kerberoasting,
    )
    from traffic_testing.attacks.ot_iot import (
        ModbusUnauthorizedWrite, MQTTWithCleartextCredentials,
        ModbusScanAndEnumerate,
    )

    attacks = [
        ("C2 Beacon Regular (90min)", C2BeaconRegular(target_ip=target_ip, interval=3.0, duration=5400)),
        ("C2 Beacon Jittered (90min)", C2BeaconJittered(target_ip=target_ip, base_interval=10.0, duration=5400)),
        ("C2 Beacon No Response (10min)", C2BeaconNoResponse(target_ip=target_ip, interval=5.0, duration=600)),
        ("DNS Tunneling (60min)", DNSTunneling(target_ip=target_ip, duration=3600)),
        ("DNS Tunnel TXT (30min)", DNSTunnelTXTExfil(target_ip=target_ip, duration=1800)),
        ("DGA Domain Generation (30min)", DGADomainGeneration(target_ip=target_ip, duration=1800)),
        ("Fast Flux DNS (10min)", FastFluxDNS(target_ip=target_ip, duration=600)),
        ("WMI Execution", WMIExecution(target_ip=target_ip)),
        ("PowerShell Remoting", PowerShellRemoting(target_ip=target_ip)),
        ("Kerberoasting", Kerberoasting(target_ip=target_ip)),
        ("Modbus Unauthorized Write", ModbusUnauthorizedWrite(target_ip=target_ip)),
        ("MQTT Cleartext Credentials", MQTTWithCleartextCredentials(target_ip=target_ip)),
        ("Modbus Enumeration", ModbusScanAndEnumerate(target_ip=target_ip)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    return started


def run_exfil_tests(target_ip: str, monitor: TrafficMonitor,
                    runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.exfiltration import (
        DNSExfiltrationSlow, DNSExfiltrationFast,
        HTTPExfiltrationFast, HTTPExfiltrationSlow,
        ICMPExfiltration, HTTPSExfiltration,
        CovertHTTPDNSExfil,
    )

    attacks = [
        ("DNS Exfil Slow (30min)", DNSExfiltrationSlow(target_ip=target_ip, duration=1800)),
        ("DNS Exfil Fast", DNSExfiltrationFast(target_ip=target_ip, total_bytes=512*1024)),
        ("HTTP Exfil Fast (50MB)", HTTPExfiltrationFast(target_ip=target_ip, total_bytes=50*1024*1024)),
        ("HTTP Exfil Slow (30min)", HTTPExfiltrationSlow(target_ip=target_ip, duration=1800)),
        ("ICMP Exfil (50 packets)", ICMPExfiltration(target_ip=target_ip, total_count=50)),
        ("HTTPS Exfil (10MB)", HTTPSExfiltration(target_ip=target_ip, total_bytes=10*1024*1024)),
        ("Covert HTTP-over-DNS (30min)", CovertHTTPDNSExfil(target_ip=target_ip, duration=1800)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    return started


def run_dos_tests(target_ip: str, monitor: TrafficMonitor,
                  runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.dos import (
        SYNFloodLowRate, SlowlorisPattern, UDPFloodLowRate,
        HTTPFloodLowRate, ICMPFloodLowRate,
    )

    attacks = [
        ("SYN Flood Low Rate (30s)", SYNFloodLowRate(target_ip=target_ip, rate=50, duration=30)),
        ("Slowloris (60s)", SlowlorisPattern(target_ip=target_ip, connections=20, duration=60)),
        ("UDP Flood Low Rate (30s)", UDPFloodLowRate(target_ip=target_ip, rate=30, duration=30)),
        ("HTTP Flood Low Rate (30s)", HTTPFloodLowRate(target_ip=target_ip, rate=20, duration=30)),
        ("ICMP Flood Low Rate (30s)", ICMPFloodLowRate(target_ip=target_ip, rate=20, duration=30)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    for name, attack in started:
        attack.wait(timeout=120)
        attack.stop()
        runner_monitor.on_attack_complete(name)

    return started


def run_discovery_tests(target_ip: str, monitor: TrafficMonitor,
                        runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.discovery import (
        SSDPDiscovery, MDNSDiscovery, NBNSDiscovery, DHCPDiscovery,
    )

    attacks = [
        ("SSDP Discovery (20 queries)", SSDPDiscovery(target_ip=target_ip)),
        ("mDNS Discovery (10 queries)", MDNSDiscovery(target_ip=target_ip)),
        ("NBNS Discovery (5 queries)", NBNSDiscovery(target_ip=target_ip)),
        ("DHCP Discovery (5 attempts)", DHCPDiscovery(target_ip=target_ip)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    for name, attack in started:
        attack.wait(timeout=120)
        attack.stop()
        runner_monitor.on_attack_complete(name)

    return started


def run_evasion_tests(target_ip: str, monitor: TrafficMonitor,
                      runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.defense_evasion import (
        TLSTrafficWithNonTLSContent, SSHOnNonstandardPort,
        VNCOnNonstandardPort, DomainFrontingSimulation,
        ProtocolTunnelingHTTPoverDNS, EncryptedC2Channel,
        PaddingExfiltration, CovertICMPChannel,
    )

    attacks = [
        ("TLS Protocol Mismatch", TLSTrafficWithNonTLSContent(target_ip=target_ip)),
        ("SSH Nonstandard Ports", SSHOnNonstandardPort(target_ip=target_ip)),
        ("VNC Nonstandard Ports", VNCOnNonstandardPort(target_ip=target_ip)),
        ("Domain Fronting", DomainFrontingSimulation(target_ip=target_ip)),
        ("HTTP over DNS Tunnel (10min)", ProtocolTunnelingHTTPoverDNS(target_ip=target_ip, duration=600)),
        ("Encrypted C2 Channel (20 msgs)", EncryptedC2Channel(target_ip=target_ip)),
        ("Padding Exfiltration (30 msgs)", PaddingExfiltration(target_ip=target_ip)),
        ("Covert ICMP Channel (50 msgs)", CovertICMPChannel(target_ip=target_ip, count=50)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    for name, attack in started:
        attack.wait(timeout=120)
        attack.stop()
        runner_monitor.on_attack_complete(name)

    return started


def run_ot_tests(target_ip: str, monitor: TrafficMonitor,
                 runner_monitor: AttackRunnerMonitor) -> list:
    from traffic_testing.attacks.ot_iot import (
        ModbusUnauthorizedWrite, MQTTWithoutAuthentication,
        MQTTWithCleartextCredentials, ModbusScanAndEnumerate,
    )

    attacks = [
        ("Modbus Unauthorized Write", ModbusUnauthorizedWrite(target_ip=target_ip)),
        ("MQTT Without Auth", MQTTWithoutAuthentication(target_ip=target_ip)),
        ("MQTT Cleartext Credentials", MQTTWithCleartextCredentials(target_ip=target_ip)),
        ("Modbus Enumeration", ModbusScanAndEnumerate(target_ip=target_ip)),
    ]

    started = []
    for name, attack in attacks:
        runner_monitor.on_attack_start(name, attack)
        attack.start()
        started.append((name, attack))

    for name, attack in started:
        attack.wait(timeout=120)
        attack.stop()
        runner_monitor.on_attack_complete(name)

    return started


def main():
    args = parse_args()
    target_ip = args.target
    phase = args.phase

    monitor = TrafficMonitor()
    runner_monitor = AttackRunnerMonitor(monitor)
    monitor.start()

    print(f"  Target IP:  {target_ip}")
    print(f"  Local IP:   {LOCAL_IP}")
    print(f"  Phase:      {phase}")
    print(f"  Results:    {RESULTS_DIR}")
    print()

    extended_background = []
    all_quick = []

    try:
        if phase in ("all", "quick"):
            print(f"\n{'='*60}")
            print(f"  PHASE 1: QUICK TESTS (~5 min)")
            print(f"{'='*60}\n")
            all_quick = run_quick_tests(target_ip, monitor, runner_monitor)

        if phase in ("all", "extended"):
            print(f"\n{'='*60}")
            print(f"  PHASE 2: EXTENDED TESTS (running in background)")
            print(f"{'='*60}\n")
            extended_background = run_extended_tests(target_ip, monitor, runner_monitor)
            print(f"  {len(extended_background)} extended attacks running in background...")

        if phase in ("all", "exfil"):
            print(f"\n{'='*60}")
            print(f"  PHASE 3: EXFILTRATION TESTS")
            print(f"{'='*60}\n")
            exfil_attacks = run_exfil_tests(target_ip, monitor, runner_monitor)
            extended_background.extend(exfil_attacks)

        if phase in ("all", "dos"):
            print(f"\n{'='*60}")
            print(f"  PHASE 4: DoS PATTERN TESTS (~5 min)")
            print(f"{'='*60}\n")
            run_dos_tests(target_ip, monitor, runner_monitor)

        if phase in ("all", "discovery"):
            print(f"\n{'='*60}")
            print(f"  PHASE 5: NETWORK DISCOVERY TESTS")
            print(f"{'='*60}\n")
            run_discovery_tests(target_ip, monitor, runner_monitor)

        if phase in ("all", "evasion"):
            print(f"\n{'='*60}")
            print(f"  PHASE 6: DEFENSE EVASION TESTS")
            print(f"{'='*60}\n")
            run_evasion_tests(target_ip, monitor, runner_monitor)

        if phase in ("all", "ot"):
            print(f"\n{'='*60}")
            print(f"  PHASE 7: OT/IoT TESTS")
            print(f"{'='*60}\n")
            run_ot_tests(target_ip, monitor, runner_monitor)

        if extended_background and phase == "all":
            print(f"\n{'='*60}")
            print(f"  WAITING FOR BACKGROUND ATTACKS TO COMPLETE")
            print(f"  (This may take a while - check back periodically)")
            print(f"{'='*60}\n")

            still_running = True
            while still_running:
                still_running = False
                for name, attack in extended_background:
                    if attack.is_running:
                        still_running = True
                        break
                if still_running:
                    time.sleep(30)
                    completed = sum(1 for _, a in extended_background if not a.is_running)
                    print(f"  [{datetime.now().strftime('%H:%M:%S')}] "
                          f"{completed}/{len(extended_background)} extended attacks complete")

            for name, attack in extended_background:
                if attack.is_running:
                    attack.stop()
                runner_monitor.on_attack_complete(name)

    except KeyboardInterrupt:
        print(f"\n\n  Interrupted! Stopping all attacks...")
        for name, attack in extended_background:
            if attack.is_running:
                attack.stop()

    monitor.stop()


if __name__ == "__main__":
    main()

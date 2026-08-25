"""Schedule long-running, self-addressed behavioral acceptance traffic."""

from __future__ import annotations

import argparse
import hashlib
import heapq
import ipaddress
import json
import time

import scapy.all as scapy


SYNTHETIC_NETWORK = ipaddress.ip_network("127.250.0.0/24")
MARKER = b"WT-EXTENDED-V2|"


def deterministic_bytes(size: int, seed: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:size])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="Ethernet")
    parser.add_argument("--log", default="data/temp/extended_acceptance.jsonl")
    args = parser.parse_args()

    device = scapy.conf.ifaces.dev_from_name(args.interface)
    mac = str(device.mac or "")
    if not mac or mac == "00:00:00:00:00:00":
        raise SystemExit(f"Could not resolve a usable MAC for {args.interface}")

    def frame(src: str, dst: str, payload):
        if ipaddress.ip_address(src) not in SYNTHETIC_NETWORK:
            raise ValueError("source must use the synthetic acceptance network")
        if ipaddress.ip_address(dst) not in SYNTHETIC_NETWORK:
            raise ValueError("destination must use the synthetic acceptance network")
        return scapy.Ether(src=mac, dst=mac) / scapy.IP(src=src, dst=dst) / payload

    events = []

    def schedule(offset: float, scenario: str, packet) -> None:
        heapq.heappush(events, (offset, len(events), scenario, packet))

    # Negative threshold control: 19 ports in one minute must not become a scan.
    for index in range(19):
        schedule(index * 0.02, "negative_19_port_scan", frame(
            "127.250.0.21", "127.250.0.22",
            scapy.TCP(sport=57000 + index, dport=21000 + index, flags="S", seq=index),
        ))

    # Five failures over four minutes, then a success, exercise evolving auth state.
    for index in range(5):
        schedule(index * 60.0, "auth_failure_slow_burst", frame(
            "127.250.0.23", "127.250.0.24",
            scapy.TCP(sport=58000 + index, dport=3389, flags="PA", seq=index + 1)
            / (MARKER + b"authentication failed"),
        ))
    schedule(270.0, "auth_success_after_failures", frame(
        "127.250.0.23", "127.250.0.24",
        scapy.TCP(sport=58010, dport=3389, flags="PA", seq=1)
        / (MARKER + b"authentication successful"),
    ))

    # Administrative fanout is short, but delayed so it correlates after natural traffic.
    for index in range(6):
        schedule(300.0 + index * 0.1, "lateral_admin_fanout", frame(
            "127.250.0.25", f"127.250.0.{30 + index}",
            scapy.TCP(sport=59000 + index, dport=445, flags="S", seq=index + 1),
        ))

    # Twenty callbacks over 28.5 minutes test low-and-slow periodicity.
    for index in range(20):
        schedule(index * 90.0, "slow_beacon_positive", frame(
            "127.250.0.26", "127.250.0.27",
            scapy.UDP(sport=60000, dport=4445) / (MARKER + b"slow-beacon"),
        ))

    # Twenty-four ports spread over 28.75 minutes are a required negative control.
    for index in range(24):
        schedule(index * 75.0, "slow_scan_negative", frame(
            "127.250.0.28", "127.250.0.29",
            scapy.TCP(sport=61000 + index, dport=22000 + index, flags="S", seq=index + 1),
        ))

    # Encoded labels remain below the detector's five-minute query threshold.
    for index in range(20):
        label = deterministic_bytes(24, f"slow-dns-{index}".encode()).hex()
        schedule(index * 45.0, "slow_dns_negative", frame(
            "127.250.0.40", "127.250.0.53",
            scapy.UDP(sport=62000 + index, dport=53)
            / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=f"{label}.slow-control.invalid", qtype="TXT")),
        ))

    # Common NTP destination port must suppress periodic-heartbeat risk.
    for index in range(25):
        schedule(index * 10.0, "ntp_heartbeat_negative", frame(
            "127.250.0.41", "127.250.0.42",
            scapy.UDP(sport=63000, dport=123) / (MARKER + b"ntp-control"),
        ))

    started = time.time()
    with open(args.log, "a", encoding="utf-8") as log:
        while events:
            offset, _order, scenario, packet = heapq.heappop(events)
            delay = started + offset - time.time()
            if delay > 0:
                time.sleep(delay)
            scapy.sendp(packet, iface=args.interface, verbose=False)
            record = {
                "scenario": scenario,
                "scheduled_offset": offset,
                "sent_at": time.time(),
                "src": packet[scapy.IP].src,
                "dst": packet[scapy.IP].dst,
            }
            log.write(json.dumps(record, sort_keys=True) + "\n")
            log.flush()

    print(json.dumps({
        "interface": args.interface,
        "self_mac": mac,
        "duration_seconds": round(time.time() - started, 3),
        "log": args.log,
    }, sort_keys=True))


if __name__ == "__main__":
    main()

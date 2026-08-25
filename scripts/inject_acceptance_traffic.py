"""Inject auditable, self-addressed detector acceptance traffic.

Every Ethernet frame is sent from and to the selected interface's own MAC. Most
IP identities are loopback-only; the exfiltration fixture uses one fixed global
IP identity but remains an L2 self-frame and cannot target another LAN host.
"""

import argparse
import hashlib
import ipaddress
import json
import time

import scapy.all as scapy


MARKER = b"WT-ACCEPTANCE-V2|"
SYNTHETIC_NETWORK = ipaddress.ip_network("127.250.0.0/24")
EXFIL_TEST_DESTINATION = ipaddress.ip_address("8.8.8.8")


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
    parser.add_argument("--skip-large-transfer", action="store_true")
    parser.add_argument("--only-exfil", action="store_true")
    parser.add_argument("--exfil-destination", default=str(EXFIL_TEST_DESTINATION))
    parser.add_argument("--exfil-inter", type=float, default=0.003)
    args = parser.parse_args()
    exfil_destination = ipaddress.ip_address(args.exfil_destination)
    if not exfil_destination.is_global:
        raise SystemExit("The exfiltration semantic destination must be globally routable")
    if args.exfil_inter < 0.001:
        raise SystemExit("--exfil-inter must be at least 0.001 seconds")

    device = scapy.conf.ifaces.dev_from_name(args.interface)
    mac = str(device.mac or "")
    if not mac or mac == "00:00:00:00:00:00":
        raise SystemExit(f"Could not resolve a usable MAC for {args.interface}")

    def frame(src: str, dst: str, payload):
        source_address = ipaddress.ip_address(src)
        destination_address = ipaddress.ip_address(dst)
        if source_address not in SYNTHETIC_NETWORK:
            raise ValueError("Acceptance traffic sources must remain in 127.250.0.0/24")
        if destination_address not in SYNTHETIC_NETWORK and destination_address != exfil_destination:
            raise ValueError("Acceptance destinations must be synthetic or the fixed exfil test identity")
        return scapy.Ether(src=mac, dst=mac) / scapy.IP(src=src, dst=dst) / payload

    counts = {}

    if args.only_exfil:
        counts["mode"] = "exfil_only"
    else:
        ftp_first = MARKER + b"\r\nUSER wt_test\r\nPA"
        ftp = [
            frame(
                "127.250.0.10", "127.250.0.20",
                scapy.TCP(sport=50000, dport=21, flags="PA", seq=1) / ftp_first,
            ),
            frame(
                "127.250.0.10", "127.250.0.20",
                scapy.TCP(sport=50000, dport=21, flags="PA", seq=1 + len(ftp_first))
                / b"SS WT_FAKE_TEST_ONLY\r\n",
            ),
        ]
        scapy.sendp(ftp, iface=args.interface, verbose=False)
        counts["fragmented_ftp"] = len(ftp)

        tls = [
            frame(
                "127.250.0.10", "127.250.0.20",
                scapy.TCP(sport=50100, dport=443, flags="S", seq=1),
            ),
            frame(
                "127.250.0.10", "127.250.0.20",
                scapy.TCP(sport=50100, dport=443, flags="PA", seq=2) / (MARKER + b"not-tls"),
            ),
        ]
        scapy.sendp(tls, iface=args.interface, verbose=False)
        counts["tls_mismatch"] = len(tls)

        vertical = [
            frame(
                "127.250.0.10", "127.250.0.20",
                scapy.TCP(sport=51000 + index, dport=20000 + index, flags="S", seq=index),
            )
            for index in range(20)
        ]
        horizontal = [
            frame(
                "127.250.0.11", f"127.250.0.{30 + index}",
                scapy.TCP(sport=52000 + index, dport=445, flags="S", seq=index),
            )
            for index in range(20)
        ]
        scapy.sendp(vertical + horizontal, iface=args.interface, inter=0.01, verbose=False)
        counts["vertical_scan"] = len(vertical)
        counts["horizontal_scan"] = len(horizontal)

        dns = [
            frame(
                "127.250.0.12", "127.250.0.53",
                scapy.UDP(sport=53000 + index, dport=53)
                / scapy.DNS(rd=1, qd=scapy.DNSQR(
                    qname=f"{deterministic_bytes(24, bytes([index])).hex()}.acceptance.invalid",
                    qtype="TXT",
                )),
            )
            for index in range(20)
        ]
        scapy.sendp(dns, iface=args.interface, inter=0.02, verbose=False)
        counts["dns_tunnel"] = len(dns)

        icmp = [
            frame(
                "127.250.0.13", "127.250.0.20",
                scapy.ICMP(type=8, id=31337, seq=index)
                / (MARKER + deterministic_bytes(700, f"icmp-{index}".encode())),
            )
            for index in range(100)
        ]
        scapy.sendp(icmp, iface=args.interface, inter=0.02, verbose=False)
        counts["icmp_tunnel"] = len(icmp)

        syn_template = frame(
            "127.250.0.14", "127.250.0.20",
            scapy.TCP(sport=54000, dport=8443, flags="S", seq=1),
        )
        for _ in range(3):
            scapy.sendp([syn_template] * 3500, iface=args.interface, verbose=False)
            time.sleep(1.0)
        counts["syn_flood"] = 10_500

        beacon = frame(
            "127.250.0.15", "127.250.0.20",
            scapy.UDP(sport=55000, dport=4444) / (MARKER + b"beacon"),
        )
        for _ in range(25):
            scapy.sendp(beacon, iface=args.interface, verbose=False)
            time.sleep(6.0)
        counts["beacon"] = 25

    if not args.skip_large_transfer:
        exfil = frame(
            "127.250.0.16", str(exfil_destination),
            scapy.UDP(sport=56000, dport=9443)
            / (MARKER + deterministic_bytes(1380, b"exfil")),
        )
        target = 105 * 1024 * 1024
        sent = 0
        frame_bytes = len(bytes(exfil))
        while sent < target:
            batch = min(1000, (target - sent + frame_bytes - 1) // frame_bytes)
            scapy.sendp([exfil] * batch, iface=args.interface, inter=args.exfil_inter, verbose=False)
            sent += batch * frame_bytes
        counts["large_transfer_frames"] = (sent + frame_bytes - 1) // frame_bytes
        counts["large_transfer_bytes"] = sent

    print(json.dumps({
        "interface": args.interface,
        "self_mac": mac,
        "synthetic_network": str(SYNTHETIC_NETWORK),
        "exfil_semantic_destination": str(exfil_destination),
        "ethernet_destination": mac,
        "marker": MARKER.decode().rstrip("|"),
        "counts": counts,
    }, sort_keys=True))


if __name__ == "__main__":
    main()

"""Generate deterministic, hashed PCAPs for WatchTower release acceptance.

The captures are offline-only and use synthetic loopback identities. Generation
streams directly to disk so the same code can create 25 MiB and 1 GiB fixtures
without retaining packets in memory.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Iterable

import scapy.all as scapy


GENERATOR_VERSION = "watchtower-acceptance-v1"
SELF_MAC = "02:57:54:00:00:01"
EXPECTED_FINDINGS = (
    "credential.cleartext.ftp",
    "auth.failure_burst",
    "icmp.tunnel.suspected",
    "tls.protocol_mismatch",
    "recon.port_scan",
    "recon.host_scan",
    "recon.syn_flood",
    "lateral.admin_fanout",
    "dns.tunnel.suspected",
    "behavior.beacon.suspected",
)


def _bytes(size: int, seed: bytes) -> bytes:
    value = bytearray()
    counter = 0
    while len(value) < size:
        value.extend(sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(value[:size])


def _frame(src: str, dst: str, transport, timestamp: float):
    packet = scapy.Ether(src=SELF_MAC, dst=SELF_MAC) / scapy.IP(src=src, dst=dst) / transport
    packet.time = timestamp
    return packet


def _detection_packets() -> Iterable[object]:
    now = 1_700_000_000.0

    ftp_first = b"USER watchtower_test\r\nPA"
    yield _frame("127.250.0.10", "127.250.0.20", scapy.TCP(sport=50000, dport=21, flags="PA", seq=1) / ftp_first, now)
    now += 0.01
    yield _frame("127.250.0.10", "127.250.0.20", scapy.TCP(sport=50000, dport=21, flags="PA", seq=1 + len(ftp_first)) / b"SS REDACT_ME\r\n", now)
    now += 0.01

    yield _frame("127.250.0.10", "127.250.0.20", scapy.TCP(sport=50100, dport=443, flags="S", seq=1), now)
    now += 0.01
    yield _frame("127.250.0.10", "127.250.0.20", scapy.TCP(sport=50100, dport=443, flags="PA", seq=2) / b"GET /not-tls HTTP/1.1\r\n\r\n", now)
    now += 0.01

    for index in range(20):
        yield _frame(
            "127.250.0.30", "127.250.0.31",
            scapy.TCP(sport=51000 + index, dport=20000 + index, flags="S", seq=index + 1),
            now,
        )
        now += 0.01
    for index in range(20):
        yield _frame(
            "127.250.0.32", f"127.250.0.{40 + index}",
            scapy.TCP(sport=52000 + index, dport=445, flags="S", seq=index + 1),
            now,
        )
        now += 0.01

    for index in range(5):
        peer = f"127.250.0.{70 + index}"
        yield _frame(
            "127.250.0.33", peer,
            scapy.TCP(sport=53000 + index, dport=445, flags="S", seq=1), now,
        )
        now += 0.01
        yield _frame(
            peer, "127.250.0.33",
            scapy.TCP(sport=445, dport=53000 + index, flags="PA", seq=1)
            / b"authentication failed",
            now,
        )
        now += 0.01

    for index in range(20):
        label = _bytes(24, f"dns-{index}".encode()).hex()
        dns = scapy.UDP(sport=54000 + index, dport=53) / scapy.DNS(
            rd=1,
            qd=scapy.DNSQR(qname=f"{label}.acceptance.invalid", qtype="TXT"),
        )
        yield _frame("127.250.0.34", "127.250.0.53", dns, now)
        now += 0.02

    for index in range(100):
        message = scapy.ICMP(type=8, id=31337, seq=index) / _bytes(700, f"icmp-{index}".encode())
        yield _frame("127.250.0.35", "127.250.0.36", message, now)
        now += 0.02

    for second in range(3):
        second_start = now + second
        for index in range(3500):
            yield _frame(
                "127.250.0.37", "127.250.0.38",
                scapy.TCP(sport=55000 + index % 1000, dport=8443, flags="S", seq=index + 1),
                second_start + index / 3500.0,
            )
    now += 3.0

    for index in range(25):
        yield _frame(
            "127.250.0.39", "127.250.0.40",
            scapy.UDP(sport=56000, dport=4444) / b"WT-BEACON",
            now + index * 6.0,
        )


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_acceptance_pcap(
    output: Path | str,
    target_bytes: int,
    profile: str = "detection",
) -> dict:
    output = Path(output).resolve()
    if profile != "detection":
        raise ValueError("acceptance profile must be detection")
    if target_bytes < 1024 * 1024:
        raise ValueError("acceptance PCAP must be at least 1 MiB")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    writer = scapy.PcapWriter(str(temporary), linktype=1, sync=False)
    packet_count = 0
    written_bytes = 24
    first_timestamp = None
    last_timestamp = None

    def write(packet) -> None:
        nonlocal packet_count, written_bytes, first_timestamp, last_timestamp
        timestamp = float(packet.time)
        writer.write(packet)
        packet_count += 1
        written_bytes += 16 + len(bytes(packet))
        first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
        last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)

    try:
        for packet in _detection_packets():
            write(packet)
        filler_index = 0
        filler_time = float(last_timestamp or 1_700_000_000.0) + 1.0
        while written_bytes < target_bytes:
            filler = scapy.UDP(sport=60000 + filler_index % 1000, dport=123) / _bytes(96, b"benign-ntp")
            write(_frame("127.250.0.90", "127.250.0.91", filler, filler_time + filler_index * 0.001))
            filler_index += 1
    finally:
        writer.close()
    temporary.replace(output)

    manifest = {
        "schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "profile": profile,
        "pcap": output.name,
        "sha256": _file_sha256(output),
        "size_bytes": output.stat().st_size,
        "packet_count": packet_count,
        "capture_started_at": first_timestamp,
        "capture_ended_at": last_timestamp,
        "expected_finding_types": list(EXPECTED_FINDINGS),
        "safety": "offline synthetic loopback identities; no packets transmitted",
    }
    manifest_path = output.with_suffix(".manifest.json")
    pending_manifest = manifest_path.with_suffix(".json.tmp")
    pending_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    pending_manifest.replace(manifest_path)
    return manifest


def _parse_size(value: str) -> int:
    text = value.strip().lower()
    units = {"mib": 1024 ** 2, "mb": 1024 ** 2, "gib": 1024 ** 3, "gb": 1024 ** 3}
    for suffix, multiplier in units.items():
        if text.endswith(suffix):
            return int(float(text[:-len(suffix)]) * multiplier)
    return int(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--size", default="25MiB")
    parser.add_argument("--profile", default="detection", choices=["detection"])
    arguments = parser.parse_args()
    manifest = generate_acceptance_pcap(arguments.output, _parse_size(arguments.size), arguments.profile)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


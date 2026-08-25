"""Generate and replay one million packets through the production Rust sensor."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import threading
import time

import psutil
import scapy.all as scapy

from core.packet_engine.rust_capture import sensor_binary


def generate(path: Path, packet_count: int) -> int:
    frame = bytes(
        scapy.Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / scapy.IP(src="10.10.0.2", dst="10.10.0.3")
        / scapy.TCP(sport=50000, dport=443, flags="S", seq=1)
    )
    timestamp = struct.pack("<IIII", 1, 0, len(frame), len(frame))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb", buffering=8 * 1024 * 1024) as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        record = timestamp + frame
        chunk = record * 10_000
        complete_chunks, remainder = divmod(packet_count, 10_000)
        for _ in range(complete_chunks):
            output.write(chunk)
        output.write(record * remainder)
    return path.stat().st_size


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=1_000_000)
    parser.add_argument("--path", default="scratch/rust-million-packet.pcap")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    path = Path(args.path)
    pcap_bytes = generate(path, args.packets)
    binary = sensor_binary()
    if not binary.is_file():
        raise SystemExit(f"Rust sensor is not built: {binary}")

    process = subprocess.Popen(
        [str(binary), "benchmark", "--pcap", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    observed = psutil.Process(process.pid)
    peak_rss = observed.memory_info().rss
    running = True

    def sample() -> None:
        nonlocal peak_rss
        while running:
            try:
                peak_rss = max(peak_rss, observed.memory_info().rss)
            except psutil.NoSuchProcess:
                return
            time.sleep(0.01)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    started = time.perf_counter()
    _stdout, stderr = process.communicate()
    elapsed = time.perf_counter() - started
    running = False
    sampler.join(timeout=1)
    result = {
        "packets": args.packets,
        "pcap_bytes": pcap_bytes,
        "seconds": round(elapsed, 3),
        "packets_per_second": round(args.packets / elapsed, 1),
        "peak_rss_mib": round(peak_rss / 1024 ** 2, 2),
        "exit_code": process.returncode,
        "stderr": stderr.decode("utf-8", errors="replace").strip(),
    }
    print(json.dumps(result, sort_keys=True))
    if not args.keep:
        path.unlink(missing_ok=True)
    if process.returncode:
        raise SystemExit(process.returncode)


if __name__ == "__main__":
    main()

"""Generate a deterministic large PCAP and benchmark streaming analysis RSS."""

import argparse
import json
from pathlib import Path
import struct
import threading
import time

import psutil
import scapy.all as scapy

from core.forensics.engine import ForensicsEngine


def generate(path: Path, size_gib: float):
    target = int(size_gib * 1024 ** 3)
    frame = bytes(
        scapy.Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
        scapy.IP(src="10.10.0.2", dst="10.10.0.3") /
        scapy.ICMP(type=8, id=7, seq=1) /
        scapy.Raw(b"x" * 65493)
    )
    record_size = 16 + len(frame)
    records = max(1, (target - 24 + record_size - 1) // record_size)
    with path.open("wb", buffering=8 * 1024 * 1024) as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index in range(records):
            output.write(struct.pack("<IIII", index, 0, len(frame), len(frame)))
            output.write(frame)
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-gib", type=float, default=1.0)
    parser.add_argument("--path", default="scratch/large-streaming-benchmark.pcap")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    path = Path(args.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    records = generate(path, args.size_gib)

    process = psutil.Process()
    peak_rss = process.memory_info().rss
    running = True
    def sample():
        nonlocal peak_rss
        while running:
            peak_rss = max(peak_rss, process.memory_info().rss)
            time.sleep(0.05)
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    started = time.perf_counter()
    engine = ForensicsEngine(data_dir=path.parent / "benchmark-data", silent=True)
    report = engine.analyze_pcap(str(path), mode="streaming", source_name=f"benchmark:{path.name}")
    elapsed = time.perf_counter() - started
    running = False
    sampler.join(timeout=1)
    print(json.dumps({
        "pcap_bytes": path.stat().st_size, "packets": records, "seconds": round(elapsed, 3),
        "packets_per_second": round(records / elapsed, 1), "peak_rss_bytes": peak_rss,
        "peak_rss_gib": round(peak_rss / 1024 ** 3, 3), "status": report.status,
        "flows": report.summary["total_flows"], "truncated_stream_bytes": report.summary["stream_truncated_bytes"],
    }, sort_keys=True))
    if not args.keep:
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

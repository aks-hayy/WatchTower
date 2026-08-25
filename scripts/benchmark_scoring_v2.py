"""Repeatable microbenchmark for Behavioral Scoring V2."""

import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.detection.contracts import DetectionFindingV2
from core.detection.scoring import PriorityScorer
from core.storage.database import WatchtowerDB


def make_finding(index, observed_at):
    return DetectionFindingV2(
        finding_type="behavior.beacon.suspected",
        detector_id="watchtower.behavior.beacon", detector_version="2.0.0",
        category="ANOMALY", impact="MEDIUM", confidence=0.8,
        evidence_quality=1.0, calibration_state="CALIBRATED",
        signal_family="behavior", correlation_group=f"group-{index % 10}",
        subject="10.0.0.8", target=f"203.0.113.{index + 1}",
        observed_at=observed_at, explanation="benchmark finding",
        evidence={"dst_ip": f"203.0.113.{index + 1}"}, source="pcap:benchmark",
    )


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * fraction))]


def main():
    now = time.time()
    findings = [make_finding(index, now) for index in range(50)]
    scorer = PriorityScorer()
    tracemalloc.start()
    started = time.perf_counter()
    for _ in range(10_000):
        scorer.score(findings, as_of=now)
    scorer_seconds = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    with tempfile.TemporaryDirectory(prefix="watchtower-scoring-") as data_dir:
        db = WatchtowerDB(data_dir=data_dir)
        for finding in findings:
            db.upsert_detection_finding(finding)
        latencies = []
        for _ in range(250):
            started = time.perf_counter()
            db.recompute_risk("10.0.0.8", source="pcap:benchmark", as_of=now, persist=False)
            latencies.append((time.perf_counter() - started) * 1000)
        db.close()

    print(json.dumps({
        "assessment_count": 10_000,
        "findings_per_assessment": len(findings),
        "assessments_per_second": round(10_000 / scorer_seconds, 2),
        "scorer_peak_memory_mib": round(peak / 1024 / 1024, 3),
        "entity_recompute_p50_ms": round(statistics.median(latencies), 3),
        "entity_recompute_p95_ms": round(percentile(latencies, 0.95), 3),
        "entity_recompute_p99_ms": round(percentile(latencies, 0.99), 3),
        "recompute_gate_ms": 50.0,
        "recompute_gate_pass": percentile(latencies, 0.95) < 50.0,
    }, indent=2))


if __name__ == "__main__":
    main()

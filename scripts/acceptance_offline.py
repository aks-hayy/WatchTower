#!/usr/bin/env python3
"""Run and verify the production offline Rust CLI against a synthetic fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SAFETY = "offline synthetic loopback identities; no packets transmitted"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_fixture(path: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    manifest_path = path.with_suffix(".manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, ["synthetic fixture manifest is missing or invalid"]
    if manifest.get("schema_version") != 1:
        errors.append("unsupported fixture manifest schema")
    if manifest.get("profile") != "detection":
        errors.append("fixture manifest profile is not detection")
    if manifest.get("safety") != EXPECTED_SAFETY:
        errors.append("fixture safety declaration is missing or unexpected")
    if manifest.get("pcap") != path.name:
        errors.append("manifest PCAP name does not match the supplied fixture")
    if manifest.get("size_bytes") != path.stat().st_size:
        errors.append("fixture size does not match its manifest")
    if manifest.get("sha256") != _sha256(path):
        errors.append("fixture SHA-256 does not match its manifest")
    expected = manifest.get("expected_finding_types")
    if not isinstance(expected, list) or not expected or not all(isinstance(item, str) for item in expected):
        errors.append("manifest has no valid expected finding types")
    return manifest, errors


def _select_new_report(
    reports: list[dict[str, Any]], source: str, previous_ids: set[int]
) -> dict[str, Any] | None:
    candidates = [
        report
        for report in reports
        if report.get("source") == source
        and report.get("id") is not None
        and int(report["id"]) not in previous_ids
    ]
    return max(candidates, key=lambda report: int(report["id"])) if candidates else None


def _run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    path = args.pcap.expanduser().resolve()
    outcome: dict[str, Any] = {
        "schema_version": 1,
        "status": "failed",
        "backend": "rust",
        "source": f"pcap:{path.name}",
        "fixture_sha256": None,
        "report_id": None,
        "bytes_processed": 0,
        "report_status": None,
        "flow_count": 0,
        "entity_count": 0,
        "alert_count": 0,
        "expected_finding_types": [],
        "present_finding_types": [],
        "failures": [],
    }
    errors = outcome["failures"]
    if not path.is_file():
        errors.append("fixture PCAP does not exist")
        return outcome, 1

    manifest, manifest_errors = _verify_fixture(path)
    errors.extend(manifest_errors)
    outcome["fixture_sha256"] = manifest.get("sha256")
    outcome["expected_finding_types"] = sorted(set(manifest.get("expected_finding_types") or []))
    if errors:
        return outcome, 1

    from core.storage.database import WatchtowerDB

    db = WatchtowerDB()
    try:
        previous_ids = {
            int(report["id"])
            for report in db.get_reports()
            if report.get("source") == outcome["source"] and report.get("id") is not None
        }
    finally:
        db.close()

    command = [
        sys.executable,
        "-m",
        "core.packet_engine.main",
        "analyze",
        str(path),
        "--mode",
        "auto",
        "--backend",
        "rust",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env=os.environ.copy(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=args.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        errors.append("production CLI analysis exceeded its timeout")
        return outcome, 1
    if completed.returncode != 0:
        errors.append(f"production CLI analysis exited with status {completed.returncode}")

    # The CLI can report an analysis exception without returning a failing exit
    # code, so persisted, scope-matched report data is the acceptance evidence.
    db = WatchtowerDB()
    try:
        report = _select_new_report(db.get_reports(), outcome["source"], previous_ids)
        if report is None:
            errors.append("CLI did not create a new forensic report for the fixture")
        else:
            summary = report.get("summary") or {}
            outcome["report_id"] = int(report["id"])
            outcome["report_status"] = report.get("status")
            outcome["bytes_processed"] = int(report.get("bytes_processed") or 0)
            outcome["flow_count"] = int(report.get("total_flows") or summary.get("total_flows") or 0)
            outcome["entity_count"] = int(report.get("total_entities") or summary.get("total_entities") or 0)
            outcome["alert_count"] = int(report.get("total_alerts") or summary.get("total_alerts") or 0)
            aggregate = summary.get("rust_aggregate") or {}
            if report.get("status") != "COMPLETE":
                errors.append("persisted forensic report is not COMPLETE")
            if report.get("backend") != "rust":
                errors.append("persisted forensic report did not use the Rust backend")
            if outcome["bytes_processed"] != path.stat().st_size:
                errors.append("persisted processed-byte count does not match the fixture")
            if aggregate.get("terminal_status") != "complete":
                errors.append("Rust aggregate did not report complete terminal status")
            if int(aggregate.get("packet_index_rows") or 0) <= 0:
                errors.append("Rust aggregate has no persisted packet-index rows")
            if outcome["flow_count"] <= 0 or outcome["entity_count"] <= 0 or outcome["alert_count"] <= 0:
                errors.append("persisted forensic report has no flows, entities, or alerts")

        findings = db.get_detection_findings(source=outcome["source"], limit=100000)
        present = {str(item.get("finding_type")) for item in findings if item.get("finding_type")}
        outcome["present_finding_types"] = sorted(present)
        missing = sorted(set(outcome["expected_finding_types"]) - present)
        if missing:
            errors.append("persisted findings are missing expected types: " + ", ".join(missing))
    finally:
        db.close()

    if not errors:
        outcome["status"] = "passed"
        return outcome, 0
    return outcome, 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path, help="Synthetic acceptance PCAP with generator manifest")
    parser.add_argument("--timeout", type=int, default=1680, help="CLI timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    outcome, status = _run(args)
    print(json.dumps(outcome, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())

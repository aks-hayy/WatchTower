"""Run an isolated, offline end-to-end acceptance check for bundled Sigma rules."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RULE_ID = "c92ab6e7-9d55-4f33-80f1-4ce91010f998"


def run_acceptance() -> dict[str, object]:
    # This child process receives WATCHTOWER_HOME from acceptance_full.ps1;
    # scoring dual mode keeps the legacy alert projection observable here.
    os.environ["WATCHTOWER_SCORING_MODE"] = "dual"

    from core.forensics.sigma_engine import SigmaEngine
    from core.storage.database import WatchtowerDB

    run_id = uuid.uuid4().hex
    source = f"pcap:acceptance-sigma-{run_id}"
    session_id = f"acceptance-sigma-session-{run_id}"
    other_session_id = f"acceptance-sigma-decoy-{run_id}"
    db = WatchtowerDB()
    engine = None
    try:
        db.upsert_flow(
            src_ip="192.0.2.10", dst_ip="198.51.100.21", src_port=49152,
            dst_port=21, protocol="TCP", start_time=1_800_000_000.0,
            last_seen=1_800_000_002.0, packet_count=3, byte_count=192,
            source=source, capture_session_id=session_id,
            capture_interface="acceptance-synthetic", capture_type="network",
        )
        # A matching FTP flow outside the requested capture must be excluded.
        db.upsert_flow(
            src_ip="192.0.2.11", dst_ip="198.51.100.22", src_port=49153,
            dst_port=21, protocol="TCP", start_time=1_800_000_010.0,
            last_seen=1_800_000_012.0, packet_count=3, byte_count=192,
            source=source, capture_session_id=other_session_id,
            capture_interface="acceptance-decoy", capture_type="network",
        )
        # A nonmatching flow in scope guards against overbroad match counts.
        db.upsert_flow(
            src_ip="192.0.2.12", dst_ip="198.51.100.23", src_port=49154,
            dst_port=443, protocol="TCP", start_time=1_800_000_020.0,
            last_seen=1_800_000_022.0, packet_count=3, byte_count=192,
            source=source, capture_session_id=session_id,
            capture_interface="acceptance-synthetic", capture_type="network",
        )
        engine = SigmaEngine(
            plugins_dir=ROOT / "core" / "forensics" / "plugins" / "sigma",
            managed_dir=Path(os.environ["WATCHTOWER_HOME"]) / "sigma" / "active",
            custom_dir=Path(os.environ["WATCHTOWER_HOME"]) / "sigma" / "custom",
            db=db,
        )
        if any(item.get("id") == RULE_ID for item in engine.rejected):
            raise RuntimeError("The bundled acceptance Sigma rule was rejected during loading.")
        if not any(item.get("id") == RULE_ID for item in engine.rules):
            raise RuntimeError("The bundled acceptance Sigma rule did not load.")

        matches = engine.run_hunt(
            source=source, capture_session_id=session_id,
            specific_rule=RULE_ID, persist=True,
        )
        alerts = db.get_alerts(source=source, capture_session_id=session_id, limit=100)
        observed_rule_ids = {
            str(((item.get("evidence") or {}) if isinstance(item, dict) else {}).get("rule_id"))
            for item in alerts
        }
        result = {
            "status": "passed" if len(matches) == 1 and len(alerts) == 1 and observed_rule_ids == {RULE_ID} else "failed",
            "engine": "WatchTower SigmaEngine",
            "rule_id": RULE_ID,
            "match_count": len(matches),
            "persisted_alert_count": len(alerts),
            "scope": {"source": source, "capture_session_id": session_id},
            "decoy_session_excluded": other_session_id != session_id,
        }
        if result["status"] != "passed":
            raise RuntimeError(f"Unexpected Sigma acceptance result: {json.dumps(result, sort_keys=True)}")
        return result
    finally:
        db.close()


if __name__ == "__main__":
    try:
        print(json.dumps(run_acceptance(), sort_keys=True))
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)

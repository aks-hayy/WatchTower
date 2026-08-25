"""Reproducible investigation case export with integrity manifest."""

from dataclasses import asdict, is_dataclass
from hashlib import sha256
from pathlib import Path
from typing import Optional
import csv
import json
import re
import time


class CaseExporter:
    def __init__(self, output_root: str):
        self.output_root = Path(output_root)

    def export(self, investigation, case_name: Optional[str] = None) -> Path:
        data = asdict(investigation) if is_dataclass(investigation) else dict(investigation)
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", data.get("target", "unknown"))
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", case_name or f"{safe_target}_{int(time.time())}")
        case_dir = self.output_root / safe_name
        case_dir.mkdir(parents=True, exist_ok=False)

        json_path = case_dir / "investigation.json"
        json_path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")

        timeline_path = case_dir / "timeline.csv"
        self._write_csv(timeline_path, data.get("timeline") or [], ["timestamp", "type", "ref", "summary"])

        evidence_path = case_dir / "evidence.csv"
        evidence_rows = [
            {
                "timestamp": item.get("timestamp"),
                "type": item.get("evidence_type"),
                "ref": item.get("evidence_ref"),
                "confidence": item.get("confidence"),
                "summary": item.get("summary"),
            }
            for item in data.get("evidence") or []
        ]
        self._write_csv(evidence_path, evidence_rows, ["timestamp", "type", "ref", "confidence", "summary"])

        exported_files = [json_path, timeline_path, evidence_path]
        manifest = {
            "format": "watchtower-case-v1",
            "target": data.get("target"),
            "source": data.get("source"),
            "generated_at": data.get("generated_at"),
            "exported_at": time.time(),
            "files": {path.name: self._hash(path) for path in exported_files},
        }
        (case_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        return case_dir

    @staticmethod
    def _write_csv(path: Path, rows, fieldnames):
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def _hash(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


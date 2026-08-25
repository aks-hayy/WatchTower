"""Operator workflows for scoring V2 validation, recomputation, and migration."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
from typing import Dict, Optional

from core.backend_policy import backend_policy
from core.detection.scoring import ScoringConfig
class ScoringOperations:
    def __init__(self, db):
        self.db = db

    def _config(self) -> ScoringConfig:
        override = Path(self.db.data_dir) / "config" / "scoring.yaml"
        return ScoringConfig(override_path=str(override) if override.exists() else None)

    def status(self) -> Dict:
        from core.calibration.service import CalibrationService

        config = self._config()
        storage = self.db.scoring_storage_status(config.model_version)
        calibration = CalibrationService(data_dir=self.db.data_dir).status()
        levels = {}
        for item in calibration["targets"]:
            level = item["calibration_level"]
            levels[level] = levels.get(level, 0) + 1
        return {
            "mode": os.environ.get("WATCHTOWER_SCORING_MODE", "dual").lower(),
            "model_version": config.model_version,
            "config_hash": config.config_hash,
            **storage,
            "uncalibrated_finding_cap": config.uncalibrated_finding_cap,
            "uncalibrated_total_cap": config.uncalibrated_total_cap,
            "corpus_validated_finding_cap": config.corpus_validated_finding_cap,
            "corpus_validated_total_cap": config.corpus_validated_total_cap,
            "calibration_levels": levels,
        }

    def validate(self) -> Dict:
        from core.calibration.service import CalibrationService
        from core.forensics.plugin_loader import PluginLoader

        config = self._config()
        errors = list(config.validate())
        mode = os.environ.get("WATCHTOWER_SCORING_MODE", "dual").lower()
        if mode not in {"legacy", "dual", "v2"}:
            errors.append("WATCHTOWER_SCORING_MODE must be legacy, dual, or v2")
        loader = PluginLoader()
        plugins = loader.list_plugins()
        invalid = []
        uncalibrated = []
        uncalibrated_findings = []
        for name, item in plugins.items():
            if item.get("type") != "detector":
                continue
            if not item.get("valid") or item.get("errors"):
                invalid.append(name)
            if not item.get("calibrated"):
                uncalibrated.append(name)
            for finding in item.get("calibration") or []:
                if finding.get("calibration_level") != "FIELD_CALIBRATED":
                    uncalibrated_findings.append(f"{item.get('detector_id')}/{finding.get('finding_type')}")
        attestation_validation = CalibrationService(data_dir=self.db.data_dir).verify()
        errors.extend(attestation_validation["errors"])
        with sqlite3.connect(str(self.db.db_path)) as connection:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            errors.append(f"database quick_check: {quick_check}")
        return {
            "valid": not errors and not invalid,
            "errors": errors,
            "invalid_detectors": invalid,
            "uncalibrated_detectors": uncalibrated,
            "uncalibrated_findings": sorted(uncalibrated_findings),
            "attestations_valid": attestation_validation["valid"],
            "config_hash": config.config_hash,
            "database_quick_check": quick_check,
        }

    def explain(self, subject: str, source: str = None, interface: str = None,
                session_id: str = None, as_of: float = None, persist: bool = False,
                sensor_node_id: str = None) -> Dict:
        entity = self.db.get_entity(subject) or {}
        assessment = self.db.recompute_risk(
            subject, source=source, interface=interface, capture_session_id=session_id,
            as_of=as_of, asset_role=entity.get("asset_role"), persist=persist,
            sensor_node_id=sensor_node_id,
        )
        baselines = self.db.get_feature_baselines(subject=subject, source=source, interface=interface)
        assessment["baseline_maturity"] = {
            "mature": bool(baselines) and all(item["maturity"]["mature"] for item in baselines),
            "features": len(baselines),
            "minimum_sample_count": min((item["sample_count"] for item in baselines), default=0),
            "last_update": max((float(item.get("last_sample_at") or 0) for item in baselines), default=0.0),
        }
        return assessment

    def recompute(self, source: str = None, interface: str = None, session_id: str = None,
                  as_of: float = None, dry_run: bool = False, sensor_node_id: str = None) -> Dict:
        findings = self.db.get_detection_findings(
            source=source, interface=interface, capture_session_id=session_id,
            include_suppressed=True, limit=100000, sensor_node_id=sensor_node_id,
        )
        subjects = sorted({item["subject"] for item in findings})
        results = [
            self.explain(subject, source, interface, session_id, as_of, persist=not dry_run, sensor_node_id=sensor_node_id)
            for subject in subjects
        ]
        return {
            "dry_run": dry_run, "subjects": len(subjects), "assessments": results,
            "max_priority_score": max((item["priority_score"] for item in results), default=0.0),
        }

    def backup_and_purge(self) -> Dict:
        """Create and verify a full backup before purging legacy alerts/scores."""
        backup_dir = Path(self.db.data_dir) / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup_path = backup_dir / f"watchtower-pre-scoring-v2-{stamp}.db"
        with sqlite3.connect(str(self.db.db_path)) as source, sqlite3.connect(str(backup_path)) as target:
            source.backup(target)
            quick_check = target.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            backup_path.unlink(missing_ok=True)
            raise RuntimeError(f"backup verification failed: {quick_check}")
        digest = self._file_hash(backup_path)
        manifest = {
            "created_at": time.time(), "database": str(backup_path), "sha256": digest,
            "quick_check": quick_check, "source_database": str(self.db.db_path),
            "model_version": self._config().model_version,
        }
        manifest_path = backup_path.with_suffix(".manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        alert_count = self.db.purge_legacy_alerts_and_scores()
        return {**manifest, "manifest": str(manifest_path), "legacy_alerts_purged": alert_count}

    def rebuild_available_pcaps(self) -> Dict:
        """Reanalyze retained originals under a SHA-256-stable V2 source identity."""
        from core.forensics.engine import ForensicsEngine

        reports = list(self.db.get_reports())
        roots = [Path(self.db.data_dir), Path.cwd()]
        analyzed, missing, seen = [], [], set()
        for report in reports:
            source = str(report.get("source") or "")
            if not source.startswith("pcap:"):
                continue
            filename = source.rsplit(":", 1)[-1]
            candidates = []
            for root in roots:
                direct = root / filename
                if direct.is_file():
                    candidates.append(direct)
                if root == Path(self.db.data_dir):
                    candidates.extend(path for path in root.rglob(filename) if path.is_file())
            path = next((item.resolve() for item in candidates if item.resolve() not in seen), None)
            if path is None:
                missing.append({"source": source, "filename": filename})
                continue
            seen.add(path)
            digest = self._file_hash(path)
            stable_source = f"pcap:{digest}:{path.name}"
            ForensicsEngine(db=self.db, data_dir=str(self.db.data_dir), silent=True).analyze_pcap(
                str(path), source_name=stable_source, mode="auto",
                backend=backend_policy.replay_backend(),
            )
            analyzed.append({"path": str(path), "sha256": digest, "source": stable_source})
        return {"reanalyzed": analyzed, "missing": missing}

    @staticmethod
    def restore_backup(backup_file: str, destination_file: str) -> Dict:
        backup = Path(backup_file).resolve()
        destination = Path(destination_file).resolve()
        if not backup.is_file():
            raise ValueError(f"backup does not exist: {backup}")
        with sqlite3.connect(str(backup)) as source:
            quick_check = source.execute("PRAGMA quick_check").fetchone()[0]
            if quick_check != "ok":
                raise ValueError(f"backup quick_check failed: {quick_check}")
            with sqlite3.connect(str(destination)) as target:
                source.backup(target)
                restored_check = target.execute("PRAGMA quick_check").fetchone()[0]
            if restored_check != "ok":
                raise RuntimeError(f"restored database quick_check failed: {restored_check}")
        return {"restored": str(destination), "backup": str(backup), "sha256": ScoringOperations._file_hash(backup)}

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

"""Evidence basis labels for calibration status surfaces."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from core.calibration.attestations import ATTESTATION_DIR, document_digest


def calibration_trust_basis(
    level: str,
    attestation_digest: str = "",
    attestation_dir: Path = ATTESTATION_DIR,
    stale_reason: str = "",
) -> str:
    """Distinguish bootstrap corpus trust from actual field evidence."""
    normalized = str(level or "UNCALIBRATED").upper()
    if normalized == "CORPUS_VALIDATED":
        return "corpus"
    if normalized != "FIELD_CALIBRATED":
        return "uncalibrated"
    if stale_reason:
        return "unknown"
    if not re.fullmatch(r"[a-f0-9]{64}", str(attestation_digest or "")):
        return "unknown"
    path = Path(attestation_dir) / f"{attestation_digest}.json"
    try:
        attestation = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "unknown"
    if attestation.get("digest") != attestation_digest or document_digest(attestation) != attestation_digest:
        return "unknown"
    if (attestation.get("bootstrap_exception") or {}).get("exception_id"):
        return "bootstrap_corpus"
    field = attestation.get("field_evidence") or {}
    if float(field.get("relevant_host_days") or 0.0) >= 30.0:
        return "field_evidence"
    return "unknown"


def calibration_trust_label(level: str, basis: str) -> str:
    """Return an unambiguous label for people, without changing policy levels."""
    if basis == "bootstrap_corpus":
        return "BOOTSTRAP QUALIFIED"
    if basis == "field_evidence":
        return "FIELD EVIDENCE"
    if basis == "corpus":
        return "CORPUS VALIDATED"
    if basis == "uncalibrated":
        return "UNCALIBRATED"
    if str(level or "").upper() == "DISABLED":
        return "DISABLED"
    return "TRUST UNKNOWN"


def calibration_trust_summary(
    calibration: list[dict], attestation_dir: Path | None = None,
) -> str:
    """Summarize verified evidence labels without replacing policy levels."""
    if not calibration:
        return "NOT APPLICABLE"

    attestation_root = attestation_dir or ATTESTATION_DIR
    labels = {
        calibration_trust_label(
            str(item.get("calibration_level") or "UNCALIBRATED"),
            calibration_trust_basis(
                str(item.get("calibration_level") or "UNCALIBRATED"),
                str(item.get("attestation_digest") or ""),
                attestation_root,
                stale_reason=str(item.get("stale_reason") or ""),
            ),
        )
        for item in calibration
    }
    return next(iter(labels)) if len(labels) == 1 else "MIXED TRUST"


def annotate_calibration_verification(
    result: dict,
    profiles_path: Path | None = None,
    attestation_dir: Path = ATTESTATION_DIR,
) -> dict:
    """Add evidence-basis presentation to policy verification without changing policy."""
    profile_path = profiles_path or Path(__file__).resolve().parents[2] / "core" / "detection" / "scoring_profiles.yaml"
    try:
        data = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    profiles = {
        (str(detector_id), str(finding_type)): profile
        for detector_id, detector in (data.get("detectors") or {}).items()
        for finding_type, profile in (detector.get("findings") or {}).items()
    }
    annotated = dict(result)
    targets = []
    for target in result.get("targets") or []:
        item = dict(target)
        profile = profiles.get((str(item.get("detector_id") or ""), str(item.get("finding_type") or "")), {})
        level = str(item.get("level") or item.get("calibration_level") or "UNCALIBRATED")
        digest = str(profile.get("attestation_digest") or "")
        stale_reason = str(item.get("reason") or "") if not item.get("valid", False) else ""
        basis = calibration_trust_basis(level, digest, attestation_dir, stale_reason)
        item["attestation_digest"] = digest
        item["trust_basis"] = basis
        item["trust_label"] = calibration_trust_label(level, basis)
        targets.append(item)
    annotated["targets"] = targets
    return annotated

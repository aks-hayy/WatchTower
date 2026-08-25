"""Strict, serializable contracts used by the calibration engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import math
import re
from typing import Any, Dict, List, Tuple


CALIBRATION_LEVELS = {"UNCALIBRATED", "CORPUS_VALIDATED", "FIELD_CALIBRATED"}
CASE_LABELS = {"positive", "benign"}
REQUIRED_VARIANTS = {
    "positive", "benign", "malformed", "truncated", "fragmented",
    "retransmitted", "reordered", "directional", "reset", "memory_bound",
}
SENSITIVE_KEYS = re.compile(r"(?i)(payload|password|passwd|secret|token|authorization|credential|raw_bytes)")


@dataclass(frozen=True)
class CalibrationCase:
    case_id: str
    detector_id: str
    finding_type: str
    label: str
    variant: str
    input_kind: str
    recipe: Dict[str, Any]
    modes: Tuple[str, ...] = ("isolation", "integrated")
    backends: Tuple[str, ...] = ("python", "rust")
    unsupported: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: Dict[str, Any], defaults: Dict[str, Any] = None) -> "CalibrationCase":
        merged = {**(defaults or {}), **value}
        return cls(
            case_id=str(merged.get("id") or ""),
            detector_id=str(merged.get("detector_id") or ""),
            finding_type=str(merged.get("finding_type") or ""),
            label=str(merged.get("label") or "").lower(),
            variant=str(merged.get("variant") or ""),
            input_kind=str(merged.get("input_kind") or "packet").lower(),
            recipe=dict(merged.get("recipe") or {}),
            modes=tuple(str(item).lower() for item in (merged.get("modes") or ("isolation", "integrated"))),
            backends=tuple(str(item).lower() for item in (merged.get("backends") or ("python", "rust"))),
            unsupported={str(key).lower(): str(reason) for key, reason in (merged.get("unsupported") or {}).items()},
        )

    def validate(self) -> List[str]:
        errors = []
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", self.case_id):
            errors.append("case id must be a stable lowercase identifier")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", self.detector_id):
            errors.append("detector_id is invalid")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,127}", self.finding_type):
            errors.append("finding_type is invalid")
        if self.label not in CASE_LABELS:
            errors.append("label must be positive or benign")
        if not self.variant:
            errors.append("variant is required")
        if self.input_kind not in {"packet", "stream", "flow", "session"}:
            errors.append("input_kind must be packet, stream, flow, or session")
        if not self.recipe:
            errors.append("recipe is required")
        invalid_modes = set(self.modes) - {"isolation", "integrated"}
        if invalid_modes:
            errors.append("unsupported modes: " + ", ".join(sorted(invalid_modes)))
        invalid_backends = set(self.backends) - {"python", "rust"}
        if invalid_backends:
            errors.append("unsupported backends: " + ", ".join(sorted(invalid_backends)))
        for backend in set(self.unsupported) - {"python", "rust", "integrated"}:
            errors.append(f"unsupported declaration key: {backend}")
        return errors


@dataclass
class CalibrationMetrics:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    high_benign: int = 0
    critical_benign: int = 0
    positive_cases: int = 0
    benign_cases: int = 0
    precision: float = 0.0
    recall: float = 0.0
    false_alert_rate: float = 0.0
    evidence_completeness: float = 0.0
    execution_seconds: float = 0.0
    peak_memory_bytes: int = 0
    deterministic: bool = True
    backend_parity: bool = True
    secrets_redacted: bool = True
    state_within_limit: bool = True
    variants: List[str] = field(default_factory=list)

    def finalize(self, evidence_values: List[float]) -> None:
        self.precision = self.true_positive / max(1, self.true_positive + self.false_positive)
        self.recall = self.true_positive / max(1, self.true_positive + self.false_negative)
        self.false_alert_rate = self.false_positive / max(1, self.benign_cases)
        self.evidence_completeness = sum(evidence_values) / max(1, len(evidence_values))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FieldEvidenceEntry:
    detector_id: str
    detector_version: str
    finding_type: str
    relevant_host_days: float
    complete_sessions: int
    max_sensor_drop_ratio: float
    high_findings: int
    critical_findings: int
    high_false_alerts: int
    critical_false_alerts: int
    unresolved_high_critical: int

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "FieldEvidenceEntry":
        return cls(
            detector_id=str(value.get("detector_id") or ""),
            detector_version=str(value.get("detector_version") or ""),
            finding_type=str(value.get("finding_type") or ""),
            relevant_host_days=float(value.get("relevant_host_days") or 0.0),
            complete_sessions=int(value.get("complete_sessions") or 0),
            max_sensor_drop_ratio=float(value.get("max_sensor_drop_ratio") or 0.0),
            high_findings=int(value.get("high_findings") or 0),
            critical_findings=int(value.get("critical_findings") or 0),
            high_false_alerts=int(value.get("high_false_alerts") or 0),
            critical_false_alerts=int(value.get("critical_false_alerts") or 0),
            unresolved_high_critical=int(value.get("unresolved_high_critical") or 0),
        )

    def validate(self) -> List[str]:
        errors = []
        numeric = asdict(self)
        for key, value in numeric.items():
            if key in {"detector_id", "detector_version", "finding_type"}:
                continue
            if not math.isfinite(float(value)) or float(value) < 0:
                errors.append(f"{key} must be finite and non-negative")
        if self.max_sensor_drop_ratio > 1:
            errors.append("max_sensor_drop_ratio must be 0..1")
        return errors


def contains_sensitive_material(value: Any, key: str = "") -> bool:
    if key == "contains_payloads" and value is False:
        return False
    if SENSITIVE_KEYS.search(key):
        return True
    if isinstance(value, dict):
        return any(contains_sensitive_material(child, str(name)) for name, child in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains_sensitive_material(child, key) for child in value)
    return isinstance(value, (bytes, bytearray))

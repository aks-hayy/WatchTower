"""Deterministic, bounded behavioral priority scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import math
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional

import yaml

from core.detection.contracts import DetectionFindingV2


BASE_IMPACT = {"INFORMATIONAL": 0.0, "LOW": 10.0, "MEDIUM": 30.0, "HIGH": 55.0, "CRITICAL": 80.0}
HALF_LIVES = {"ANOMALY": 86400.0, "THREAT": 259200.0, "EXPOSURE": 604800.0, "POLICY_VIOLATION": 604800.0}
ASSET_MULTIPLIERS = {"SERVER": 1.15, "CRITICAL": 1.25, "CRITICAL_ASSET": 1.25}

_DEFAULT_CONFIG = None
_DEFAULT_CONFIG_STATE = None
_DEFAULT_CONFIG_LOCK = Lock()


@dataclass(frozen=True)
class DetectorProfile:
    detector_id: str
    finding_type: str = "*"
    detector_version: str = ""
    calibration_level: str = "UNCALIBRATED"
    max_contribution: float = 80.0
    attestation_digest: str = ""
    stale_reason: str = ""
    base_impact: Dict[str, float] = field(default_factory=lambda: dict(BASE_IMPACT))
    half_life_seconds: Dict[str, float] = field(default_factory=lambda: dict(HALF_LIVES))

    @property
    def calibrated(self) -> bool:
        """Compatibility projection: only field-calibrated means fully calibrated."""
        return self.calibration_level == "FIELD_CALIBRATED"


@dataclass
class RiskContributor:
    finding_id: Optional[int]
    fingerprint: str
    finding_type: str
    detector_id: str
    correlation_group: str
    effective_contribution: float
    impact: str
    confidence: float
    evidence_quality: float
    occurrence_count: int
    recency: float
    calibrated: bool
    calibration_level: str
    explanation: str


@dataclass
class RiskAssessment:
    priority_score: float
    risk_level: str
    assessment_confidence: float
    model_version: str
    config_hash: str
    as_of: float
    contributors: List[RiskContributor] = field(default_factory=list)
    scope: Dict[str, Optional[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["contributors"] = [asdict(item) for item in self.contributors]
        return result


class ScoringConfig:
    model_version = "behavioral-v2.1"

    def __init__(self, shipped_path: Optional[str] = None, override_path: Optional[str] = None):
        shipped = Path(shipped_path) if shipped_path else Path(__file__).with_name("scoring_profiles.yaml")
        self.shipped_path = shipped
        self.override_path = Path(override_path) if override_path else None
        data = self._read(shipped)
        if override_path:
            data = self._merge(data, self._read(Path(override_path), required=False))
        self.raw = data
        self.uncalibrated_finding_cap = float(data.get("uncalibrated_finding_cap", 5.0))
        self.uncalibrated_total_cap = float(data.get("uncalibrated_total_cap", 10.0))
        self.corpus_validated_finding_cap = float(data.get("corpus_validated_finding_cap", 20.0))
        self.corpus_validated_total_cap = float(data.get("corpus_validated_total_cap", 35.0))
        self.profiles: Dict[tuple, DetectorProfile] = {}
        for detector_id, config in (data.get("detectors") or {}).items():
            default_cap = float(config.get("max_contribution", 80.0))
            version = str(config.get("version") or "")
            for finding_type, finding_config in (config.get("findings") or {}).items():
                level = str(finding_config.get("calibration_level", "UNCALIBRATED")).upper()
                digest = str(finding_config.get("attestation_digest") or "")
                resolved_cap = float(finding_config.get("max_contribution", default_cap))
                resolved_base = {**BASE_IMPACT, **{str(k).upper(): float(v) for k, v in (finding_config.get("base_impact") or config.get("base_impact") or {}).items()}}
                resolved_half_life = {**HALF_LIVES, **{str(k).upper(): float(v) for k, v in (finding_config.get("half_life_seconds") or config.get("half_life_seconds") or {}).items()}}
                stale_reason = ""
                if level != "UNCALIBRATED":
                    try:
                        from core.calibration.attestations import scoring_policy_digest, verify_profile_attestation

                        valid, stale_reason = verify_profile_attestation(
                            digest, detector_id, version, finding_type, level,
                            scoring_policy_digest(resolved_cap, resolved_base, resolved_half_life),
                        )
                        if not valid:
                            level = "UNCALIBRATED"
                    except Exception as exc:
                        level, stale_reason = "UNCALIBRATED", str(exc)
                self.profiles[(detector_id, finding_type, version)] = DetectorProfile(
                    detector_id=detector_id,
                    finding_type=finding_type,
                    detector_version=version,
                    calibration_level=level,
                    max_contribution=resolved_cap,
                    attestation_digest=digest,
                    stale_reason=stale_reason,
                    base_impact=resolved_base,
                    half_life_seconds=resolved_half_life,
                )
        normalized = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        self.config_hash = sha256(normalized).hexdigest()

    @staticmethod
    def _read(path: Path, required: bool = True) -> Dict[str, Any]:
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(value, dict):
                raise ValueError(f"Scoring profile must be a mapping: {path}")
            return value
        except FileNotFoundError:
            if required:
                raise
            return {}

    @classmethod
    def _merge(cls, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(base)
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = cls._merge(result[key], value)
            else:
                result[key] = value
        return result

    def profile_for(self, detector_id: str, finding_type: str = "*", detector_version: str = "") -> DetectorProfile:
        exact = self.profiles.get((detector_id, finding_type, detector_version))
        if exact:
            return exact
        candidates = [
            profile for (candidate_id, candidate_type, _version), profile in self.profiles.items()
            if candidate_id == detector_id and candidate_type == finding_type
        ]
        return candidates[0] if len(candidates) == 1 else DetectorProfile(
            detector_id=detector_id, finding_type=finding_type, detector_version=detector_version,
        )

    def validate(self) -> List[str]:
        errors = []
        if not 0 <= self.uncalibrated_finding_cap <= 5 or not self.uncalibrated_finding_cap <= self.uncalibrated_total_cap <= 10:
            errors.append("uncalibrated caps must satisfy 0 <= finding <= 5 and finding <= total <= 10")
        if not 0 <= self.corpus_validated_finding_cap <= 20 or not self.corpus_validated_finding_cap <= self.corpus_validated_total_cap <= 35:
            errors.append("corpus-validated caps must satisfy 0 <= finding <= 20 and finding <= total <= 35")
        for (detector_id, finding_type, _version), profile in self.profiles.items():
            if not detector_id:
                errors.append("detector profile ID cannot be empty")
            if not finding_type:
                errors.append(f"{detector_id}: finding type cannot be empty")
            if profile.calibration_level not in {"UNCALIBRATED", "CORPUS_VALIDATED", "FIELD_CALIBRATED"}:
                errors.append(f"{detector_id}/{finding_type}: invalid calibration level")
            if not 0 <= profile.max_contribution <= 100:
                errors.append(f"{detector_id}: max_contribution must be 0..100")
            if any(not math.isfinite(value) or value < 0 for value in profile.base_impact.values()):
                errors.append(f"{detector_id}: base impact values must be finite and non-negative")
            if any(not math.isfinite(value) or value <= 0 for value in profile.half_life_seconds.values()):
                errors.append(f"{detector_id}: half-life values must be finite and positive")
        return errors


def _file_state(path: Path) -> tuple:
    try:
        stat = path.stat()
        return (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return (str(path), None, None)


def _config_file_state(config: ScoringConfig) -> tuple:
    state = [_file_state(config.shipped_path)]
    if config.override_path is not None:
        state.append(_file_state(config.override_path))
    attestation_dir = Path(__file__).parents[2] / "calibration" / "attestations"
    digests = sorted({profile.attestation_digest for profile in config.profiles.values() if profile.attestation_digest})
    state.extend(_file_state(attestation_dir / f"{digest}.json") for digest in digests)
    return tuple(state)


def default_scoring_config() -> ScoringConfig:
    """Reuse verified scoring policy until its profile or attestations change."""
    global _DEFAULT_CONFIG, _DEFAULT_CONFIG_STATE
    with _DEFAULT_CONFIG_LOCK:
        if _DEFAULT_CONFIG is not None:
            current_state = _config_file_state(_DEFAULT_CONFIG)
            if current_state == _DEFAULT_CONFIG_STATE:
                return _DEFAULT_CONFIG
        config = ScoringConfig()
        _DEFAULT_CONFIG = config
        _DEFAULT_CONFIG_STATE = _config_file_state(config)
        return config


def clear_default_scoring_config_cache() -> None:
    """Clear the process-local policy cache for tests and explicit reloads."""
    global _DEFAULT_CONFIG, _DEFAULT_CONFIG_STATE
    with _DEFAULT_CONFIG_LOCK:
        _DEFAULT_CONFIG = None
        _DEFAULT_CONFIG_STATE = None


class PriorityScorer:
    def __init__(self, config: Optional[ScoringConfig] = None):
        self.config = config or ScoringConfig()
        errors = self.config.validate()
        if errors:
            raise ValueError("Invalid scoring configuration: " + "; ".join(errors))

    @staticmethod
    def risk_level(score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    def score(
        self,
        findings: Iterable[Any],
        as_of: float,
        asset_role: Optional[str] = None,
        scope: Optional[Dict[str, Optional[str]]] = None,
    ) -> RiskAssessment:
        as_of = float(as_of)
        asset_multiplier = min(1.25, ASSET_MULTIPLIERS.get(str(asset_role or "").upper(), 1.0))
        strongest_by_group: Dict[str, RiskContributor] = {}
        uncalibrated: List[RiskContributor] = []
        corpus_validated: Dict[str, RiskContributor] = {}

        ordered = self._deduplicate(findings)
        for finding in ordered:
            if self._value(finding, "disposition") in {"false_positive", "benign_expected"}:
                continue
            confidence = self._bounded(self._value(finding, "confidence", 0.0))
            if self._value(finding, "disposition") == "true_positive":
                confidence = max(0.95, confidence)
            quality = self._bounded(self._value(finding, "evidence_quality", 0.0))
            impact = str(self._value(finding, "impact", "LOW")).upper()
            category = str(self._value(finding, "category", "ANOMALY")).upper()
            detector_id = str(self._value(finding, "detector_id", "unknown"))
            finding_type = str(self._value(finding, "finding_type", "unknown"))
            detector_version = str(self._value(finding, "detector_version", ""))
            profile = self.config.profile_for(detector_id, finding_type, detector_version)
            calibration_level = profile.calibration_level
            calibrated = calibration_level == "FIELD_CALIBRATED"
            last_seen = float(self._value(finding, "last_seen", self._value(finding, "observed_at", as_of)) or as_of)
            age = max(0.0, as_of - last_seen)
            half_life = profile.half_life_seconds.get(category, HALF_LIVES.get(category, 86400.0))
            recency = 2.0 ** (-age / half_life)
            occurrences = max(1, int(self._value(finding, "occurrence_count", 1) or 1))
            recurrence = min(1.35, 1.0 + 0.10 * math.log2(occurrences))
            base = profile.base_impact.get(impact, BASE_IMPACT.get(impact, 10.0))
            if calibrated:
                cap = profile.max_contribution
            elif calibration_level == "CORPUS_VALIDATED":
                cap = min(profile.max_contribution, self.config.corpus_validated_finding_cap)
            else:
                cap = self.config.uncalibrated_finding_cap
            effective = min(cap, base * confidence * quality * recurrence * recency * asset_multiplier)
            contributor = RiskContributor(
                finding_id=self._value(finding, "id"),
                fingerprint=str(self._value(finding, "fingerprint", "")),
                finding_type=finding_type,
                detector_id=detector_id,
                correlation_group=str(self._value(finding, "correlation_group", "uncalibrated")),
                effective_contribution=round(max(0.0, effective), 4),
                impact=impact,
                confidence=confidence,
                evidence_quality=quality,
                occurrence_count=occurrences,
                recency=round(recency, 6),
                calibrated=calibrated,
                calibration_level=calibration_level,
                explanation=str(self._value(finding, "explanation", "")),
            )
            if calibrated:
                previous = strongest_by_group.get(contributor.correlation_group)
                if previous is None or contributor.effective_contribution > previous.effective_contribution:
                    strongest_by_group[contributor.correlation_group] = contributor
            elif calibration_level == "CORPUS_VALIDATED":
                previous = corpus_validated.get(contributor.correlation_group)
                if previous is None or contributor.effective_contribution > previous.effective_contribution:
                    corpus_validated[contributor.correlation_group] = contributor
            else:
                uncalibrated.append(contributor)

        remaining_corpus = self.config.corpus_validated_total_cap
        for contributor in sorted(corpus_validated.values(), key=lambda item: (-item.effective_contribution, item.fingerprint)):
            if remaining_corpus <= 0:
                break
            contributor.effective_contribution = round(min(remaining_corpus, contributor.effective_contribution), 4)
            remaining_corpus -= contributor.effective_contribution
            strongest_by_group[contributor.correlation_group] = contributor

        strongest_uncalibrated: Dict[str, RiskContributor] = {}
        for contributor in uncalibrated:
            previous = strongest_uncalibrated.get(contributor.correlation_group)
            if previous is None or contributor.effective_contribution > previous.effective_contribution:
                strongest_uncalibrated[contributor.correlation_group] = contributor
        uncalibrated = sorted(
            strongest_uncalibrated.values(),
            key=lambda item: (-item.effective_contribution, item.fingerprint),
        )
        if uncalibrated:
            remaining = self.config.uncalibrated_total_cap
            selected = []
            for contributor in uncalibrated:
                if remaining <= 0:
                    break
                contributor.effective_contribution = round(min(remaining, contributor.effective_contribution), 4)
                remaining -= contributor.effective_contribution
                selected.append(contributor)
            if selected:
                strongest_by_group["uncalibrated"] = RiskContributor(
                    finding_id=selected[0].finding_id,
                    fingerprint=selected[0].fingerprint,
                    finding_type=selected[0].finding_type,
                    detector_id="uncalibrated.aggregate",
                    correlation_group="uncalibrated",
                    effective_contribution=round(sum(item.effective_contribution for item in selected), 4),
                    impact=max((item.impact for item in selected), key=lambda value: BASE_IMPACT.get(value, 0)),
                    confidence=max(item.confidence for item in selected),
                    evidence_quality=max(item.evidence_quality for item in selected),
                    occurrence_count=sum(item.occurrence_count for item in selected),
                    recency=max(item.recency for item in selected),
                    calibrated=False,
                    calibration_level="UNCALIBRATED",
                    explanation=f"{len(selected)} independent uncalibrated finding group(s), capped",
                )

        contributors = sorted(strongest_by_group.values(), key=lambda item: (-item.effective_contribution, item.correlation_group))
        complement = 1.0
        for item in contributors:
            complement *= 1.0 - min(item.effective_contribution, 99.0) / 100.0
        priority = round(min(100.0, max(0.0, 100.0 * (1.0 - complement))), 1)
        total_weight = sum(item.effective_contribution for item in contributors)
        assessment_confidence = 0.0 if not total_weight else sum(
            item.effective_contribution * item.confidence * item.evidence_quality for item in contributors
        ) / total_weight
        return RiskAssessment(
            priority_score=priority,
            risk_level=self.risk_level(priority),
            assessment_confidence=round(min(0.99, max(0.0, assessment_confidence)), 2),
            model_version=self.config.model_version,
            config_hash=self.config.config_hash,
            as_of=as_of,
            contributors=contributors,
            scope=dict(scope or {}),
        )

    @staticmethod
    def _value(item: Any, key: str, default: Any = None) -> Any:
        if isinstance(item, dict):
            return item.get(key, default)
        return getattr(item, key, default)

    @staticmethod
    def _bounded(value: Any) -> float:
        value = float(value or 0.0)
        return min(1.0, max(0.0, value)) if math.isfinite(value) else 0.0

    @classmethod
    def _deduplicate(cls, findings: Iterable[Any]) -> List[Dict[str, Any]]:
        """Deduplicate equivalent evidence across interfaces/sessions before rollup."""
        unique: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            if isinstance(finding, dict):
                item = dict(finding)
            else:
                item = dict(vars(finding))
            fingerprint = str(item.get("fingerprint") or "")
            key = fingerprint or f"{item.get('detector_id')}:{item.get('finding_type')}:{item.get('subject')}"
            previous = unique.get(key)
            if previous is None:
                unique[key] = item
                continue
            previous["occurrence_count"] = max(int(previous.get("occurrence_count") or 1), int(item.get("occurrence_count") or 1))
            previous["confidence"] = max(float(previous.get("confidence") or 0), float(item.get("confidence") or 0))
            previous["evidence_quality"] = max(float(previous.get("evidence_quality") or 0), float(item.get("evidence_quality") or 0))
            if float(item.get("last_seen") or item.get("observed_at") or 0) > float(previous.get("last_seen") or previous.get("observed_at") or 0):
                for field in ("last_seen", "observed_at", "explanation", "evidence", "disposition", "is_suppressed"):
                    if field in item:
                        previous[field] = item[field]
        return sorted(unique.values(), key=lambda item: (str(item.get("fingerprint") or ""), str(item.get("detector_id") or "")))

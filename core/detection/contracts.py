"""Versioned detector contracts and canonical WatchTower findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


FINDING_CATEGORIES = {"THREAT", "ANOMALY", "EXPOSURE", "POLICY_VIOLATION"}
IMPACT_LEVELS = {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
CALIBRATION_STATES = {
    "UNCALIBRATED", "CORPUS_VALIDATED", "FIELD_CALIBRATED",
    "CALIBRATED", "LEGACY_MAPPED",
}
INPUT_KINDS = {"packet", "flow", "stream", "conversation", "session", "metadata"}
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SENSITIVE_EVIDENCE_KEYS = re.compile(
    r"(?i)^(password|passwd|authorization|token|secret|credential_value|raw(?:_bytes)?|"
    r"payload(?:_bytes|_excerpt)?|content(?:_bytes|_excerpt)?)$"
)


LEGACY_TYPE_MAP = {
    "ARP_SPOOFING": "network.arp.binding_conflict",
    "NDP_SPOOFING": "network.ndp.binding_conflict",
    "ROGUE_DHCP": "network.dhcp.untrusted_server",
    "ROGUE_IPV6_RA": "network.ipv6.untrusted_router",
    "PORT_SCAN": "recon.port_scan",
    "HORIZONTAL_SCAN": "recon.host_scan",
    "SERVICE_ENUMERATION": "recon.port_scan",
    "SYN_FLOOD": "recon.syn_flood",
    "AUTHENTICATION_ABUSE": "auth.failure_burst",
    "LATERAL_MOVEMENT": "lateral.admin_fanout",
    "BEACONING": "behavior.beacon.suspected",
    "SUSPICIOUS_DNS": "dns.tunnel.suspected",
    "EXFILTRATION": "exfil.volume_anomaly",
    "POTENTIAL_EXFILTRATION": "exfil.volume_anomaly",
    "ICMP_TUNNELING": "icmp.tunnel.suspected",
    "TLS_PROTOCOL_MISMATCH": "tls.protocol_mismatch",
    "PROTOCOL_MISMATCH": "protocol.nonstandard_service",
    "FILE_TRANSFER": "file.executable_transfer",
    "SUSPICIOUS_FILE": "file.executable_transfer",
    "UNSAFE_OT_COMMAND": "ot.modbus.unauthorized_write",
    "IOT_CLEARTEXT_CREDENTIALS": "credential.cleartext.mqtt",
    "CLEARTEXT_CREDENTIALS": "credential.cleartext.ftp",
    "CLEARTEXT_SECRET": "credential.cleartext.generic",
    "KNOWN_BAD": "intel.ioc_match",
    "SIGMA_MATCH": "rule.sigma.match",
}


@dataclass(frozen=True)
class DetectorManifestV2:
    detector_id: str
    name: str
    version: str = "2.0.0"
    contract_version: int = 2
    input_kinds: Tuple[str, ...] = ("packet",)
    finding_types: Tuple[str, ...] = ()
    required_evidence: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    signal_family: str = "uncalibrated"
    correlation_group: str = "uncalibrated"
    supported_protocols: Tuple[str, ...] = ()
    supported_link_types: Tuple[str, ...] = ("ethernet", "raw-ip")
    supported_capture_sources: Tuple[str, ...] = ("network",)
    state_scope: str = "analysis"
    max_state_entries: int = 4096
    memory_limit_bytes: int = 16 * 1024 * 1024
    reset_behavior: str = "per-analysis"
    finalize_behavior: str = "optional"
    calibration_candidate: bool = True
    calibrated: bool = False  # Deprecated compatibility hint; never authoritative.

    def validate(self) -> List[str]:
        errors = []
        if not self.detector_id or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", self.detector_id):
            errors.append("detector_id must be a stable lowercase identifier")
        if not _SEMVER.match(self.version):
            errors.append("version must be semantic versioning")
        if self.contract_version != 2:
            errors.append("contract_version must be 2")
        invalid_inputs = sorted(set(self.input_kinds) - INPUT_KINDS)
        if invalid_inputs:
            errors.append("unsupported input kinds: " + ", ".join(invalid_inputs))
        if not self.finding_types:
            errors.append("at least one finding_type is required")
        for finding_type in self.finding_types:
            if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,127}", finding_type):
                errors.append(f"invalid finding type: {finding_type}")
        if self.max_state_entries < 0:
            errors.append("max_state_entries cannot be negative")
        if self.memory_limit_bytes < 0:
            errors.append("memory_limit_bytes cannot be negative")
        if self.reset_behavior not in {"per-analysis", "per-source", "stateless"}:
            errors.append("unsupported reset_behavior")
        if self.finalize_behavior not in {"required", "optional", "none"}:
            errors.append("unsupported finalize_behavior")
        return errors


@dataclass
class DetectionFindingV2:
    finding_type: str
    detector_id: str
    detector_version: str
    category: str
    impact: str
    confidence: float
    subject: str
    observed_at: float
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: Tuple[str, ...] = ()
    evidence_quality: float = 1.0
    calibration_state: str = "UNCALIBRATED"
    signal_family: str = "uncalibrated"
    correlation_group: str = "uncalibrated"
    target: Optional[str] = None
    flow_ref: Optional[str] = None
    source: str = "live"
    sensor_node_id: Optional[str] = None
    capture_interface: Optional[str] = None
    capture_session_id: Optional[str] = None
    capture_backend: Optional[str] = None
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    occurrence_count: int = 1
    recommended_action: str = "Review supporting evidence"
    mitre_technique: Optional[str] = None
    fingerprint: Optional[str] = None
    model_version: str = "behavioral-v2.1"
    legacy_type: Optional[str] = None

    def __post_init__(self):
        self.category = str(self.category).upper()
        self.impact = str(self.impact).upper()
        self.calibration_state = str(self.calibration_state).upper()
        self.confidence = float(self.confidence)
        self.evidence_quality = float(self.evidence_quality)
        self.observed_at = float(self.observed_at or 0.0)
        self.first_seen = float(self.first_seen if self.first_seen is not None else self.observed_at)
        self.last_seen = float(self.last_seen if self.last_seen is not None else self.observed_at)
        self.occurrence_count = max(1, int(self.occurrence_count or 1))
        self.evidence = sanitize_evidence(self.evidence)
        self.evidence_refs = tuple(str(ref)[:512] for ref in self.evidence_refs[:64])
        if not self.fingerprint:
            self.fingerprint = self.make_fingerprint()

    def validate(self, manifest: Optional[DetectorManifestV2] = None) -> List[str]:
        errors = []
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,127}", self.finding_type or ""):
            errors.append("finding_type must be a namespaced lowercase identifier")
        if self.category not in FINDING_CATEGORIES:
            errors.append(f"unsupported category: {self.category}")
        if self.impact not in IMPACT_LEVELS:
            errors.append(f"unsupported impact: {self.impact}")
        if self.calibration_state not in CALIBRATION_STATES:
            errors.append(f"unsupported calibration state: {self.calibration_state}")
        if not self.subject:
            errors.append("subject is required")
        for name, value in (("confidence", self.confidence), ("evidence_quality", self.evidence_quality)):
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                errors.append(f"{name} must be finite and between 0 and 1")
        if not math.isfinite(self.observed_at) or self.observed_at < 0:
            errors.append("observed_at must be a non-negative finite timestamp")
        if self.last_seen < self.first_seen:
            errors.append("last_seen cannot precede first_seen")
        if manifest:
            if self.detector_id != manifest.detector_id:
                errors.append("finding detector_id does not match manifest")
            if self.finding_type not in manifest.finding_types:
                errors.append("finding_type is not declared by the detector manifest")
            required = manifest.required_evidence.get(self.finding_type, ())
            missing = [key for key in required if self.evidence.get(key) is None]
            if missing:
                errors.append("missing required evidence: " + ", ".join(missing))
        return errors

    def make_fingerprint(self) -> str:
        identity_keys = (
            "dst_ip", "destination_ip", "dst_port", "domain", "remote_hostname",
            "sha256", "ja3", "ja4", "rule_id", "record_id", "target", "targets",
            "function_code", "unit_id", "protocol",
        )
        identity = {key: self.evidence[key] for key in identity_keys if key in self.evidence}
        payload = {
            "detector_id": self.detector_id,
            "finding_type": self.finding_type,
            "subject": self.subject,
            "target": self.target,
            "identity": identity,
        }
        encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        return sha256(encoded).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def sanitize_evidence(value: Any, key: str = "") -> Any:
    """Remove secrets and replace arbitrary bytes with stable evidence hashes."""
    if _SENSITIVE_EVIDENCE_KEYS.search(str(key)):
        if value in (None, "", b""):
            return value
        encoded = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="replace")
        return {"redacted": True, "sha256": sha256(encoded).hexdigest(), "length": len(encoded)}
    if isinstance(value, dict):
        return {str(child_key): sanitize_evidence(child_value, str(child_key)) for child_key, child_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_evidence(item) for item in value[:256]]
    if isinstance(value, bytes):
        return {"sha256": sha256(value).hexdigest(), "length": len(value)}
    if isinstance(value, str):
        return value[:2048]
    return value


def evidence_quality(required: Iterable[str], evidence: Dict[str, Any]) -> float:
    required = tuple(required)
    if not required:
        return 1.0 if evidence else 0.75
    present = sum(evidence.get(key) is not None for key in required)
    return round(present / len(required), 4)


def legacy_alert_to_finding(
    alert: Any,
    subject: str,
    source: str = "live",
    capture_interface: Optional[str] = None,
    capture_session_id: Optional[str] = None,
    capture_backend: Optional[str] = None,
) -> DetectionFindingV2:
    legacy_type = str(getattr(alert, "type", None) or "UNKNOWN").upper()
    finding_type = LEGACY_TYPE_MAP.get(legacy_type, "legacy." + legacy_type.lower().replace("_", "."))
    severity = str(getattr(alert, "severity", "LOW") or "LOW").upper()
    impact = severity if severity in IMPACT_LEVELS else "LOW"
    evidence = dict(getattr(alert, "evidence", None) or {})
    timestamp = float(getattr(alert, "timestamp", 0.0) or 0.0)
    return DetectionFindingV2(
        finding_type=finding_type,
        detector_id="legacy." + legacy_type.lower(),
        detector_version="1.0.0",
        category="ANOMALY",
        impact=impact,
        confidence=0.5,
        evidence_quality=0.75 if evidence else 0.5,
        calibration_state="LEGACY_MAPPED",
        signal_family="legacy",
        correlation_group="legacy",
        subject=subject,
        target=evidence.get("dst_ip") or evidence.get("destination_ip"),
        observed_at=timestamp,
        explanation=str(getattr(alert, "explanation", "Legacy detector finding")),
        evidence=evidence,
        source=source,
        capture_interface=capture_interface,
        capture_session_id=capture_session_id,
        capture_backend=capture_backend,
        legacy_type=legacy_type,
    )


def detector_alert_to_finding(
    detector: Any,
    alert: Any,
    subject: str,
    source: str = "live",
    capture_interface: Optional[str] = None,
    capture_session_id: Optional[str] = None,
    capture_backend: Optional[str] = None,
) -> DetectionFindingV2:
    """Adapt a V1 alert using a detector's reviewed V2 manifest and metadata."""
    finding = legacy_alert_to_finding(
        alert, subject, source, capture_interface, capture_session_id, capture_backend,
    )
    manifest = getattr(detector, "manifest", None)
    if not isinstance(manifest, DetectorManifestV2):
        return finding
    metadata = dict((getattr(detector, "finding_metadata", None) or {}).get(finding.finding_type, {}))
    finding.detector_id = manifest.detector_id
    finding.detector_version = manifest.version
    finding.signal_family = str(metadata.get("signal_family", manifest.signal_family))
    finding.correlation_group = str(metadata.get("correlation_group", manifest.correlation_group))
    # Calibration is owned by the reviewed central profile, never by a plugin.
    try:
        from core.detection.scoring import default_scoring_config

        profile = default_scoring_config().profile_for(
            manifest.detector_id, finding.finding_type, manifest.version,
        )
        finding.calibration_state = profile.calibration_level
    except Exception:
        finding.calibration_state = "UNCALIBRATED"
    finding.category = str(metadata.get("category", finding.category)).upper()
    finding.impact = str(metadata.get("impact", finding.impact)).upper()
    finding.confidence = float(metadata.get("confidence", finding.confidence))
    if finding.evidence.get("protected_gateway"):
        finding.impact = "HIGH"
        finding.confidence = max(0.95, finding.confidence)
    required = manifest.required_evidence.get(finding.finding_type, ())
    finding.evidence_quality = evidence_quality(required, finding.evidence)
    finding.recommended_action = metadata.get("recommended_action", finding.recommended_action)
    finding.mitre_technique = metadata.get("mitre_technique", finding.mitre_technique)
    if all(key in finding.evidence for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")):
        finding.flow_ref = (
            f"{finding.evidence['src_ip']}:{finding.evidence['src_port']}->"
            f"{finding.evidence['dst_ip']}:{finding.evidence['dst_port']}/{finding.evidence['protocol']}"
        )
    refs = []
    for key, value in finding.evidence.items():
        if key.endswith("hash") and isinstance(value, str):
            refs.append(f"sha256:{value}")
        elif key in {"record_id", "rule_id"} and value is not None:
            refs.append(f"{key}:{value}")
    if finding.flow_ref:
        refs.append(f"flow:{finding.flow_ref}")
    finding.evidence_refs = tuple(sorted(set(refs)))
    finding.fingerprint = finding.make_fingerprint()
    return finding

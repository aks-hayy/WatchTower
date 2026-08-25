"""Threat context, suppression and deterministic alert fingerprinting."""

from dataclasses import dataclass, field
from hashlib import sha256
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, List, Optional
import json
import time

import yaml


@dataclass
class AlertDecision:
    severity: str
    score: float
    fingerprint: str
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    context: Dict = field(default_factory=dict)


class DetectionPolicy:
    def __init__(self, config_path: Optional[str] = None, config: Optional[Dict] = None):
        path = Path(config_path) if config_path else Path(__file__).resolve().parents[1] / "threat_intel.yaml"
        if config is not None:
            self.config = config
        else:
            try:
                self.config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                self.config = {}
        self.dedup_window = int(self.config.get("dedup_window_seconds", 300))

    def evaluate(
        self,
        entity_ip: str,
        alert_type: str,
        severity: str,
        score: float,
        explanation: str,
        evidence: Optional[Dict] = None,
        timestamp: Optional[float] = None,
    ) -> AlertDecision:
        evidence = dict(evidence or {})
        destination = evidence.get("dst_ip") or evidence.get("destination_ip")
        domain = str(evidence.get("domain") or evidence.get("remote_hostname") or "").lower().rstrip(".")
        file_hash = str(evidence.get("sha256") or "").lower()
        matches = self._ioc_matches(entity_ip, destination, domain, file_hash)

        adjusted_score = float(score or 0.0)
        adjusted_severity = str(severity or "LOW").upper()
        if matches:
            adjusted_score = max(adjusted_score, 90.0)
            adjusted_severity = "CRITICAL"

        multiplier = self._subnet_sensitivity(entity_ip)
        adjusted_score = round(min(100.0, adjusted_score * multiplier), 1)
        adjusted_severity = self._severity_for_score(
            adjusted_score, adjusted_severity, allow_downgrade=multiplier < 1.0 and not matches
        )

        suppression_reason = None
        if not matches:
            suppression_reason = self._suppression_reason(entity_ip, destination, domain, alert_type)

        context = {
            "ioc_matches": matches,
            "subnet_multiplier": multiplier,
            "evaluated_at": time.time(),
        }
        fingerprint = self.fingerprint(entity_ip, alert_type, explanation, evidence)
        return AlertDecision(
            severity=adjusted_severity,
            score=adjusted_score,
            fingerprint=fingerprint,
            suppressed=bool(suppression_reason),
            suppression_reason=suppression_reason,
            context=context,
        )

    @staticmethod
    def fingerprint(entity_ip: str, alert_type: str, explanation: str, evidence: Dict) -> str:
        identity_keys = (
            "dst_ip", "destination_ip", "dst_port", "port", "domain", "remote_hostname",
            "sha256", "ja3", "ja4", "flow", "rule", "target", "targets",
        )
        identity = {key: evidence[key] for key in identity_keys if key in evidence}
        if not identity:
            identity["explanation"] = explanation
        payload = {
            "entity_ip": entity_ip,
            "type": alert_type,
            "identity": identity,
        }
        encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
        return sha256(encoded).hexdigest()

    def _ioc_matches(self, entity_ip, destination, domain, file_hash) -> List[str]:
        iocs = self.config.get("iocs") or {}
        matches = []
        malicious_ips = set(iocs.get("ips") or [])
        if entity_ip in malicious_ips:
            matches.append(f"ip:{entity_ip}")
        if destination in malicious_ips:
            matches.append(f"ip:{destination}")
        if domain and self._domain_matches(domain, iocs.get("domains") or []):
            matches.append(f"domain:{domain}")
        if file_hash and file_hash in {str(value).lower() for value in (iocs.get("hashes") or [])}:
            matches.append(f"sha256:{file_hash}")
        return matches

    def _suppression_reason(self, entity_ip, destination, domain, alert_type) -> Optional[str]:
        allowlists = self.config.get("allowlists") or {}
        if entity_ip in set(allowlists.get("ips") or []) or destination in set(allowlists.get("ips") or []):
            return "IP allowlist"
        for cidr in allowlists.get("subnets") or []:
            if self._in_subnet(entity_ip, cidr) or (destination and self._in_subnet(destination, cidr)):
                return f"Subnet allowlist: {cidr}"
        domains = (allowlists.get("domains") or []) + (self.config.get("dns_whitelist") or [])
        if alert_type == "SUSPICIOUS_DNS" and domain and self._domain_matches(domain, domains):
            return f"Domain allowlist: {domain}"

        for rule in self.config.get("suppressions") or []:
            if rule.get("alert_type") not in (None, "*", alert_type):
                continue
            if rule.get("entity_ip") and rule["entity_ip"] != entity_ip:
                continue
            if rule.get("destination_ip") and rule["destination_ip"] != destination:
                continue
            return rule.get("reason") or "Configured suppression"
        return None

    def _subnet_sensitivity(self, entity_ip: str) -> float:
        for cidr, subnet_config in (self.config.get("subnets") or {}).items():
            if self._in_subnet(entity_ip, cidr):
                return float(subnet_config.get("sensitivity", 1.0))
        return 1.0

    @staticmethod
    def _domain_matches(domain: str, candidates: List[str]) -> bool:
        return any(domain == candidate.lower().rstrip(".") or domain.endswith("." + candidate.lower().rstrip(".")) for candidate in candidates)

    @staticmethod
    def _in_subnet(value: str, cidr: str) -> bool:
        try:
            return ip_address(value) in ip_network(cidr, strict=False)
        except ValueError:
            return False

    @staticmethod
    def _severity_for_score(score: float, original: str, allow_downgrade: bool = False) -> str:
        ranks = {"LOW": 1, "MEDIUM": 2, "SUSPICIOUS": 2, "HIGH": 3, "CRITICAL": 4}
        calculated = "CRITICAL" if score >= 90 else ("HIGH" if score >= 60 else ("MEDIUM" if score >= 25 else "LOW"))
        if allow_downgrade:
            return calculated
        return calculated if ranks.get(calculated, 0) > ranks.get(original, 0) else original

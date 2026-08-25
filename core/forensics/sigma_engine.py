"""Validated Sigma evaluation against stored WatchTower historical records."""

from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Tuple

import yaml
from sigma.collection import SigmaCollection

from core.forensics.forwarder import AlertForwarder
from core.forensics.models import ForensicAlert
from core.storage.database import WatchtowerDB
from core.detection.contracts import DetectorManifestV2, detector_alert_to_finding

logger = logging.getLogger(__name__)

SUPPORTED_CATEGORIES = {
    "dns",
    "firewall",
    "network_connection",
    "network_identity",
    "network_dns",
    "network_traffic",
}
SUPPORTED_LEVELS = {"medium", "high", "critical"}
SUPPORTED_STATUS = {"stable", "test"}
FIELD_ALIASES = {
    "SourceIp": "src_ip", "DestinationIp": "dst_ip",
    "SourcePort": "src_port", "DestinationPort": "dst_port",
    "IpAddress": "ip", "User": "username", "Hostname": "hostname",
    "Protocol": "protocol", "Bytes": "byte_count", "query": "remote_hostname",
}
FLOW_FIELDS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_count",
    "byte_count", "start_time", "last_seen", "source", "capture_interface",
    "capture_session_id", "l7_metadata", "remote_hostname", "domain", "dns_query",
    "http_host", "http_method", "tls_sni", "ja3_hash", "ja4_string",
    "application_protocol", "ssh_banner", "ldap_operation", "rdp_cookie_user",
    "mail_from", "mail_to", "snmp_community", "mqtt_packet_type",
    "modbus_function", *FIELD_ALIASES,
}
ENTITY_FIELDS = {
    "ip", "mac", "vendor", "hostname", "netbios_name", "username", "full_name",
    "os_info", "ja3_hash", "ja4_string", "tls_library", "source", *FIELD_ALIASES,
}
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "exists", "all"}


class SigmaCompatibilityError(ValueError):
    pass


SIGMA_MANIFEST = DetectorManifestV2(
    detector_id="watchtower.sigma", name="Historical Sigma Hunt Engine",
    input_kinds=("metadata",), finding_types=("rule.sigma.match",),
    required_evidence={"rule.sigma.match": ("rule_id", "record_id")},
    signal_family="rule", correlation_group="sigma",
)


class _SigmaFindingAdapter:
    manifest = SIGMA_MANIFEST
    finding_metadata = {
        "rule.sigma.match": {
            "category": "THREAT", "impact": "HIGH", "confidence": 0.95,
            "correlation_group": "sigma",
        },
    }


def validate_rule(rule: Dict[str, Any], upstream: bool = False) -> List[str]:
    reasons = []
    if not isinstance(rule, dict):
        return ["document is not a mapping"]
    category = str(rule.get("logsource", {}).get("category", ""))
    if category not in SUPPORTED_CATEGORIES:
        reasons.append(f"unsupported logsource category: {category or '<missing>'}")
    if upstream and str(rule.get("status", "")).lower() not in SUPPORTED_STATUS:
        reasons.append(f"unsupported status: {rule.get('status', '<missing>')}")
    if upstream and str(rule.get("level", "")).lower() not in SUPPORTED_LEVELS:
        reasons.append(f"unsupported level: {rule.get('level', '<missing>')}")
    if reasons:
        return list(dict.fromkeys(reasons))
    try:
        SigmaCollection.from_dicts([rule])
    except Exception as exc:
        reasons.append(f"pySigma validation failed: {exc}")
        return reasons
    detection = rule.get("detection") or {}
    condition = detection.get("condition")
    if not isinstance(condition, str):
        reasons.append("detection.condition must be a string")
    allowed_fields = ENTITY_FIELDS if category == "network_identity" else FLOW_FIELDS
    for name, selection in detection.items():
        if name == "condition":
            continue
        mappings = selection if isinstance(selection, list) else [selection]
        for mapping in mappings:
            if not isinstance(mapping, dict):
                reasons.append(f"selection {name} must contain field mappings")
                continue
            for field_spec in mapping:
                parts = field_spec.split("|")
                field = parts[0]
                modifiers = parts[1:]
                if field not in allowed_fields and field.lower() not in {item.lower() for item in allowed_fields}:
                    reasons.append(f"unsupported field: {field}")
                unknown = set(modifiers) - SUPPORTED_MODIFIERS
                if unknown:
                    reasons.append(f"unsupported modifier on {field}: {', '.join(sorted(unknown))}")
    return list(dict.fromkeys(reasons))


class SigmaPredicate:
    def __init__(self, rule: Dict[str, Any]):
        errors = validate_rule(rule)
        if errors:
            raise SigmaCompatibilityError("; ".join(errors))
        self.rule = rule
        self.detection = rule["detection"]

    @staticmethod
    def _record(record: Dict[str, Any]) -> Dict[str, Any]:
        flattened = dict(record)
        metadata = flattened.get("l7_metadata")
        if isinstance(metadata, dict):
            flattened.update(metadata)
        for alias, native in FIELD_ALIASES.items():
            if native in flattened:
                flattened[alias] = flattened[native]
        return flattened

    @staticmethod
    def _one(actual: Any, expected: Any, modifiers: List[str]) -> bool:
        if "exists" in modifiers:
            wanted = bool(expected)
            return (actual is not None) == wanted
        if actual is None:
            return False
        actual_text = str(actual)
        expected_text = str(expected)
        try:
            if "cidr" in modifiers:
                return ip_address(actual_text) in ip_network(expected_text, strict=False)
            if "re" in modifiers:
                return re.search(expected_text, actual_text, re.IGNORECASE) is not None
        except (ValueError, re.error):
            return False
        left, right = actual_text.lower(), expected_text.lower()
        if "contains" in modifiers: return right in left
        if "startswith" in modifiers: return left.startswith(right)
        if "endswith" in modifiers: return left.endswith(right)
        if "*" in right or "?" in right: return fnmatch(left, right)
        return left == right

    def _selection(self, record: Dict[str, Any], selection: Any) -> bool:
        if isinstance(selection, list):
            return any(self._selection(record, item) for item in selection)
        if not isinstance(selection, dict):
            return False
        for field_spec, expected in selection.items():
            parts = field_spec.split("|")
            field, modifiers = parts[0], parts[1:]
            actual = record.get(field)
            if actual is None:
                actual = next((value for key, value in record.items() if key.lower() == field.lower()), None)
            values = expected if isinstance(expected, list) else [expected]
            results = [self._one(actual, value, modifiers) for value in values]
            if (all(results) if "all" in modifiers else any(results)) is False:
                return False
        return True

    def matches(self, source_record: Dict[str, Any]) -> bool:
        record = self._record(source_record)
        values = {
            name: self._selection(record, selection)
            for name, selection in self.detection.items() if name != "condition"
        }
        condition = self.detection["condition"]
        condition = self._expand_quantifiers(condition, values)
        tokens = re.findall(r"\(|\)|\b(?:and|or|not|true|false)\b|[A-Za-z0-9_.-]+", condition, re.I)
        position = 0

        def parse_primary():
            nonlocal position
            if position >= len(tokens): raise SigmaCompatibilityError("incomplete condition")
            token = tokens[position]; position += 1
            if token == "(":
                value = parse_or()
                if position >= len(tokens) or tokens[position] != ")": raise SigmaCompatibilityError("unclosed condition")
                position += 1
                return value
            if token.lower() in {"true", "false"}: return token.lower() == "true"
            if token not in values: raise SigmaCompatibilityError(f"unknown selection: {token}")
            return values[token]

        def parse_not():
            nonlocal position
            if position < len(tokens) and tokens[position].lower() == "not":
                position += 1
                return not parse_not()
            return parse_primary()

        def parse_and():
            nonlocal position
            value = parse_not()
            while position < len(tokens) and tokens[position].lower() == "and":
                position += 1
                right = parse_not()
                value = value and right
            return value

        def parse_or():
            nonlocal position
            value = parse_and()
            while position < len(tokens) and tokens[position].lower() == "or":
                position += 1
                right = parse_and()
                value = value or right
            return value

        result = parse_or()
        if position != len(tokens): raise SigmaCompatibilityError("unsupported condition syntax")
        return result

    @staticmethod
    def _expand_quantifiers(condition: str, values: Dict[str, bool]) -> str:
        pattern = re.compile(r"\b(1|all)\s+of\s+(them|[A-Za-z0-9_*.-]+)(?=\s|\)|$)", re.I)
        def replace(match):
            mode, target = match.group(1).lower(), match.group(2)
            names = list(values) if target.lower() == "them" else [name for name in values if fnmatch(name, target)]
            if not names: raise SigmaCompatibilityError(f"condition pattern matched no selections: {target}")
            operator = " or " if mode == "1" else " and "
            return "(" + operator.join(names) + ")"
        return pattern.sub(replace, condition)


class SigmaEngine:
    manifest = SIGMA_MANIFEST
    finding_metadata = _SigmaFindingAdapter.finding_metadata
    """The only Sigma execution engine; it reads historical DB rows and persists matches."""

    def __init__(self, plugins_dir="core/forensics/plugins/sigma", managed_dir="data/sigma/active",
                 custom_dir="data/sigma/custom", db=None):
        self.rule_dirs = [Path(plugins_dir), Path(custom_dir), Path(managed_dir)]
        self.rules: List[Dict[str, Any]] = []
        self.rejected: List[Dict[str, str]] = []
        self.db = db or WatchtowerDB()
        self.forwarder = AlertForwarder(config={"enabled": False})
        self.load_rules()

    def load_rules(self):
        self.rules, self.rejected = [], []
        ids = set()
        for root in self.rule_dirs:
            if not root.exists(): continue
            for path in sorted(root.rglob("*.y*ml")):
                try:
                    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                    errors = validate_rule(rule)
                    rule_id = str((rule or {}).get("id", ""))
                    if rule_id and rule_id in ids: errors.append(f"duplicate rule id: {rule_id}")
                    if errors:
                        self.rejected.append({"path": str(path), "reason": "; ".join(errors)})
                        continue
                    if rule_id: ids.add(rule_id)
                    self.rules.append(rule)
                except Exception as exc:
                    self.rejected.append({"path": str(path), "reason": str(exc)})

    def run_hunt(self, source: str = None, specific_rule: str = None, interface: str = None,
                 persist: bool = True) -> List[ForensicAlert]:
        flows = self.db.get_flows(source=source, interface=interface, limit=1_000_000)
        entities = self.db.get_all_entities(source=source)
        matches: List[Tuple[ForensicAlert, str, str]] = []
        for rule in self.rules:
            if specific_rule and specific_rule not in {rule.get("title"), rule.get("id")}:
                continue
            predicate = SigmaPredicate(rule)
            category = rule.get("logsource", {}).get("category")
            if category == "network_identity":
                records = entities
            elif category == "dns":
                records = [
                    flow for flow in flows
                    if flow.get("src_port") in {53, 5353} or flow.get("dst_port") in {53, 5353}
                ]
            else:
                records = flows
            for record in records:
                if not predicate.matches(record): continue
                severity = str(rule.get("level", "medium")).upper()
                score = {"CRITICAL": 85.0, "HIGH": 60.0, "MEDIUM": 40.0, "LOW": 10.0}.get(severity, 40.0)
                ip = record.get("ip") or record.get("src_ip") or "0.0.0.0"
                alert_source = record.get("source") or source or "historical"
                evidence = {"rule_id": rule.get("id"), "rule": rule.get("title"), "record_id": record.get("id")}
                alert = ForensicAlert(float(record.get("start_time") or record.get("last_seen") or 0.0),
                    "SIGMA_MATCH", severity, score, f"Sigma Rule Match: {rule.get('title', 'Unknown Rule')}", evidence)
                matches.append((alert, ip, alert_source, record))
        result = []
        for alert, ip, alert_source, record in matches:
            if not persist:
                result.append(alert)
                continue
            mode = os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower()
            stored = {"suppressed": False}
            if mode in {"legacy", "dual"}:
                stored = self.db.insert_alert(
                    ip, alert.timestamp, alert.type, alert.severity, alert.score,
                    alert.explanation, alert.evidence, source=alert_source,
                    capture_interface=record.get("capture_interface"),
                    capture_session_id=record.get("capture_session_id"),
                    capture_backend=record.get("capture_backend"),
                )
            elif mode == "v2":
                decision = self.db.alert_policy.evaluate(
                    ip, alert.type, alert.severity, alert.score,
                    alert.explanation, alert.evidence, alert.timestamp,
                )
                stored = {"suppressed": decision.suppressed,
                          "suppression_reason": decision.suppression_reason or "policy suppression"}
            if mode in {"dual", "v2"}:
                finding = detector_alert_to_finding(
                    self, alert, ip, source=alert_source,
                    capture_interface=record.get("capture_interface"),
                    capture_session_id=record.get("capture_session_id"),
                    capture_backend=record.get("capture_backend"),
                )
                finding.impact = alert.severity if alert.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"
                finding.fingerprint = finding.make_fingerprint()
                errors = finding.validate(self.manifest)
                if errors:
                    logger.error("Rejected Sigma finding: %s", "; ".join(errors))
                    continue
                finding_result = self.db.upsert_detection_finding(finding)
                if stored["suppressed"] and finding_result.get("created"):
                    self.db.set_finding_disposition(
                        finding_result["id"], "benign_expected",
                        stored.get("suppression_reason") or "detection policy suppression",
                        actor="watchtower-policy",
                    )
                self.db.recompute_risk_rollups(
                    ip, source=alert_source, interface=record.get("capture_interface"),
                    capture_session_id=record.get("capture_session_id"), as_of=finding.last_seen,
                )
            if not stored["suppressed"]:
                result.append(alert)
                self.forwarder.forward(alert, ip)
        return result

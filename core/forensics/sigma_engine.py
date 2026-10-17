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
from core.forensics.sigma_paths import default_sigma_builtin_dir, default_sigma_data_dir
from core.storage.database import WatchtowerDB
from core.detection.contracts import DetectorManifestV2, detector_alert_to_finding

logger = logging.getLogger(__name__)

SIGMA_FLOW_HUNT_LIMIT = 1_000_000
SIGMA_IDENTITY_HUNT_LIMIT = 4_999  # leave one slot for the truncation sentinel; DB caps requests at 5,000

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
        if isinstance(actual, (list, tuple, set)):
            return any(SigmaPredicate._one(item, expected, modifiers) for item in actual)
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

    def __init__(self, plugins_dir=None, managed_dir=None, custom_dir=None, db=None):
        sigma_data_dir = default_sigma_data_dir()
        self.rule_dirs = [
            Path(plugins_dir) if plugins_dir is not None else default_sigma_builtin_dir(),
            Path(custom_dir) if custom_dir is not None else sigma_data_dir / "custom",
            Path(managed_dir) if managed_dir is not None else sigma_data_dir / "active",
        ]
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

    @staticmethod
    def _scoped_identity_records(flows: List[Dict[str, Any]],
                                 observations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build identity rows only from facts carrying the selected capture provenance."""
        records: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}

        def record_for(ip: str, source: str, interface: str, session_id: str,
                       sensor_node_id: str, first_seen: Any = None,
                       last_seen: Any = None) -> Dict[str, Any]:
            key = (ip, source, interface, session_id, sensor_node_id)
            record = records.setdefault(key, {
                "ip": ip, "source": source, "capture_interface": interface or None,
                "capture_session_id": session_id or None,
                "sensor_node_id": sensor_node_id or None, "evidence_refs": [],
                "evidence_refs_truncated": False,
            })
            if first_seen is not None:
                previous = record.get("start_time")
                record["start_time"] = min(float(previous), float(first_seen)) if previous is not None else float(first_seen)
            if last_seen is not None:
                record["last_seen"] = max(float(record.get("last_seen") or last_seen), float(last_seen))
            return record

        def add_values(record: Dict[str, Any], field: str, values: Any) -> None:
            if values is None:
                return
            items = values if isinstance(values, (list, tuple, set)) else [values]
            kept = [str(item) for item in items if item not in (None, "")]
            if not kept:
                return
            existing = record.get(field)
            merged = list(existing) if isinstance(existing, list) else ([existing] if existing is not None else [])
            unique = list(dict.fromkeys([*merged, *kept]))
            if len(unique) > 64:
                record["evidence_values_truncated"] = True
                unique = unique[:64]
            record[field] = unique

        def add_evidence_ref(record: Dict[str, Any], reference: str) -> None:
            if reference in record["evidence_refs"]:
                return
            if len(record["evidence_refs"]) >= 32:
                record["evidence_refs_truncated"] = True
                return
            record["evidence_refs"].append(reference)

        source_fields = {
            "hostname": ("local_hostname", "hostname"),
            "netbios_name": ("netbios_name",),
            "username": ("local_username", "smb_user"),
            "full_name": ("full_name",),
            "mac": ("mac", "local_mac", "arp_sender_mac"),
            "vendor": ("vendor",), "os_info": ("os_info", "os"),
            "ja3_hash": ("ja3_hash",), "ja4_string": ("ja4_string",),
            "tls_library": ("tls_library",),
        }
        destination_fields = {
            "hostname": ("remote_hostname", "server_name", "tls_sni", "http_host"),
        }

        for flow in flows:
            metadata = flow.get("l7_metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            scope = (
                str(flow.get("source") or ""), str(flow.get("capture_interface") or ""),
                str(flow.get("capture_session_id") or ""), str(flow.get("sensor_node_id") or ""),
            )
            for ip, field_map in (
                (str(flow.get("src_ip") or ""), source_fields),
                (str(flow.get("dst_ip") or ""), destination_fields),
            ):
                if not ip:
                    continue
                record = record_for(
                    ip, *scope, first_seen=flow.get("start_time"), last_seen=flow.get("last_seen"),
                )
                record.setdefault("capture_backend", flow.get("capture_backend"))
                record.setdefault("capture_type", flow.get("capture_type"))
                for field, names in field_map.items():
                    for name in names:
                        add_values(record, field, metadata.get(name))
                flow_id = flow.get("id")
                if flow_id is not None:
                    add_evidence_ref(record, f"flow:{flow_id}")

        observation_fields = {
            "dns_name": (("hostname", "name"),),
            "arp_binding": (("mac", "mac"),),
            "ndp_binding": (("mac", "mac"),),
            "active_arp_confirmation": (("mac", "mac"),),
        }
        for observation in observations:
            ip = str(observation.get("subject_ip") or "")
            if not ip:
                continue
            scope = (
                str(observation.get("source") or ""),
                str(observation.get("capture_interface") or ""),
                str(observation.get("capture_session_id") or ""),
                str(observation.get("sensor_node_id") or ""),
            )
            record = record_for(
                ip, *scope, first_seen=observation.get("first_seen"),
                last_seen=observation.get("last_seen"),
            )
            value = observation.get("value")
            if not isinstance(value, dict):
                continue
            for field, key in observation_fields.get(observation.get("observation_type"), ()):
                add_values(record, field, value.get(key))
            evidence_ref = observation.get("evidence_ref") or observation.get("id")
            if evidence_ref:
                add_evidence_ref(record, f"identity:{evidence_ref}")

        for record in records.values():
            record["evidence_refs"] = sorted(set(record["evidence_refs"]))
        return list(records.values())

    def run_hunt(self, source: str = None, specific_rule: str = None, interface: str = None,
                 persist: bool = True, capture_session_id: str = None,
                 time_start: float = None, time_end: float = None,
                 sensor_node_id: str = None, target_ips: list[str] = None) -> List[ForensicAlert]:
        """Compatibility API returning matches only; use run_hunt_report for completeness."""
        return self.run_hunt_report(
            source=source, specific_rule=specific_rule, interface=interface, persist=persist,
            capture_session_id=capture_session_id, time_start=time_start, time_end=time_end,
            sensor_node_id=sensor_node_id, target_ips=target_ips,
        )["alerts"]

    def run_hunt_report(self, source: str = None, specific_rule: str = None, interface: str = None,
                        persist: bool = True, capture_session_id: str = None,
                        time_start: float = None, time_end: float = None,
                        sensor_node_id: str = None, target_ips: list[str] = None) -> Dict[str, Any]:
        """Evaluate a bounded hunt and state explicitly when a query cap omitted evidence."""
        flows = self.db.get_flows(
            source=source, interface=interface, capture_session_id=capture_session_id,
            time_start=time_start, time_end=time_end, sensor_node_id=sensor_node_id,
            target_ips=target_ips, limit=SIGMA_FLOW_HUNT_LIMIT + 1,
        )
        limitations = []
        if len(flows) > SIGMA_FLOW_HUNT_LIMIT:
            flows = flows[:SIGMA_FLOW_HUNT_LIMIT]
            limitations.append(
                f"Flow evaluation reached the {SIGMA_FLOW_HUNT_LIMIT:,}-record limit; matches may be missing."
            )
        scoped = any(value is not None for value in (
            source, interface, capture_session_id, time_start, time_end, sensor_node_id,
        )) or bool(target_ips)
        if scoped:
            candidate_ips = {
                str(ip) for flow in flows for ip in (flow.get("src_ip"), flow.get("dst_ip")) if ip
            }
            candidate_ips.update(str(ip) for ip in (target_ips or ()) if ip)
            observations = self.db.get_identity_observations(
                source=source, interface=interface, capture_session_id=capture_session_id,
                sensor_node_id=sensor_node_id, time_start=time_start, time_end=time_end,
                target_ips=sorted(candidate_ips) if candidate_ips else None,
                limit=SIGMA_IDENTITY_HUNT_LIMIT + 1,
            )
            if len(observations) > SIGMA_IDENTITY_HUNT_LIMIT:
                observations = observations[:SIGMA_IDENTITY_HUNT_LIMIT]
                limitations.append(
                    f"Identity evaluation reached the {SIGMA_IDENTITY_HUNT_LIMIT:,}-record limit; matches may be missing."
                )
            identity_records = self._scoped_identity_records(flows, observations)
        else:
            identity_records = self.db.get_all_entities(source=source)
        selected_rules = [
            rule for rule in self.rules
            if not specific_rule or specific_rule in {rule.get("title"), rule.get("id")}
        ]
        matches: List[Tuple[ForensicAlert, str, str]] = []
        for rule in selected_rules:
            predicate = SigmaPredicate(rule)
            category = rule.get("logsource", {}).get("category")
            if category == "network_identity":
                records = identity_records
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
                record_id = record.get("id") or record.get("ip")
                evidence = {"rule_id": rule.get("id"), "rule": rule.get("title"), "record_id": record_id}
                if record.get("evidence_refs"):
                    evidence["evidence_refs"] = record["evidence_refs"]
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
                    capture_type=record.get("capture_type") or "network",
                    sensor_node_id=record.get("sensor_node_id"),
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
                finding.sensor_node_id = record.get("sensor_node_id")
                finding.first_seen = float(
                    record.get("start_time") if record.get("start_time") is not None else alert.timestamp
                )
                finding.last_seen = float(
                    record.get("last_seen") if record.get("last_seen") is not None else alert.timestamp
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
        return {
            "alerts": result,
            "complete": not limitations,
            "limitations": limitations,
            "evaluated_flows": len(flows),
            "evaluated_identity_observations": len(observations) if scoped else None,
            "evaluated_rules": len(selected_rules),
            "coverage_status": "no_compatible_rules" if not selected_rules else "covered",
        }

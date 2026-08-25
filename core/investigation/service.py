"""Correlate stored Watchtower records into an evidence-backed IP investigation."""

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional
import time

from core.intelligence.local_assets import LocalAssetProfiler


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "SUSPICIOUS": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class InvestigationResult:
    target: str
    source: str
    generated_at: float
    verdict: str
    risk_score: float
    confidence: float
    summary: str
    asset_profile: Dict
    findings: List[str] = field(default_factory=list)
    alert_groups: List[Dict] = field(default_factory=list)
    correlations: List[Dict] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class InvestigationService:
    def __init__(self, db):
        self.db = db
        self.asset_profiler = LocalAssetProfiler(db)

    def investigate(self, ip: str, source: Optional[str] = None, persist: bool = True,
                    sensor_node_id: Optional[str] = None) -> InvestigationResult:
        entity = self.db.get_entity(ip) or {"ip": ip}
        effective_source = source or entity.get("source") or "live"
        profile = self.asset_profiler.build(
            ip, source=source, persist=persist, sensor_node_id=sensor_node_id,
        ).to_dict()
        flow_kwargs = {"source": source, "limit": 5000}
        alert_kwargs = {"entity_ip": ip, "source": source, "limit": 1000}
        file_kwargs = {"entity_ip": ip, "source": source}
        if sensor_node_id:
            flow_kwargs["sensor_node_id"] = sensor_node_id
            alert_kwargs["sensor_node_id"] = sensor_node_id
            file_kwargs["sensor_node_id"] = sensor_node_id
        flows = self.db.get_entity_flows(ip, **flow_kwargs)
        alerts = self.db.get_alerts(**alert_kwargs)
        files = self.db.get_carved_files(**file_kwargs)

        evidence = []
        timeline = []
        for flow in flows:
            ref = f"flow:{flow['id']}"
            direction = "outbound" if flow.get("src_ip") == ip else "inbound"
            peer = flow.get("dst_ip") if direction == "outbound" else flow.get("src_ip")
            summary = (
                f"{direction} {flow.get('protocol', 'OTHER')} traffic with {peer} "
                f"on port {flow.get('dst_port')} ({flow.get('packet_count', 0)} packets)"
            )
            item = self._evidence_item(
                ip, effective_source, "flow", ref, flow.get("last_seen") or flow.get("start_time"),
                summary, flow, 1.0,
            )
            evidence.append(item)
            timeline.append(self._timeline_item(item))

        for alert in alerts:
            ref = f"alert:{alert['id']}"
            details = dict(alert)
            summary = f"{alert.get('severity', 'UNKNOWN')} {alert.get('type', 'UNKNOWN')}: {alert.get('explanation', '')}"
            item = self._evidence_item(
                ip, effective_source, "alert", ref, alert.get("timestamp"), summary, details, 1.0,
            )
            evidence.append(item)
            timeline.append(self._timeline_item(item))

        for carved in files:
            ref = f"file:{carved['id']}"
            summary = f"Carved {carved.get('filename')} ({carved.get('size', 0)} bytes, SHA256 {carved.get('sha256')})"
            item = self._evidence_item(
                ip, effective_source, "file", ref, carved.get("timestamp"), summary, carved, 1.0,
            )
            evidence.append(item)
            timeline.append(self._timeline_item(item))

        correlations = self._correlate_alerts_to_flows(ip, effective_source, alerts, flows)
        evidence.extend(correlations)
        alert_groups = self._group_alerts(alerts)
        risk_score, verdict = self._risk(alerts)
        findings = self._findings(profile, alert_groups, files)
        confidence = self._confidence(entity, flows, alerts, files)
        next_actions = self._next_actions(profile, alert_groups, files, correlations)
        timeline.sort(key=lambda item: item.get("timestamp") or 0, reverse=True)

        summary = (
            f"{len(flows)} flow(s), {len(alerts)} alert(s), {len(files)} carved file(s), "
            f"and {len(correlations)} temporal correlation(s) support a {verdict.lower()} assessment."
        )
        result = InvestigationResult(
            target=ip,
            source=effective_source,
            generated_at=time.time(),
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            summary=summary,
            asset_profile=profile,
            findings=findings,
            alert_groups=alert_groups,
            correlations=correlations,
            timeline=timeline[:200],
            evidence=evidence,
            next_actions=next_actions,
        )
        if persist:
            self.db.upsert_evidence_links(evidence)
        return result

    @staticmethod
    def _evidence_item(ip, source, evidence_type, ref, timestamp, summary, details, confidence):
        return {
            "entity_ip": ip,
            "source": source,
            "evidence_type": evidence_type,
            "evidence_ref": ref,
            "timestamp": float(timestamp or 0.0),
            "summary": summary,
            "details": details,
            "confidence": confidence,
        }

    @staticmethod
    def _timeline_item(item):
        return {
            "timestamp": item["timestamp"],
            "type": item["evidence_type"],
            "ref": item["evidence_ref"],
            "summary": item["summary"],
        }

    def _correlate_alerts_to_flows(self, ip, source, alerts, flows):
        links = []
        for alert in alerts:
            alert_time = float(alert.get("timestamp") or 0.0)
            if alert_time <= 0:
                continue
            candidates = []
            for flow in flows:
                start = float(flow.get("start_time") or 0.0)
                end = float(flow.get("last_seen") or start)
                if start - 5.0 <= alert_time <= end + 30.0:
                    distance = 0.0 if start <= alert_time <= end else min(abs(alert_time - start), abs(alert_time - end))
                    candidates.append((distance, flow))
            for distance, flow in sorted(candidates, key=lambda item: item[0])[:3]:
                confidence = round(max(0.55, 0.9 - (distance / 100.0)), 2)
                alert_ref = f"alert:{alert['id']}"
                flow_ref = f"flow:{flow['id']}"
                ref = f"{alert_ref}->{flow_ref}"
                links.append(self._evidence_item(
                    ip,
                    source,
                    "correlation",
                    ref,
                    alert_time,
                    f"{alert_ref} occurred during or near {flow_ref}",
                    {"alert_ref": alert_ref, "flow_ref": flow_ref, "time_distance_seconds": distance},
                    confidence,
                ))
        return links

    @staticmethod
    def _group_alerts(alerts):
        groups = {}
        for alert in alerts:
            alert_type = alert.get("type") or "UNKNOWN"
            group = groups.setdefault(alert_type, {
                "type": alert_type,
                "count": 0,
                "max_severity": "LOW",
                "max_score": 0.0,
                "latest": 0.0,
                "refs": [],
            })
            group["count"] += 1
            group["max_score"] = max(group["max_score"], float(alert.get("score") or 0.0))
            group["latest"] = max(group["latest"], float(alert.get("timestamp") or 0.0))
            group["refs"].append(f"alert:{alert['id']}")
            severity = (alert.get("severity") or "LOW").upper()
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(group["max_severity"], 0):
                group["max_severity"] = severity
        return sorted(groups.values(), key=lambda item: (-SEVERITY_RANK.get(item["max_severity"], 0), -item["max_score"]))

    @staticmethod
    def _risk(alerts):
        score = min(100.0, sum(max(0.0, float(alert.get("score") or 0.0)) for alert in alerts))
        severities = {str(alert.get("severity") or "").upper() for alert in alerts}
        if "CRITICAL" in severities or score >= 80:
            verdict = "CRITICAL"
        elif "HIGH" in severities or score >= 50:
            verdict = "HIGH RISK"
        elif alerts or score >= 20:
            verdict = "ELEVATED"
        else:
            verdict = "LOW OBSERVED RISK"
        return round(score, 1), verdict

    @staticmethod
    def _confidence(entity, flows, alerts, files):
        categories = sum(bool(items) for items in (flows, alerts, files))
        identity = sum(bool(entity.get(field)) for field in ("mac", "hostname", "username", "os"))
        score = 0.20 + min(len(flows), 20) * 0.015 + categories * 0.10 + identity * 0.05
        return round(min(0.95, score), 2)

    @staticmethod
    def _findings(profile, alert_groups, files):
        findings = list(profile.get("insights") or [])
        for group in alert_groups[:5]:
            findings.append(
                f"{group['type']} triggered {group['count']} time(s), maximum severity {group['max_severity']}"
            )
        if files:
            findings.append(f"{len(files)} file artifact(s) were carved from related streams")
        return findings or ["No material findings are supported by current evidence"]

    @staticmethod
    def _next_actions(profile, alert_groups, files, correlations):
        actions = []
        if alert_groups:
            actions.append("Review the highest-severity alert references and their exact detector evidence")
        if correlations:
            actions.append("Inspect correlated flow references around each alert timestamp")
        if files:
            actions.append("Validate carved-file hashes and retain the source PCAP for chain of custody")
        if profile.get("served_services"):
            actions.append("Confirm each observed served service is expected for the inferred asset role")
        if profile.get("identity_completeness", 0) < 0.5:
            actions.append("Collect additional passive DHCP, NBNS, Kerberos, or SMB identity observations")
        return actions or ["Continue passive monitoring and establish a behavioral baseline"]

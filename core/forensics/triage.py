"""Case-scoped, explainable suspicion triage for offline investigations."""

from collections import defaultdict
import ipaddress
from typing import Any, Dict, Iterable, List


class OfflineTriageEngine:
    """Turn persisted detector evidence into analyst-reviewable case flags.

    Triage never invents a finding. It only promotes one strong detector signal
    or two independent weaker signals into a case-scoped review item.
    """

    _STRONG_IMPACTS = {"HIGH", "CRITICAL"}
    _WEAK_MIN_CONFIDENCE = 0.5
    _DIRECT_EVIDENCE_TYPES = {
        "file.executable_transfer",
        "file.ioc_match",
        "intel.ioc_match",
        "credential.cleartext.ftp",
        "credential.cleartext.generic",
        "ot.modbus.unauthorized_write",
    }

    def __init__(self, db):
        self.db = db

    @staticmethod
    def _target_type(target: str, flow_ref: str | None) -> str:
        if flow_ref:
            return "flow"
        try:
            ipaddress.ip_address(str(target))
            return "ip"
        except ValueError:
            return "domain" if "." in str(target) else "entity"

    @staticmethod
    def _evidence_refs(finding: Dict[str, Any]) -> List[Any]:
        refs = finding.get("evidence_refs") or []
        return refs if isinstance(refs, list) else [refs]

    def run(self, *, case_id: str, source: str, limit: int = 100000) -> Dict[str, Any]:
        if not hasattr(self.db, "get_detection_findings") or not hasattr(self.db, "upsert_triage_flag"):
            return {"flagged": 0, "signals": 0}
        findings = self.db.get_detection_findings(
            source=source, include_suppressed=False, limit=max(1, min(int(limit), 100000)),
        )
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            target = str(finding.get("target") or finding.get("subject") or "")
            if target:
                groups[target].append(finding)

        flagged = 0
        for target, signals in groups.items():
            strong = [
                item for item in signals
                if str(item.get("impact") or "").upper() in self._STRONG_IMPACTS
                or str(item.get("category") or "").upper() == "THREAT"
                or str(item.get("finding_type") or "") in self._DIRECT_EVIDENCE_TYPES
            ]
            independent = {
                str(item.get("finding_type") or item.get("detector_id") or item.get("id"))
                for item in signals
                if float(item.get("confidence") or 0.0) >= self._WEAK_MIN_CONFIDENCE
            }
            if not strong and len(independent) < 2:
                continue
            selected = strong or [item for item in signals if float(item.get("confidence") or 0.0) >= self._WEAK_MIN_CONFIDENCE]
            selected = sorted(selected, key=lambda item: (float(item.get("confidence") or 0.0), int(item.get("id") or 0)), reverse=True)
            fingerprints = sorted({str(item.get("fingerprint") or item.get("id")) for item in selected})
            fingerprint = "offline-triage:" + ":".join(fingerprints)
            evidence_refs = []
            for item in selected:
                evidence_refs.extend(self._evidence_refs(item))
            dedup_refs = list(dict.fromkeys(str(ref) for ref in evidence_refs if ref))
            primary = selected[0]
            explanation = str(primary.get("explanation") or "Detector evidence requires analyst review")
            if len(selected) > 1:
                explanation = f"{explanation}; corroborated by {len(selected) - 1} independent finding(s)"
            self.db.upsert_triage_flag(case_id, {
                "fingerprint": fingerprint,
                "target_type": self._target_type(target, primary.get("flow_ref")),
                "target_id": target,
                "detector": primary.get("detector_id"),
                "source": source,
                "finding_ids": [item.get("id") for item in selected],
                "evidence_refs": dedup_refs,
                "observed_values": {
                    "finding_types": sorted({str(item.get("finding_type") or "") for item in selected}),
                    "impact": primary.get("impact"),
                    "threshold": (primary.get("evidence") or {}).get("threshold"),
                },
                "reason": explanation,
                "confidence": max(float(item.get("confidence") or 0.0) for item in selected),
                "first_seen": min(float(item.get("first_seen") or 0.0) for item in selected),
                "last_seen": max(float(item.get("last_seen") or 0.0) for item in selected),
                "actor": "system",
            })
            flagged += 1
        return {"flagged": flagged, "signals": len(findings)}

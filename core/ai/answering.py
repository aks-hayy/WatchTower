"""Evidence-first narrative rendering for structured analyst results."""

from __future__ import annotations

import re
from typing import Optional

from core.ai.contracts import ToolResult


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_investigation_answer(result: ToolResult) -> Optional[str]:
    """Render a completed endpoint investigation without adding model-derived facts.

    The local model still chooses and runs the investigation tools. For this
    high-stakes single-endpoint result, this renderer presents only fields
    returned by WatchTower, so a weak synthesis cannot invent a verdict source,
    severity count, or completeness state.
    """
    if result.tool != "investigate" or not isinstance(result.data, dict):
        return None
    data = result.data
    target = str(data.get("target") or "").strip()
    summary = str(data.get("summary") or "").strip()
    if not target or not summary or data.get("error"):
        return None

    lines = [f"WatchTower investigated **{target}** in the selected capture.", "", summary]
    alert_groups = data.get("alert_groups")
    if isinstance(alert_groups, list) and alert_groups:
        lines.extend(["", "**Observed alert groups**"])
        ordered = sorted(
            (item for item in alert_groups if isinstance(item, dict)),
            key=lambda item: _SEVERITY_ORDER.get(str(item.get("max_severity") or "").casefold(), 5),
        )
        for group in ordered[:12]:
            kind = str(group.get("type") or "Unclassified finding")
            severity = str(group.get("max_severity") or "Unrated").upper()
            try:
                count = max(0, int(group.get("count") or 0))
            except (TypeError, ValueError, OverflowError):
                count = 0
            if count == 1:
                detail = f"1 alert; severity **{severity}**"
            else:
                detail = f"{count} alerts (highest recorded severity: **{severity}**)"
            refs = group.get("refs") if isinstance(group.get("refs"), list) else []
            reference_text = f" Evidence: {', '.join(str(ref) for ref in refs[:5])}." if refs else ""
            lines.append(f"- **{severity} — {kind}**: {detail}.{reference_text}")
    else:
        lines.extend(["", "No alert groups were returned by this endpoint investigation."])

    profile = data.get("asset_profile")
    if isinstance(profile, dict):
        role = str(profile.get("role") or "").strip()
        if role:
            try:
                confidence = float(profile.get("role_confidence"))
            except (TypeError, ValueError, OverflowError):
                confidence = None
            suffix = f" (profile confidence {confidence:.2f})" if confidence is not None else ""
            lines.extend(["", f"WatchTower's endpoint profile labels this address **{role}**{suffix}."])
        try:
            identity_completeness = float(profile.get("identity_completeness"))
        except (TypeError, ValueError, OverflowError):
            identity_completeness = None
        if identity_completeness is not None and identity_completeness < 1.0:
            lines.append("Identity attribution is incomplete in this capture.")

    verdict = str(data.get("verdict") or "").strip()
    if verdict:
        lines.extend([
            "",
            f"WatchTower's investigation label is **{verdict.upper()}**. "
            "This assessment reflects the surfaced evidence; it is not proof of compromise.",
        ])

    limitations = list(result.limitations or [])
    data_limitations = data.get("limitations")
    if isinstance(data_limitations, list):
        limitations.extend(str(item) for item in data_limitations if item)
    if limitations:
        lines.extend(["", "**What this investigation could not establish**"])
        lines.extend(f"- {item}" for item in dict.fromkeys(limitations) if item)

    next_actions = data.get("next_actions")
    if isinstance(next_actions, list) and next_actions:
        lines.extend(["", "**Useful next steps**"])
        lines.extend(f"- {str(item)}" for item in next_actions[:5] if item)

    return "\n".join(lines)


def render_tool_failure_answer(results: list[ToolResult], prompt: str) -> Optional[str]:
    """Give an honest recovery response when a requested evidence call failed."""
    research_results = [result for result in results if result.tool == "research"]
    if research_results and all(not result.data and not result.citations for result in research_results) \
            and all(result.tool == "research" for result in results):
        allowed_sources = {
            "rdap", "dns-ptr", "certificate-transparency", "nvd", "cisa-kev", "rdap-asn",
            "virustotal", "abuseipdb", "brave", "openai-web-search", "public-indicator",
        }
        allowed_statuses = {
            "returned data", "no results", "disabled", "credential missing", "timed out", "failed",
        }
        source_outcomes = []
        for result in research_results:
            summary = str(result.summary or "")
            marker = "source outcomes:"
            if marker not in summary.casefold():
                continue
            outcome_text = summary[summary.casefold().index(marker) + len(marker):]
            for outcome in outcome_text.split(";"):
                parts = outcome.strip().rstrip(".").split(maxsplit=1)
                if len(parts) == 2 and parts[0] in allowed_sources and parts[1] in allowed_statuses:
                    label = f"{parts[0]} {parts[1]}"
                    if label not in source_outcomes:
                        source_outcomes.append(label)
        answer = (
            "No configured external source returned data for the requested indicator. "
            "This is an unknown research outcome, not a clean verdict. No research document or citation was returned."
        )
        if source_outcomes:
            answer += "\n\nSource checks: " + "; ".join(source_outcomes[:12]) + "."
        else:
            answer += " Per-source outcome details were unavailable for this request."
        return answer

    failures = [
        result for result in results
        if isinstance(result.data, dict) and result.data.get("error")
    ]
    if not failures:
        return None

    priority_request = bool(re.search(r"\b(?:highest\s+priority|priority\s+endpoint|what\s+should\s+i\s+investigate\s+first)\b", prompt, re.I))
    if priority_request:
        lines = [
            "I couldn't identify the highest-priority endpoint because a scoped evidence request was rejected.",
            "I won't substitute a high-volume conversation for a priority assessment or infer compromise from partial results.",
        ]
    else:
        lines = [
            "I couldn't complete the endpoint investigation because a scoped evidence request was rejected.",
            "No endpoint conclusion was produced from that failed request.",
        ]

    completed = [
        result.summary.strip() for result in results
        if result not in failures and result.complete and not result.truncated and result.summary.strip()
    ]
    if completed:
        lines.extend(["", "**Completed evidence checks**"])
        lines.extend(f"- {summary}" for summary in dict.fromkeys(completed) if summary)

    if priority_request:
        next_step = "Next: ask me to list the scoped findings, then we can rank an endpoint using WatchTower's priority assessment."
    else:
        next_step = "Next: retry the request, or ask me to inspect a specific alert or flow from the selected capture."
    lines.extend(["", next_step])
    return "\n".join(lines)


def render_priority_answer(result: ToolResult, finding_results=()) -> Optional[str]:
    """Render exact-scope V2 ranking without substituting traffic volume or model judgment."""
    data = result.data
    if result.tool != "priority_endpoints" or not isinstance(data, dict):
        return None
    endpoints = data.get("top_endpoints") or []
    limitations = list(dict.fromkeys(
        [*(result.limitations or []), *(data.get("scope_limitations") or [])]
    ))
    if not endpoints:
        text = "WatchTower could not rank an endpoint: no observed endpoints were available in the selected capture scope."
    else:
        score = endpoints[0].get("priority_score")
        ips = [str(row.get("ip")) for row in endpoints if row.get("ip")]
        tie_count = max(len(ips), int(data.get("top_tie_count") or len(ips)))
        score_text = f"{score:g}" if isinstance(score, (int, float)) else "unavailable"
        text = (
            f"WatchTower's V2 assessment found {tie_count} endpoint(s) tied for the highest observed "
            f"investigation-priority score ({score_text})."
        )
        if ips:
            text += f" Endpoints: {', '.join(f'**{ip}**' for ip in ips)}"
            if tie_count > len(ips):
                text += f" (showing {len(ips)} of {tie_count} tied endpoints)"
            text += "."
        total = int(data.get("observed_endpoint_count") or 0)
        text += f" The selected scope contained {total} observed endpoint(s)."
        if tie_count > 1:
            text += " There is no unique first endpoint from this ranking."
        if score == 0:
            text += " A zero score is not a clean bill of health; it means this assessment did not assign priority signals in this scope."
        text += " Priority is based on WatchTower's V2 assessment, not traffic volume, and a score alone does not establish compromise."
    findings = [
        item for result_item in finding_results
        if isinstance(result_item.data, list)
        for item in result_item.data if isinstance(item, dict)
    ]
    uncalibrated_count = sum(
        1 for item in findings
        if str(item.get("calibration_state") or "UNCALIBRATED").upper() == "UNCALIBRATED"
    )
    if uncalibrated_count:
        qualifier = "At least " if any(not item.complete or item.truncated for item in finding_results) else ""
        text += (
            f" The selected capture also contains {qualifier}{uncalibrated_count} finding(s) marked UNCALIBRATED; "
            "those findings are not calibrated priority evidence and should be reviewed directly."
        )
        top_endpoints = data.get("top_endpoints") or []
        if top_endpoints and all(str(row.get("risk_level") or "").upper() == "LOW" for row in top_endpoints):
            text += " The LOW V2 band does not negate those findings or make this capture clean."
    if limitations:
        text += "\n\nLimitations: " + " ".join(limitations)
    return text


def render_investigation_followup(results, prompt: str) -> Optional[str]:
    """Answer referential severity/evidence questions from a prior same-scope investigation."""
    if not re.search(r"\b(?:why|what evidence|which evidence|explain|tell me more|what does)\b", prompt, re.I):
        return None
    if not re.search(r"\b(?:it|that|this|they|those|them)\b", prompt, re.I):
        return None
    result = next((
        item for item in reversed(list(results or []))
        if item.tool == "investigate" and isinstance(item.data, dict)
        and item.data.get("target") and not item.data.get("error")
    ), None)
    if result is None:
        return None
    data = result.data
    groups = [item for item in data.get("alert_groups", []) if isinstance(item, dict)]
    if not groups:
        return (
            f"WatchTower's stored investigation for **{data['target']}** has no alert groups to explain the "
            "severity label. I can't justify the label from the retained structured evidence."
        )
    ordered = sorted(
        groups,
        key=lambda item: _SEVERITY_ORDER.get(str(item.get("max_severity") or "").casefold(), 5),
    )
    verdict = str(data.get("verdict") or "assessment").upper()
    lines = [
        f"WatchTower's stored investigation labeled **{data['target']}** **{verdict}** because it returned these scoped alert groups:"
    ]
    for group in ordered[:12]:
        severity = str(group.get("max_severity") or "unrated").upper()
        kind = str(group.get("type") or "unclassified finding")
        try:
            count = max(0, int(group.get("count") or 0))
        except (TypeError, ValueError, OverflowError):
            count = 0
        label = "alert" if count == 1 else "alerts"
        refs = group.get("refs") if isinstance(group.get("refs"), list) else []
        evidence = f" Evidence: {', '.join(str(ref) for ref in refs[:5])}." if refs else ""
        lines.append(f"- **{severity} — {kind}**: {count} {label}.{evidence}")
    lines.extend([
        "The severity is WatchTower's detection assessment, not proof of compromise.",
    ])
    limitations = list(result.limitations or [])
    if limitations:
        lines.append("Limitations: " + " ".join(dict.fromkeys(limitations)))
    return "\n".join(lines)

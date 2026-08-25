"""Claim-level validation for analyst answers.

This is deliberately conservative and deterministic. It does not try to prove
general language; it removes unsupported concrete endpoint and numeric claims,
then exposes the remaining uncertainty to the operator.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from typing import Iterable

from core.ai.contracts import ToolResult
from core.ai.redaction import redact_text, redact_value


@dataclass(frozen=True)
class ValidationReport:
    text: str
    status: str
    supported_claims: int
    inferred_claims: int
    blocked_claims: int
    numeric_accuracy: float
    citation_coverage: float


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_NUMBER_RE = re.compile(r"(?<![A-Za-z])\d+(?:\.\d+)?%?(?![A-Za-z])")
_NETWORK_WORDS = re.compile(r"\b(network|ip|flow|alert|finding|endpoint|entities|entity|risk|traffic|session|host|identity|score|bytes?|packets?)\b", re.I)


def _verified_fact_lines(results: Iterable[ToolResult]) -> tuple[list[str], int]:
    lines = []
    endpoint_count = None
    for result in results:
        data = result.data
        for fact in result.facts:
            value = json.dumps(fact.value, sort_keys=True, default=str) if isinstance(fact.value, (dict, list)) else str(fact.value)
            lines.append(f"- {fact.subject} {fact.predicate}: {value} [{fact.fact_id}]")
        if not isinstance(data, dict):
            continue
        if "endpoints" in data or "observed_addresses" in data:
            endpoint_count = int(data.get("endpoints", data.get("observed_addresses", 0)) or 0)
            labels = (
                ("observed_addresses", "observed addresses"),
                ("confirmed_endpoints", "confirmed endpoints"),
                ("probable_endpoints", "probable endpoints"),
                ("unconfirmed_targets", "unconfirmed targets"),
                ("address_only", "address-only endpoints"),
                ("evidence_backed_identities", "evidence-backed identities"),
                ("actionable_identities", "actionable identities"),
            )
            lines.extend(f"- Identity {label}: {int(data.get(key) or 0)}" for key, label in labels if key in data)
        if "flow_count" in data or "packet_count" in data:
            for key, label in (("flow_count", "flows"), ("packet_count", "packets"), ("byte_count", "bytes")):
                if key in data:
                    lines.append(f"- Session {label}: {int(data.get(key) or 0)}")
        if "status" in data and "queue_lag_ms" in data:
            lines.append(f"- Pipeline status: {data.get('status')}; queue lag: {data.get('queue_lag_ms')} ms")
    return lines, endpoint_count or 0


def _evidence_text(results: Iterable[ToolResult]) -> str:
    return json.dumps([
        {"data": redact_value(item.data), "facts": [
            {"subject": fact.subject, "predicate": fact.predicate, "value": redact_value(fact.value), "fact_id": fact.fact_id}
            for fact in item.facts
        ]}
        for item in results
    ], sort_keys=True, default=str)


def validate_answer(text: str, results: Iterable[ToolResult], *, mode: str = "investigate") -> ValidationReport:
    answer = redact_text(text or "", 12000).strip()
    collected = list(results)
    serialized = _evidence_text(collected)
    available_ips = set()
    for value in _IP_RE.findall(serialized):
        try:
            ipaddress.ip_address(value)
            available_ips.add(value)
        except ValueError:
            pass

    blocked = 0
    known_fact_ids = {fact.fact_id for result in collected for fact in result.facts}
    if mode != "general" and re.search(r"[\{\[]\s*[\"'](?:name|tool)[\"']\s*:", answer):
        answer = "The provider returned a tool request as final text instead of a completed analyst answer. No unsupported tool action was executed."
        blocked += 1
    sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", answer) if part.strip()]
    cleaned = []
    evidence_numbers = set(_NUMBER_RE.findall(serialized))
    verified_lines, endpoint_count = _verified_fact_lines(collected)
    for sentence in sentences:
        for fact_id in re.findall(r"fact:[A-Za-z0-9_-]+", sentence):
            if fact_id not in known_fact_ids:
                blocked += 1
                sentence = sentence.replace(fact_id, "[unsupported fact reference removed]")
        unsupported_ips = [value for value in _IP_RE.findall(sentence) if value not in available_ips]
        if unsupported_ips:
            blocked += len(unsupported_ips)
            for value in unsupported_ips:
                sentence = sentence.replace(value, "[unsupported endpoint claim removed]")
        if mode != "general" and _NETWORK_WORDS.search(sentence):
            if endpoint_count and re.search(r"\b(no|zero|none|not any|(?:has )?not identified)\b.*\b(identity|identities|endpoint|endpoints|entities)\b", sentence, re.I):
                blocked += 1
                sentence = "[contradictory identity claim removed; verified endpoint coverage is shown below]"
            numbers = [value for value in _NUMBER_RE.findall(sentence) if value not in {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}]
            unsupported_numbers = [value for value in numbers if value.rstrip("%") not in evidence_numbers]
            if unsupported_numbers and any(word in sentence.casefold() for word in ("count", "total", "score", "risk", "bytes", "packets", "%")):
                blocked += 1
                sentence = "[unsupported numeric claim removed; bounded evidence did not contain the stated value]"
        cleaned.append(sentence)
    answer = "\n".join(cleaned).strip()
    if not answer:
        answer = "The analyst could not prove a concrete claim from the bounded evidence collected."

    citations = [citation for result in collected for citation in result.citations]
    native = [item.reference for item in citations if item.kind == "watchtower"]
    external = [item.reference for item in citations if item.kind == "external"]
    if native and "watchtower evidence:" not in answer.casefold():
        answer += "\n\nWatchTower evidence:\n" + "\n".join(f"- {item}" for item in native[:12])
    if external and "external research:" not in answer.casefold():
        answer += "\n\nExternal research:\n" + "\n".join(f"- {item}" for item in external[:12])
    if citations and "analyst inference:" not in answer.casefold():
        answer += "\n\nAnalyst inference: Treat interpretation as guidance, not proof beyond the cited records."
    if verified_lines and "verified watchtower facts:" not in answer.casefold():
        answer += "\n\nVerified WatchTower facts:\n" + "\n".join(verified_lines[:20])
    if blocked:
        answer += "\n\nValidation warning: one or more unsupported concrete claims were removed. Review visibility limits before drawing conclusions."

    meaningful = [part for part in cleaned if not part.startswith("[") and _NETWORK_WORDS.search(part)]
    supported = max(0, len(meaningful) - blocked)
    inferred = sum(1 for part in cleaned if re.search(r"\b(likely|may|could|inference|appears)\b", part, re.I))
    coverage = 1.0 if not meaningful else round(min(1.0, len(citations) / max(1, len(meaningful))), 2)
    return ValidationReport(answer, "degraded" if blocked or (meaningful and not citations) else "validated",
                            supported, inferred, blocked, 0.0 if blocked else 1.0, coverage)

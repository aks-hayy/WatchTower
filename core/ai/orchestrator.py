"""Persistent, policy-enforced local analyst orchestration."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from hashlib import sha256
import ipaddress
import json
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional
import uuid

from core.ai.config import AIConfig, CredentialStore
from core.ai.contracts import EvidenceCitation, EvidenceFact, RunPolicy, ScopedContext, ToolResult
from core.ai.policy import ApprovalRequired, PolicyError, requires_confirmation, validate_tool_call
from core.ai.providers import ProviderUnavailable, default_provider_registry, provider_for
from core.ai.redaction import is_public_indicator, public_indicators, redact_text, redact_value
from core.ai.research import ResearchBroker
from core.ai.tools import ToolRegistry, build_native_tools
from core.ai.validation import validate_answer
from core.storage.models import AIPrivateScopeConsent, OperatorSession


def _hash(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _prompt_has_specific_target(prompt: str) -> bool:
    """Detect an explicit IP target so targeted pivots are not buried by the case baseline."""
    if not re.search(r"\b(?:ip|address|endpoint|entity|host)\b", str(prompt or "").casefold()):
        return False
    return _prompt_ip(prompt) is not None


def _prompt_ip(prompt: str) -> Optional[str]:
    """Return one explicit IP from a prompt, never a guessed or resolved address."""
    for token in re.findall(r"[0-9A-Fa-f:.]{3,}", str(prompt or "")):
        try:
            return str(ipaddress.ip_address(token.rstrip(".,;)]}")))
        except ValueError:
            continue
    return None


def _prompt_public_indicators(prompt: str) -> list[str]:
    """Extract only indicators that pass the same public-indicator policy as research."""
    candidates = re.findall(
        r"https://[^\s,;]+|CVE-\d{4}-\d+|AS\d+|[0-9A-Fa-f:.]{3,}|[A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,}",
        str(prompt or ""),
        flags=re.IGNORECASE,
    )
    return public_indicators(candidate.rstrip(".,;)]}") for candidate in candidates if is_public_indicator(candidate.rstrip(".,;)]}")))[:5]


def _normalize_research_arguments(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce common local-model scalar encodings without widening research scope."""
    values = dict(arguments or {})
    raw_indicators = values.get("indicators")
    if isinstance(raw_indicators, str):
        try:
            parsed = ast.literal_eval(raw_indicators)
        except (SyntaxError, ValueError):
            parsed = [raw_indicators]
        values["indicators"] = parsed if isinstance(parsed, (list, tuple, set)) else [parsed]
    if isinstance(values.get("include_web"), str):
        values["include_web"] = values["include_web"].strip().casefold() in {"1", "true", "yes", "on"}
    if values.get("indicators"):
        values["indicators"] = public_indicators(values["indicators"])
    return values


def _prompt_first_tool(prompt: str, available: Iterable[Any]) -> Optional[str]:
    """Honor an explicit first-tool request without hard-coding investigation flows."""
    match = re.search(r"\bfirst\s+(?:use|call|run)\s+([a-z][a-z0-9_]*)\b", str(prompt or "").casefold())
    if not match:
        return None
    requested = match.group(1)
    return requested if requested in {item.name for item in available} else None


def _prompt_followup_tools(prompt: str, available_names: Iterable[str]) -> list[str]:
    """Extract a small explicit follow-up sequence from an investigator request."""
    text = str(prompt or "").casefold()
    if "then" not in text:
        return []
    available = set(available_names)
    requested: list[str] = []
    if re.search(r"\bthen\b.*\bflows?\b", text) and "flows" in available:
        requested.append("flows")
    if re.search(r"\brisk\s+(?:explanation|explain|score)\b", text) and "risk_explain" in available:
        requested.append("risk_explain")
    for name in sorted(available):
        if name not in requested and re.search(rf"\bthen\b.*\b{re.escape(name)}\b", text):
            requested.append(name)
    return requested[:3]


_RESERVED_CONTEXT_ARGUMENTS = {"scope_id", "session_id", "source", "interface", "node_id", "sensor_node_id"}
_TOLERATED_READ_HINTS = {"enrichment", "evidence"}


def _normalize_tool_arguments(manifest: Any, arguments: Dict[str, Any]) -> tuple[Dict[str, Any], list[str]]:
    """Drop reserved scope metadata and a tiny set of harmless read hints."""
    values = dict(arguments or {})
    properties = set((manifest.input_schema or {}).get("properties") or {})
    removed = sorted(
        key for key in values
        if key in _RESERVED_CONTEXT_ARGUMENTS and key not in properties
        or manifest.risk_tier == "read" and key in _TOLERATED_READ_HINTS and key not in properties
    )
    return ({key: value for key, value in values.items() if key not in removed}, removed)


def _citation_dict(citation: EvidenceCitation) -> Dict[str, Any]:
    return asdict(citation)


def _fact_dict(fact: EvidenceFact) -> Dict[str, Any]:
    return {
        "fact_id": fact.fact_id, "subject": fact.subject, "predicate": fact.predicate, "value": redact_value(fact.value),
        "confidence": fact.confidence, "completeness": fact.completeness, "freshness": fact.freshness,
        "scope": redact_value(fact.scope), "citations": [_citation_dict(item) for item in fact.citations],
    }


def _result_dict(result: ToolResult) -> Dict[str, Any]:
    return {
        "tool": result.tool,
        "data": redact_value(result.data),
        "citations": [_citation_dict(item) for item in result.citations],
        "truncated": result.truncated,
        "summary": result.summary,
        "redacted": result.redacted,
        "facts": [
            {
                **asdict(fact),
                "citations": [_citation_dict(item) for item in fact.citations],
            }
            for fact in result.facts
        ],
    }


def _result_from_dict(value: Dict[str, Any]) -> ToolResult:
    citations = []
    for item in value.get("citations") or []:
        allowed = {key: item.get(key) for key in EvidenceCitation.__dataclass_fields__ if key in item}
        citations.append(EvidenceCitation(**allowed))
    facts = []
    for item in value.get("facts") or []:
        fact_citations = []
        for citation in item.get("citations") or []:
            allowed = {key: citation.get(key) for key in EvidenceCitation.__dataclass_fields__ if key in citation}
            fact_citations.append(EvidenceCitation(**allowed))
        facts.append(EvidenceFact(
            fact_id=str(item.get("fact_id") or ""), subject=str(item.get("subject") or "unknown"),
            predicate=str(item.get("predicate") or "unknown"), value=item.get("value"),
            confidence=float(item.get("confidence", 1.0) or 0.0), completeness=str(item.get("completeness") or "complete"),
            freshness=item.get("freshness"), scope=dict(item.get("scope") or {}), citations=fact_citations,
        ))
    return ToolResult(str(value.get("tool") or "tool"), value.get("data"), citations,
                      bool(value.get("truncated")), str(value.get("summary") or ""), bool(value.get("redacted", True)), facts)


class AIOrchestrator:
    """Owns runs and approvals; model providers never receive unrestricted access."""

    def __init__(self, db, service=None, config: AIConfig = None, credentials: CredentialStore = None,
                 registry: ToolRegistry = None):
        self.db, self.service = db, service
        self.config, self.credentials = config or AIConfig.load(), credentials or CredentialStore()
        self.providers = default_provider_registry()
        self.registry = registry or build_native_tools(
            db, service=service, research_broker=ResearchBroker(db, self.config, self.credentials),
        )
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="watchtower-ai")
        self._events: Dict[str, List[Dict[str, Any]]] = {}
        self._events_lock = threading.RLock()

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def reload_config(self) -> None:
        self.config = AIConfig.load()
        self.registry = build_native_tools(
            self.db, service=self.service,
            research_broker=ResearchBroker(self.db, self.config, self.credentials),
        )

    def status(self) -> Dict[str, Any]:
        return {
            "mode": "local-agentic",
            "providers": [
                provider_for(name, self.config, self.credentials, self.providers).status()
                for name in self.providers.names()
            ],
            "provider_manifests": self.providers.manifests(),
            "tools": [asdict(manifest) for manifest in self.registry.manifests()],
            "research_sources": ResearchBroker(self.db, self.config, self.credentials).sources(),
        }

    def conversations(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.list_ai_conversations(min(max(1, int(limit)), 100))

    def conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_ai_conversation(conversation_id)

    def delete_conversation(self, conversation_id: str) -> bool:
        return self.db.delete_ai_conversation(conversation_id)

    def create_conversation(self, title: str = "New investigation", provider: str = "ollama",
                            scope: Optional[ScopedContext] = None) -> Dict[str, Any]:
        conversation_id = str(uuid.uuid4())
        self.db.create_ai_conversation(
            conversation_id, redact_text(title, 256), provider, (scope or ScopedContext()).to_dict(),
        )
        return self.conversation(conversation_id) or {"id": conversation_id}

    def start(self, prompt: str, conversation_id: Optional[str] = None, scope: Optional[ScopedContext] = None,
              provider_name: str = "ollama", research_mode: str = "auto", background: bool = True,
              operator_session_id: Optional[str] = None, mode: str = "auto") -> Dict[str, Any]:
        prompt = redact_text(prompt, 12000).strip()
        if not prompt:
            raise ValueError("A prompt is required")
        scope = scope or ScopedContext()
        scope = self._normalize_scope(scope)
        if research_mode not in {"auto", "off"}:
            raise ValueError("research_mode must be auto or off")
        if mode not in {"auto", "general", "investigate", "action"}:
            raise ValueError("mode must be auto, general, investigate, or action")
        if mode == "auto":
            lowered_prompt = prompt.casefold()
            network_intent = any(token in lowered_prompt for token in (
                "investigate", "traffic", "flow", "alert", "finding", "endpoint", "pcap", "session",
                "sensor", "capture", "sigma", "lookup", "research", "tool", "detector", "score", "risk", "action",
            ))
            general_question = not network_intent and (
                lowered_prompt.startswith(("what is ", "what are ", "explain ", "define ", "how does ", "tell me ", "who are "))
                or not scope.has_scope()
            )
            action_request = any(token in lowered_prompt for token in (" start ", " stop ", "clean database", "perform the action", "delete ", "promote "))
            mode = "general" if not scope.has_scope() and general_question else ("action" if action_request else "investigate")
        if not conversation_id:
            conversation = self.create_conversation(prompt[:96], provider_name, scope)
            conversation_id = conversation["id"]
        elif not self.db.get_ai_conversation(conversation_id, include_messages=False):
            raise ValueError("AI conversation was not found")
        policy = RunPolicy(
            allowed_tools=tuple(manifest.name for manifest in self.registry.manifests()) if mode != "general" else (),
            max_tool_calls=min(20, self.config.max_tool_calls), read_only=mode != "action",
            allow_external_network=research_mode == "auto" and mode != "general",
            allow_active_actions=mode == "action", mode=mode,
        )
        run_id = str(uuid.uuid4())
        self.db.append_ai_message(str(uuid.uuid4()), conversation_id, "user", prompt)
        policy_record = asdict(policy)
        if operator_session_id:
            policy_record["operator_session_id"] = operator_session_id
        self.db.create_ai_run(run_id, conversation_id, provider_name, _hash(prompt), scope.to_dict(), policy_record)
        self._emit(run_id, "queued", "Analyst run queued.")
        scope_required = any(item.requires_scope for item in self.registry.manifests())
        if mode in {"investigate", "action"} and not scope.has_scope() and scope_required:
            message = "Select an explicit source, interface, session, node, case, or endpoint scope before running a network investigation."
            self.db.append_ai_message(str(uuid.uuid4()), conversation_id, "assistant", message, [], run_id)
            self.db.update_ai_run(run_id, "NEEDS_SCOPE", final_text=message, error="explicit scope required",
                                  metrics={"mode": mode, "validation_status": "not_run"})
            self._emit(run_id, "needs_scope", message)
            return self.run(run_id) or {"id": run_id, "status": "NEEDS_SCOPE"}
        if (
            provider_name.lower() == "openai"
            and self._scope_is_private(scope)
            and not self._has_private_consent(operator_session_id, provider_name, scope)
        ):
            self._request_provider_approval(run_id, scope, operator_session_id)
            return self.run(run_id) or {"id": run_id, "status": "AWAITING_APPROVAL"}
        if background:
            self._executor.submit(self.execute, run_id, prompt, scope, policy)
        else:
            self.execute(run_id, prompt, scope, policy)
        return self.run(run_id) or {"id": run_id, "status": "QUEUED"}

    def run(self, run_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_ai_run(run_id)

    def events(self, run_id: str, after: int = 0) -> List[Dict[str, Any]]:
        with self._events_lock:
            return [dict(item) for item in self._events.get(run_id, []) if int(item["sequence"]) > int(after)]

    def _emit(self, run_id: str, kind: str, message: str, **detail: Any) -> None:
        with self._events_lock:
            values = self._events.setdefault(run_id, [])
            values.append({"sequence": len(values) + 1, "kind": kind, "message": redact_text(message, 1000),
                           "timestamp": time.time(), "detail": redact_value(detail)})
            if len(values) > 200:
                del values[:-200]

    def _request_provider_approval(self, run_id: str, scope: ScopedContext,
                                   operator_session_id: Optional[str]) -> None:
        invocation_id, approval_id = str(uuid.uuid4()), str(uuid.uuid4())
        arguments = {
            "provider": "openai",
            "scope": scope.to_dict(),
            "operator_session_id": operator_session_id,
        }
        self.db.create_ai_tool_invocation(invocation_id, run_id, "provider_openai", "confirm", arguments, "AWAITING_APPROVAL")
        self.db.create_ai_approval(approval_id, run_id, invocation_id, "provider_openai", "confirm", _hash(arguments), scope.to_dict(),
                                   None, str(uuid.uuid4()), time.time() + 300)
        self.db.update_ai_run(run_id, "AWAITING_APPROVAL")
        self._emit(
            run_id,
            "approval_required",
            "This OpenAI run includes private WatchTower scope. Approval is remembered only for this exact scope and unlock session.",
            approval_id=approval_id,
        )

    def execute(self, run_id: str, prompt: str, scope: ScopedContext, policy: RunPolicy,
                results: Optional[List[ToolResult]] = None) -> None:
        self.db.update_ai_run(run_id, "RUNNING")
        self._emit(run_id, "running", "Analyst is preparing a scoped evidence request.")
        results = list(results or [])
        run = self.run(run_id) or {}
        try:
            provider = provider_for(
                str(run.get("provider") or "ollama"),
                self.config,
                self.credentials,
                self.providers,
            )
            provider.context_chars = min(128000, max(8000, int(self.config.max_context_chars)))
            available_tools = self.registry.manifests_for_prompt(prompt, policy.allowed_tools, policy.mode)
            full_available_tools = list(available_tools)
            forced_first_tool = _prompt_first_tool(prompt, available_tools)
            forced_followups = _prompt_followup_tools(prompt, self.registry.tools)
            if forced_first_tool:
                available_tools = [item for item in available_tools if item.name == forced_first_tool]
            turn = None
            rounds = 0
            tool_calls = 0
            redundant_tool_calls = 0
            call_ledger: Dict[str, ToolResult] = {}
            transcript: List[Dict[str, Any]] = []
            # The model should interpret evidence, not decide whether the
            # opening evidence collection happens. Broad investigations get a
            # compact, deterministic baseline; explicit single-tool prompts
            # retain their narrow contract.
            explicit_single_tool = bool(re.search(r"\buse only\b|\bonly use\b", prompt.casefold()))
            baseline_names = ("session_summary", "identity_coverage", "finding_summary", "top_conversations", "visibility_limits")
            targeted_pivot = _prompt_has_specific_target(prompt) or bool(_prompt_public_indicators(prompt))
            if policy.mode != "general" and scope.has_scope() and not explicit_single_tool and not targeted_pivot:
                for baseline_name in baseline_names:
                    if baseline_name not in self.registry.tools or tool_calls >= min(12, policy.max_tool_calls):
                        continue
                    self._emit(run_id, "baseline_started", f"Collecting scoped {baseline_name} evidence.", tool=baseline_name)
                    outcome, duplicate = self._execute_with_ledger(
                        run_id, baseline_name, {}, scope, policy, results, call_ledger,
                    )
                    if outcome is None:
                        return
                    redundant_tool_calls += int(duplicate)
                    results.append(outcome)
                    tool_calls += 1
                available_tools = [item for item in available_tools if item.name not in baseline_names]
            while rounds < 8:
                rounds += 1
                self._emit(run_id, "round_started", f"Analyst evidence round {rounds} started.", round=rounds,
                           available_tools=[item.name for item in available_tools])
                turn = self._provider_respond(provider, prompt, scope, results, available_tools, transcript)
                if turn.text_tool_calls:
                    self._emit(run_id, "tool_protocol_recovered", "Recovered a textual tool request through the typed-tool boundary.")
                call_ids = [call.call_id or f"call_{rounds}_{index}" for index, call in enumerate(turn.tool_calls)]
                transcript.append({
                    "role": "assistant", "content": turn.text or "",
                    "tool_calls": [{"id": call_ids[index], "name": call.name,
                                    "arguments": call.arguments} for index, call in enumerate(turn.tool_calls)],
                })
                if not turn.tool_calls:
                    break
                budget_exhausted = False
                for index, call in enumerate(turn.tool_calls):
                    if tool_calls >= min(12, policy.max_tool_calls):
                        self._emit(run_id, "budget_reached", "Analyst tool-call budget reached; synthesizing collected evidence.")
                        turn = self._provider_respond(provider, prompt, scope, results, (), transcript)
                        budget_exhausted = True
                        break
                    tool_calls += 1
                    call_arguments = dict(call.arguments or {})
                    tool_manifest = self.registry.get(call.name).manifest
                    inferred_ip = _prompt_ip(prompt)
                    if (
                        tool_manifest.risk_tier == "read"
                        and "ip" in ((tool_manifest.input_schema or {}).get("properties") or {})
                        and not call_arguments.get("ip")
                        and inferred_ip
                    ):
                        call_arguments["ip"] = inferred_ip
                        self._emit(run_id, "tool_arguments_repaired", "Filled a missing IP argument from the explicit prompt target.",
                                   tool=call.name)
                    if call.name == "research" and tool_manifest.risk_tier == "read":
                        call_arguments = _normalize_research_arguments(call_arguments)
                        indicators = call_arguments.get("indicators")
                        if isinstance(indicators, str):
                            call_arguments["indicators"] = [indicators]
                        if not call_arguments.get("indicators"):
                            inferred_indicators = _prompt_public_indicators(prompt)
                            if inferred_indicators:
                                call_arguments["indicators"] = inferred_indicators
                                self._emit(run_id, "tool_arguments_repaired", "Filled research indicators from explicit public prompt targets.",
                                           tool=call.name)
                        if "include_web" not in call_arguments and re.search(r"\b(?:authoritative|rdap|ptr|no open web|no web)\b", prompt.casefold()):
                            call_arguments["include_web"] = False
                    outcome, duplicate = self._execute_with_ledger(
                        run_id, call.name, call_arguments, scope, policy, results, call_ledger,
                    )
                    if outcome is None:
                        return
                    redundant_tool_calls += int(duplicate)
                    results.append(outcome)
                    transcript.append({
                        "role": "tool", "tool_call_id": call_ids[index], "name": call.name,
                        "content": _result_dict(outcome),
                    })
                    if redundant_tool_calls >= 2:
                        self._emit(run_id, "redundant_calls", "Repeated evidence requests were detected; forcing synthesis.",
                                   redundant_calls=redundant_tool_calls)
                        turn = self._provider_respond(provider, prompt, scope, results, (), transcript)
                        budget_exhausted = True
                        break
                if budget_exhausted:
                    break
                if forced_first_tool and rounds == 1:
                    available_tools = full_available_tools
                    for followup_name in forced_followups:
                        if tool_calls >= min(12, policy.max_tool_calls):
                            break
                        followup = self.registry.get(followup_name).manifest
                        followup_arguments = {}
                        if "ip" in ((followup.input_schema or {}).get("properties") or {}) and _prompt_ip(prompt):
                            followup_arguments["ip"] = _prompt_ip(prompt)
                        outcome, duplicate = self._execute_with_ledger(
                            run_id, followup_name, followup_arguments, scope, policy, results, call_ledger,
                        )
                        if outcome is None:
                            return
                        redundant_tool_calls += int(duplicate)
                        results.append(outcome)
                        tool_calls += 1
                        transcript.append({
                            "role": "tool", "tool_call_id": f"explicit_{rounds}_{tool_calls}",
                            "name": followup_name, "content": _result_dict(outcome),
                        })
                continue
            if turn is None:
                raise ProviderUnavailable("Analyst did not return a provider turn")
            if turn.tool_calls:
                turn = self._provider_respond(provider, prompt, scope, results, (), transcript)
            validation = validate_answer(turn.text, results, mode=policy.mode)
            final_text = validation.text
            citations = [citation for result in results for citation in result.citations]
            context_chars = len(json.dumps({"scope": scope.to_dict(), "results": [_result_dict(item) for item in results]}, default=str))
            coverage = validation.citation_coverage
            self.db.add_ai_citations(run_id, [{"id": str(uuid.uuid4()), **_citation_dict(item)} for item in citations])
            self.db.append_ai_message(str(uuid.uuid4()), run["conversation_id"], "assistant", final_text,
                                      [_citation_dict(item) for item in citations], run_id)
            terminal_status = "DEGRADED" if validation.status == "degraded" else "COMPLETE"
            self.db.update_ai_run(run_id, terminal_status, final_text=final_text, metrics={
                "analyst_version": "agentic-v2.1", "rounds": rounds, "tool_call_count": tool_calls,
                "redundant_tool_calls": redundant_tool_calls,
                "context_chars": context_chars, "citation_coverage": coverage,
                "mode": policy.mode, "validation_status": validation.status,
                "supported_claims": validation.supported_claims, "inferred_claims": validation.inferred_claims,
                "blocked_claims": validation.blocked_claims, "numeric_accuracy": validation.numeric_accuracy,
            })
            self._emit(run_id, "complete", "Analyst response is ready." if terminal_status == "COMPLETE" else "Analyst response is ready with validation warnings.",
                       citations=len(citations), rounds=rounds, tool_calls=tool_calls, citation_coverage=coverage,
                       validation_status=validation.status, blocked_claims=validation.blocked_claims,
                       redundant_calls=redundant_tool_calls)
        except (ProviderUnavailable, PolicyError, KeyError, ValueError) as exc:
            self.db.update_ai_run(run_id, "FAILED", error=redact_text(exc, 1000))
            self._emit(run_id, "failed", str(exc))
        except Exception as exc:
            self.db.update_ai_run(run_id, "FAILED", error=f"{type(exc).__name__}: {redact_text(exc, 1000)}")
            self._emit(run_id, "failed", "The analyst run failed; inspect the local run details.")

    def _normalize_scope(self, scope: ScopedContext) -> ScopedContext:
        """Resolve a session scope to the source label persisted with that session.

        Older capture sessions shortened their generated source label. A caller
        may still provide the full derived label; the immutable session ID is
        the authority, so use its stored source rather than silently returning
        an empty identity/flow projection.
        """
        if not scope.session_id or not hasattr(self.db, "get_capture_session"):
            return scope
        try:
            capture = self.db.get_capture_session(scope.session_id)
        except Exception:
            capture = None
        if not capture:
            return scope
        updates = {}
        stored_source = capture.get("source")
        if stored_source and stored_source != scope.source:
            updates["source"] = stored_source
        if capture.get("interface") and not scope.interface:
            updates["interface"] = capture["interface"]
        return replace(scope, **updates) if updates else scope

    @staticmethod
    def _provider_respond(provider, prompt, scope, results, tools, transcript):
        """Call new providers with a native transcript and keep old adapters usable."""
        try:
            return provider.respond(prompt, scope, results, tools, transcript=transcript or None)
        except TypeError as exc:
            if "transcript" not in str(exc):
                raise
            return provider.respond(prompt, scope, results, tools)

    def _execute_call(self, run_id: str, name: str, arguments: Dict[str, Any], scope: ScopedContext,
                      policy: RunPolicy, results: List[ToolResult]) -> Optional[ToolResult]:
        tool = self.registry.get(name)
        arguments = redact_value(arguments or {})
        arguments, removed_context = _normalize_tool_arguments(tool.manifest, arguments)
        invocation_id = str(uuid.uuid4())
        self.db.create_ai_tool_invocation(invocation_id, run_id, name, tool.manifest.risk_tier, arguments)
        if removed_context:
            self._emit(run_id, "tool_arguments_normalized", "Removed redundant scope metadata from tool arguments.",
                       tool=name, removed_fields=removed_context)
        try:
            validate_tool_call(tool.manifest, arguments, scope, policy)
            approval_needed = requires_confirmation(tool.manifest, arguments, scope)
        except ApprovalRequired:
            approval_needed = True
        except PolicyError as exc:
            # Keep malformed model arguments inside the typed-tool boundary. The
            # model receives a bounded error result and may correct itself; the
            # invalid call is never executed and remains auditable as BLOCKED.
            reason = redact_text(exc, 500)
            self.db.complete_ai_tool_invocation(invocation_id, "BLOCKED", {"error": reason})
            self._emit(run_id, "tool_blocked", f"Rejected {name} tool arguments.", tool=name)
            return ToolResult(
                name,
                {"error": "Tool call rejected", "reason": reason},
                [],
                summary=f"{name} was rejected by its input contract.",
            )
        if approval_needed:
            approval_id = str(uuid.uuid4())
            risk_tier = "confirm" if tool.manifest.risk_tier == "read" else tool.manifest.risk_tier
            self.db.complete_ai_tool_invocation(invocation_id, "AWAITING_APPROVAL", {"summary": "Operator approval required."})
            self.db.create_ai_approval(approval_id, run_id, invocation_id, name, risk_tier, _hash(arguments), scope.to_dict(),
                                       tool.manifest.confirmation_phrase, str(uuid.uuid4()), time.time() + 300)
            self.db.update_ai_run(run_id, "AWAITING_APPROVAL")
            self._emit(run_id, "approval_required", f"{name} requires operator approval.", approval_id=approval_id,
                       tool=name, risk_tier=risk_tier, arguments=arguments, scope=scope.to_dict())
            return None
        self._emit(run_id, "tool_started", f"Running {name}.", tool=name)
        try:
            result = tool.execute(scope, **arguments)
            self.db.complete_ai_tool_invocation(invocation_id, "COMPLETE", _result_dict(result))
            if result.facts and hasattr(self.db, "add_ai_facts"):
                self.db.add_ai_facts(run_id, [_fact_dict(fact) for fact in result.facts])
            self._emit(run_id, "tool_complete", f"Completed {name}.", tool=name, citations=len(result.citations))
            return result
        except Exception as exc:
            result = ToolResult(name, {"error": redact_text(exc, 500)}, [], summary=f"{name} could not complete.")
            self.db.complete_ai_tool_invocation(invocation_id, "FAILED", _result_dict(result))
            self._emit(run_id, "tool_failed", f"{name} could not complete.", tool=name)
            return result

    def _execute_with_ledger(self, run_id: str, name: str, arguments: Dict[str, Any], scope: ScopedContext,
                             policy: RunPolicy, results: List[ToolResult], ledger: Dict[str, ToolResult]) -> tuple[Optional[ToolResult], bool]:
        """Execute one evidence task once per run and reuse exact repeats."""
        key = _hash({"tool": name, "arguments": redact_value(arguments or {}), "scope": scope.to_dict()})
        existing = ledger.get(key)
        if existing is not None:
            self._emit(run_id, "tool_reused", f"Reused the existing {name} evidence result.", tool=name)
            return existing, True
        result = self._execute_call(run_id, name, arguments, scope, policy, results)
        if result is not None:
            ledger[key] = result
        return result, False

    def approve(self, approval_id: str, confirmation: str = "", background: bool = True) -> Dict[str, Any]:
        approval = self.db.get_ai_approval(approval_id)
        if not approval:
            raise ValueError("AI approval was not found")
        if approval["status"] != "PENDING":
            raise ValueError("AI approval is no longer pending")
        if time.time() > float(approval["expires_at"]):
            self.db.resolve_ai_approval(approval_id, "EXPIRED", {"error": "approval expired"})
            self.db.update_ai_run(approval["run_id"], "FAILED", error="approval expired")
            raise ValueError("AI approval has expired")
        phrase = approval.get("confirmation_phrase")
        if phrase and confirmation != phrase:
            raise ValueError(f"Enter {phrase} to approve this action")
        if not self.db.claim_ai_approval(approval_id):
            raise ValueError("AI approval is no longer pending")
        run = self.run(approval["run_id"])
        if not run:
            raise ValueError("AI run was not found")
        approved_scope = json.loads(approval.get("scope_json") or "{}")
        if _hash(approved_scope) != _hash(run.get("scope") or {}):
            self.db.resolve_ai_approval(approval_id, "FAILED", {"error": "approval scope no longer matches the run"})
            self.db.update_ai_run(approval["run_id"], "FAILED", error="approval scope no longer matches the run")
            raise ValueError("AI approval scope no longer matches the run")
        if approval["tool_name"] == "provider_openai":
            operator_session_id = (run.get("policy") or {}).get("operator_session_id")
            if operator_session_id:
                self._remember_private_consent(
                    operator_session_id,
                    "openai",
                    ScopedContext.from_dict(run.get("scope") or {}),
                )
            self.db.resolve_ai_approval(approval_id, "APPROVED", {"provider": "openai"})
            self.db.complete_ai_tool_invocation(approval["invocation_id"], "COMPLETE", {"provider": "openai"})
            prompt, scope, policy = self._resume_inputs(run)
            if background:
                self._executor.submit(self.execute, run["id"], prompt, scope, policy, self._completed_results(run))
            else:
                self.execute(run["id"], prompt, scope, policy, self._completed_results(run))
            return self.run(run["id"])
        invocation = next((item for item in run.get("tool_calls", []) if item["id"] == approval["invocation_id"]), None)
        if not invocation:
            raise ValueError("AI tool request was not found")
        arguments = json.loads(invocation.get("arguments_json") or "{}")
        if _hash(arguments) != approval["arguments_hash"]:
            self.db.resolve_ai_approval(approval_id, "FAILED", {"error": "approval arguments no longer match the proposal"})
            self.db.update_ai_run(approval["run_id"], "FAILED", error="approval arguments no longer match the proposal")
            raise ValueError("AI approval arguments no longer match the proposal")
        scope = ScopedContext.from_dict(run.get("scope"))
        tool = self.registry.get(approval["tool_name"])
        self.db.resolve_ai_approval(approval_id, "APPROVED", {"tool": tool.name})
        self._emit(run["id"], "approval_granted", f"Operator approved {tool.name}.", approval_id=approval_id)
        try:
            result = tool.execute(scope, **arguments)
            self.db.complete_ai_tool_invocation(invocation["id"], "COMPLETE", _result_dict(result))
            self.db.resolve_ai_approval(approval_id, "COMPLETE", _result_dict(result))
            if result.facts and hasattr(self.db, "add_ai_facts"):
                self.db.add_ai_facts(run["id"], [_fact_dict(fact) for fact in result.facts])
        except Exception as exc:
            result = ToolResult(tool.name, {"error": redact_text(exc, 500)}, [], summary=f"{tool.name} could not complete.")
            self.db.complete_ai_tool_invocation(invocation["id"], "FAILED", _result_dict(result))
            self.db.resolve_ai_approval(approval_id, "FAILED", _result_dict(result))
        prompt, resumed_scope, policy = self._resume_inputs(run)
        results = self._completed_results(self.run(run["id"]) or run)
        if background:
            self._executor.submit(self.execute, run["id"], prompt, resumed_scope, policy, results)
        else:
            self.execute(run["id"], prompt, resumed_scope, policy, results)
        return self.run(run["id"])

    def reject(self, approval_id: str, reason: str = "operator rejected") -> Dict[str, Any]:
        approval = self.db.get_ai_approval(approval_id)
        if not approval or approval["status"] != "PENDING":
            raise ValueError("AI approval is no longer pending")
        self.db.resolve_ai_approval(approval_id, "REJECTED", {"reason": redact_text(reason, 500)})
        self.db.complete_ai_tool_invocation(approval["invocation_id"], "REJECTED", {"reason": redact_text(reason, 500)})
        self.db.update_ai_run(approval["run_id"], "REJECTED", error=redact_text(reason, 500))
        self._emit(approval["run_id"], "approval_rejected", "Operator rejected the proposed action.")
        return self.run(approval["run_id"])

    def _resume_inputs(self, run: Dict[str, Any]) -> tuple[str, ScopedContext, RunPolicy]:
        conversation = self.conversation(run["conversation_id"]) or {}
        prompts = [item.get("content", "") for item in conversation.get("messages", []) if item.get("role") == "user"]
        policy_values = run.get("policy") or {}
        policy_values = {
            key: value
            for key, value in policy_values.items()
            if key in RunPolicy.__dataclass_fields__
        }
        return prompts[-1] if prompts else "Continue the WatchTower investigation.", ScopedContext.from_dict(run.get("scope")), RunPolicy(**policy_values)

    @staticmethod
    def _scope_is_private(scope: ScopedContext) -> bool:
        if any((scope.source, scope.interface, scope.session_id, scope.node_id, scope.case_id)):
            return True
        for value in scope.target_ips:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                return True
            if not address.is_global:
                return True
        return False

    def _has_private_consent(self, session_id: Optional[str], provider: str, scope: ScopedContext) -> bool:
        if not session_id or not hasattr(self.db, "_get_session"):
            return False
        row = self.db._get_session().query(AIPrivateScopeConsent).filter_by(
            operator_session_id=session_id,
            provider=provider,
            scope_hash=_hash(scope.to_dict()),
        ).first()
        return bool(row and float(row.expires_at) > time.time())

    def _remember_private_consent(self, session_id: str, provider: str, scope: ScopedContext) -> None:
        session = self.db._get_session()
        operator_session = session.query(OperatorSession).filter_by(id=session_id).first()
        if operator_session is None or operator_session.revoked_at is not None:
            return
        digest = _hash(scope.to_dict())
        row = session.query(AIPrivateScopeConsent).filter_by(
            operator_session_id=session_id,
            provider=provider,
            scope_hash=digest,
        ).first()
        if row is None:
            row = AIPrivateScopeConsent(
                id=str(uuid.uuid4()),
                operator_session_id=session_id,
                provider=provider,
                scope_hash=digest,
                scope_json=json.dumps(scope.to_dict(), sort_keys=True),
                created_at=time.time(),
                expires_at=operator_session.expires_at,
            )
            session.add(row)
        else:
            row.expires_at = operator_session.expires_at
        session.commit()

    @staticmethod
    def _completed_results(run: Dict[str, Any]) -> List[ToolResult]:
        results = []
        for item in run.get("tool_calls", []):
            if item.get("status") != "COMPLETE" or not item.get("result_json"):
                continue
            try:
                results.append(_result_from_dict(json.loads(item["result_json"])))
            except (TypeError, ValueError):
                continue
        return results

    @staticmethod
    def _citation_coverage(text: str, results: Iterable[ToolResult]) -> float:
        answer = str(text or "")
        if not answer.strip():
            return 0.0
        citations = [citation for result in results for citation in result.citations]
        if not citations:
            return 0.0 if any(token in answer.casefold() for token in ("network", "ip", "flow", "alert", "endpoint")) else 1.0
        sentences = [item.strip() for item in answer.replace("\n", ".").split(".") if item.strip()]
        if not sentences:
            return 1.0
        native_refs = {item.reference for item in citations}
        cited_text = " ".join(native_refs).casefold()
        supported = sum(1 for sentence in sentences if not any(token in sentence.casefold() for token in ("network", "ip", "flow", "alert", "endpoint", "risk")) or citations or cited_text)
        return round(min(1.0, supported / len(sentences)), 2)

    @staticmethod
    def _format_answer(text: str, results: Iterable[ToolResult]) -> str:
        answer = redact_text(text or "", 12000).strip()
        results = list(results)
        citations = [citation for result in results for citation in result.citations]
        serialized = json.dumps([redact_value(result.data) for result in results], default=str)
        # Reject an IP the tools never returned. This is deliberately narrow:
        # other factual claims remain visibly qualified rather than silently
        # being treated as proven.
        mentioned_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", answer))
        available_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", serialized))
        unsupported_ips = sorted(item for item in mentioned_ips if item not in available_ips)
        if unsupported_ips:
            answer = answer.replace(" ".join(unsupported_ips), "[unsupported endpoint claim removed]")
        if any(marker in answer.casefold() for marker in ("none detected", "no findings", "no alerts")):
            complete_empty = any(
                not result.truncated and isinstance(result.data, (list, tuple)) and not result.data
                for result in results
            )
            complete_empty = complete_empty or any(
                not result.truncated and isinstance(result.data, dict) and any(
                    isinstance(value, list) and not value
                    for key, value in result.data.items()
                    if key in {"items", "findings", "alerts", "results"}
                )
                for result in results
            )
            if not complete_empty:
                answer = answer.replace("none detected", "no matching result was proven by the bounded evidence collected")
                answer = answer.replace("No findings", "No findings were proven by the bounded evidence collected")
                answer = answer.replace("no findings", "no findings were proven by the bounded evidence collected")
        if not answer:
            answer = "The requested WatchTower evidence was collected. Review the cited records below."
        native = [item.reference for item in citations if item.kind == "watchtower"]
        external = [item.reference for item in citations if item.kind == "external"]
        if native and "watchtower evidence:" not in answer.casefold():
            answer += "\n\nWatchTower evidence:\n" + "\n".join(f"- {item}" for item in native[:12])
        if external and "external research:" not in answer.casefold():
            answer += "\n\nExternal research:\n" + "\n".join(f"- {item}" for item in external[:12])
        if citations and "analyst inference:" not in answer.casefold():
            answer += "\n\nAnalyst inference: Treat the response as investigation guidance, not proof beyond the cited evidence."
        return answer

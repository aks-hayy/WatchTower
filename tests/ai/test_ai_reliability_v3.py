import json
import pytest
import shutil
import tempfile
from pathlib import Path

from core.ai.contracts import EvidenceCitation, RunPolicy, ScopedContext, ToolCall, ToolManifest, ToolResult
from core.ai.policy import PolicyError, validate_tool_call
from core.ai.providers import _context_text, _ollama_transcript, _openai_output_text, _parse_text_tool_calls, _tool_result_item
from core.ai.orchestrator import (
    _normalize_tool_arguments,
    _normalize_research_arguments,
    _prompt_first_tool,
    _prompt_followup_tools,
    _prompt_has_specific_target,
    _prompt_ip,
    _prompt_public_indicators,
    _result_dict,
    _result_from_dict,
)
from core.ai.validation import validate_answer
from core.ai.answering import render_investigation_answer, render_tool_failure_answer
from core.ai.tools import CallableTool, EvidenceExcerptTool, ResearchTool, ToolRegistry, _session_summary, build_native_tools
from core.investigation.service import InvestigationService
from core.storage.database import WatchtowerDB
from core.storage.models import Flow


def test_general_policy_cannot_execute_watchtower_tools():
    manifest = ToolManifest("lookup", "lookup", {"type": "object", "properties": {"ip": {"type": "string"}}})
    policy = RunPolicy(allowed_tools=(), mode="general")
    try:
        validate_tool_call(manifest, {"ip": "8.8.8.8"}, ScopedContext(), policy)
    except PolicyError as exc:
        assert "General chat" in str(exc)
    else:
        raise AssertionError("general chat accepted a WatchTower tool")


def test_uuid_cannot_be_used_as_an_ip_selector():
    manifest = ToolManifest("lookup", "lookup", {"type": "object", "properties": {"ip": {"type": "string"}}})
    policy = RunPolicy(allowed_tools=("lookup",), mode="investigate")
    try:
        validate_tool_call(manifest, {"ip": "835a37fb-f793-4200-b86a-5a21bfef0a6d"}, ScopedContext(source="live"), policy)
    except PolicyError as exc:
        assert "IP address" in str(exc)
    else:
        raise AssertionError("session UUID passed the IP semantic guard")


def test_targeted_ip_prompt_is_not_treated_as_a_case_summary():
    assert _prompt_has_specific_target("Investigate IP 203.0.113.10 and pivot to its flows")
    assert not _prompt_has_specific_target("Summarize this capture session")
    assert _prompt_ip("Investigate IP 203.0.113.10") == "203.0.113.10"


def test_time_window_is_a_valid_capture_scope():
    assert ScopedContext(time_start=10.0, time_end=20.0).has_scope()


def test_ai_scope_rejects_reversed_and_non_finite_time_windows():
    for scope in (
        {"time_start": 20.0, "time_end": 10.0},
        {"time_start": float("nan")},
        {"time_end": float("inf")},
    ):
        with pytest.raises(ValueError):
            ScopedContext.from_dict(scope)


def test_sigma_hunt_receives_the_complete_capture_scope(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine

    class ScopeDB:
        def __init__(self):
            self.kwargs = None

        def get_flows(self, **kwargs):
            self.kwargs = kwargs
            return []

        def get_all_entities(self, **kwargs):
            return []

        def get_identity_observations(self, **kwargs):
            return []

    database = ScopeDB()
    engine = SigmaEngine(plugins_dir=str(tmp_path / "builtin"), custom_dir=str(tmp_path / "custom"),
                         managed_dir=str(tmp_path / "managed"), db=database)
    engine.run_hunt("pcap:test", interface="Ethernet", capture_session_id="session-1",
                    time_start=10.0, time_end=20.0, persist=False)

    assert database.kwargs["capture_session_id"] == "session-1"
    assert database.kwargs["time_start"] == 10.0
    assert database.kwargs["time_end"] == 20.0


def test_research_repair_extracts_public_indicators_only():
    assert _prompt_public_indicators("Research 1.1.1.1 and CVE-2024-1234") == ["1.1.1.1", "CVE-2024-1234"]
    assert _prompt_public_indicators("Research 192.168.1.10 and localhost") == []


def test_research_arguments_coerce_local_model_scalar_types():
    assert _normalize_research_arguments({
        "indicators": "['1.1.1.1', '192.168.1.10']", "include_web": "false",
    }) == {"indicators": ["1.1.1.1"], "include_web": False}


def test_research_arguments_drop_only_null_placeholder_for_optional_web_provider():
    assert _normalize_research_arguments({
        "indicators": ["1.1.1.1"], "include_web": False, "web_provider": "null",
    }) == {"indicators": ["1.1.1.1"], "include_web": False}
    assert _normalize_research_arguments({
        "indicators": ["1.1.1.1"], "include_web": False, "web_provider": "unsupported",
    })["web_provider"] == "unsupported"


def test_empty_research_result_is_incomplete_and_not_a_clean_indicator_verdict():
    class Broker:
        def research(self, *_args, **_kwargs):
            return []

    result = ResearchTool(Broker()).execute(
        ScopedContext(source="pcap:synthetic"),
        indicators=["1.1.1.1"], include_web=False,
    )

    assert result.data == []
    assert result.complete is False
    assert any("not evidence that the indicator is benign" in item for item in result.limitations)


def test_research_timeout_is_reported_by_source_and_marks_partial_result():
    import requests

    from core.ai.config import AIConfig
    from core.ai.research import ResearchBroker

    class TimeoutClient:
        def get(self, *_args, **_kwargs):
            raise requests.Timeout("simulated offline timeout")

    class EmptyCredentials:
        def get(self, _reference):
            return None

    broker = ResearchBroker(
        config=AIConfig(), credentials=EmptyCredentials(), client=TimeoutClient(),
    )
    result = ResearchTool(broker).execute(
        ScopedContext(source="pcap:synthetic"), indicators=["1.1.1.1"], include_web=False,
    )

    assert result.complete is False
    assert any("rdap" in item.casefold() and "timed out" in item.casefold() for item in result.limitations)
    assert not any("not benign" in item.casefold() for item in result.limitations)


def test_research_distinguishes_authoritative_no_results_from_disabled_sources():
    import json

    from core.ai.config import AIConfig
    from core.ai.research import ResearchBroker

    class EmptyPtrClient:
        def get(self, url, **_kwargs):
            if "rdap.org/ip/" in url:
                return url, json.dumps({"name": "APNIC"}).encode(), "application/json"
            return url, b'{"Status":0,"Answer":[]}', "application/json"

    broker = ResearchBroker(config=AIConfig(), client=EmptyPtrClient())
    result = ResearchTool(broker).execute(
        ScopedContext(source="pcap:synthetic"), indicators=["1.1.1.1"], include_web=False,
    )

    assert result.complete is True
    assert "dns-ptr no results" in result.summary
    assert "virustotal disabled" in result.summary
    assert "dns-ptr timed out" not in result.summary


def test_research_with_partial_documents_is_incomplete_when_one_source_times_out():
    import json
    import requests

    from core.ai.config import AIConfig
    from core.ai.research import ResearchBroker

    class PartialTimeoutClient:
        def get(self, url, **_kwargs):
            if "rdap.org/ip/" in url:
                return url, json.dumps({"name": "APNIC"}).encode(), "application/json"
            raise requests.Timeout("simulated DNS timeout")

    broker = ResearchBroker(config=AIConfig(), client=PartialTimeoutClient())
    result = ResearchTool(broker).execute(
        ScopedContext(source="pcap:synthetic"), indicators=["1.1.1.1"], include_web=False,
    )

    assert len(result.data) == 1
    assert result.complete is False
    assert any("dns-ptr" in item.casefold() and "timed out" in item.casefold() for item in result.limitations)


def test_empty_research_has_a_deterministic_unknown_answer_not_a_blank_endpoint_claim():
    result = ToolResult(
        "research", [], complete=False,
        limitations=["No external research source returned data; this is not a clean verdict."],
    )

    answer = render_tool_failure_answer([result], "Research public IP 1.1.1.1")

    assert answer is not None
    assert "No configured external source returned data" in answer
    assert "not a clean verdict" in answer
    assert "1.1.1.1" not in answer


def test_empty_research_fallback_surfaces_known_source_timeout():
    result = ToolResult(
        "research", [], complete=False,
        summary="0 external research source(s) returned. Source outcomes: rdap timed out; dns-ptr no results.",
        limitations=["Research source outcomes: rdap timed out; dns-ptr no results."],
    )

    answer = render_tool_failure_answer([result], "Research public IP 1.1.1.1")

    assert answer is not None
    assert "rdap timed out" in answer
    assert "dns-ptr no results" in answer
    assert "failures and timeouts were not reported separately" not in answer
    assert "1.1.1.1" not in answer


def test_ipv6_research_uses_the_ip6_reverse_pointer():
    from core.ai.research import _reverse_dns_name

    assert _reverse_dns_name("2001:db8::1").endswith("ip6.arpa")
    assert _reverse_dns_name("1.1.1.1") == "1.1.1.1.in-addr.arpa"


def test_explicit_first_tool_is_limited_to_the_opening_round():
    manifests = [
        ToolManifest("lookup", "lookup", {"type": "object", "properties": {}}),
        ToolManifest("flows", "flows", {"type": "object", "properties": {}}),
    ]
    assert _prompt_first_tool("First use lookup, then pivot to flows", manifests) == "lookup"
    assert _prompt_followup_tools(
        "First use lookup, then pivot to its stored flows and risk explanation.",
        {"lookup", "flows", "risk_explain"},
    ) == ["flows", "risk_explain"]


def test_compound_investigation_keeps_each_requested_capability_in_the_tool_budget():
    names = [
        "identity_coverage", "investigate", "flows", "research", "risk_explain", "identities",
        "lookup", "endpoint_processes", "finding_summary", "findings", "alerts", "timeline",
        "topology", "evidence_excerpt", "session_summary",
    ]
    registry = ToolRegistry([
        CallableTool(ToolManifest(name, name, {"type": "object", "properties": {}}), lambda scope, **args: {})
        for name in names
    ])

    offered = [item.name for item in registry.manifests_for_prompt(
        "Investigate IP 203.0.113.10, research its ownership, pivot to flows, and explain the risk score.",
        names,
    )]

    assert {"investigate", "research", "flows", "risk_explain"}.issubset(offered)


def test_only_redundant_scope_fields_are_normalized():
    manifest = ToolManifest("lookup", "lookup", {
        "type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"],
    })
    values, removed = _normalize_tool_arguments(manifest, {
        "ip": "203.0.113.10", "scope_id": "session-1", "evidence": True, "unexpected": "must remain blocked",
    })
    assert values == {"ip": "203.0.113.10", "unexpected": "must remain blocked"}
    assert removed == ["evidence", "scope_id"]
    action = ToolManifest("capture_start", "capture", {
        "type": "object", "properties": {"interface": {"type": "string"}},
    }, risk_tier="confirm")
    values, removed = _normalize_tool_arguments(action, {"interface": "Ethernet", "unexpected": True})
    assert values["unexpected"] is True
    assert removed == []


def test_json_encoded_local_model_arguments_are_normalized_before_policy_validation():
    manifest = ToolManifest("flows", "flows", {
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            "target_ips": {"type": "array", "items": {"type": "string"}},
        },
    })
    values, removed = _normalize_tool_arguments(manifest, {
        "limit": "250", "target_ips": '["127.250.0.10"]',
    })

    assert values == {"limit": 250, "target_ips": ["127.250.0.10"]}
    assert removed == []
    validate_tool_call(
        manifest, values, ScopedContext(source="pcap:synthetic"),
        RunPolicy(allowed_tools=("flows",), mode="investigate"),
    )


def test_textual_tool_request_is_recovered_only_for_offered_tools():
    offered = [ToolManifest("session_summary", "summary", {"type": "object", "properties": {}})]
    text, calls, recovered = _parse_text_tool_calls('{"name":"session_summary","arguments":{}}', offered)
    assert recovered and not text and calls[0].name == "session_summary"
    text, calls, recovered = _parse_text_tool_calls('{"name":"shell","arguments":{}}', offered)
    assert not recovered and not calls and text


def test_ollama_transcript_serializes_tool_results_as_strings():
    result = _ollama_transcript([
        {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "name": "facts", "arguments": {}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "facts", "content": {"count": 2}},
    ])
    assert result[0]["tool_calls"][0]["function"]["name"] == "facts"
    assert isinstance(result[1]["content"], str)


def test_tool_result_scope_and_limitations_survive_persistence_and_provider_serialization():
    result = ToolResult(
        "findings", {"items": [{"ip": "198.51.100.4"}]}, truncated=True,
        effective_scope={"source": "pcap:test", "interface": "Wi-Fi"}, complete=False,
        total=3, limitations=["One page returned."],
    )

    restored = _result_from_dict(_result_dict(result))
    provider_item = _tool_result_item(ToolCall("findings"), restored)
    provider_payload = json.loads(provider_item["content"])
    context_payload = json.loads(_context_text("Review findings", ScopedContext(), [restored]))

    assert restored.effective_scope == {"source": "pcap:test", "interface": "Wi-Fi"}
    assert restored.complete is False and restored.total == 3
    assert restored.limitations == ["One page returned."]
    assert provider_payload["effective_scope"] == restored.effective_scope
    assert provider_payload["limitations"] == restored.limitations
    assert context_payload["evidence"][0]["complete"] is False
    assert context_payload["evidence"][0]["total"] == 3


def test_callable_tool_propagates_scope_limitations_as_partial_results():
    limitation = "Endpoint process records lack capture-session provenance and were excluded."
    tool = CallableTool(
        ToolManifest("lookup", "lookup", {"type": "object", "properties": {}}),
        lambda scope, **args: {
            "ip": "10.1.2.3",
            "scope_limitations": [limitation],
        },
    )

    result = tool.execute(ScopedContext(source="live", session_id="capture-1"))

    assert result.complete is False
    assert result.limitations == [limitation]
    assert result.data["scope_limitations"] == [limitation]


def test_answer_validator_blocks_external_tool_attribution_without_external_citation():
    result = ToolResult(
        "investigate",
        {"summary": "2 flows and 2 alerts were observed."},
        [EvidenceCitation("investigation:1", "watchtower", "WatchTower investigation", kind="watchtower")],
    )

    answer = validate_answer(
        "This is a report likely generated by a tool such as MITRE's Threatinformer.",
        [result],
        mode="investigate",
    )

    assert "unsupported external-source attribution removed" in answer.text
    assert answer.status == "degraded"
    assert answer.blocked_claims == 1


def test_answer_validator_rejects_no_gaps_claim_when_evidence_has_limitations():
    result = ToolResult(
        "investigate",
        {"summary": "2 alerts were observed."},
        [EvidenceCitation("investigation:1", "watchtower", "WatchTower investigation", kind="watchtower")],
        complete=False,
        limitations=["Global identity was excluded because it cannot be attributed to this capture."],
    )

    answer = validate_answer("The report identifies no gaps.", [result], mode="investigate")

    assert "unsupported completeness claim removed" in answer.text
    assert answer.status == "degraded"
    assert answer.blocked_claims == 1


def test_answer_validator_rejects_empty_gaps_field_when_tool_reports_limitations():
    result = ToolResult(
        "investigate",
        {"summary": "2 alerts were observed."},
        [EvidenceCitation("investigation:1", "watchtower", "WatchTower investigation", kind="watchtower")],
        complete=False,
        limitations=["Global identity was excluded because it cannot be attributed to this capture."],
    )

    answer = validate_answer("Gaps: None.", [result], mode="investigate")

    assert "unsupported completeness claim removed" in answer.text
    assert answer.status == "degraded"
    assert answer.blocked_claims == 1


def test_answer_validator_rejects_severity_count_not_supported_by_alert_groups():
    result = ToolResult(
        "investigate",
        {
            "summary": "2 alerts were observed.",
            "alert_groups": [
                {"count": 1, "max_severity": "CRITICAL", "type": "CLEARTEXT_CREDENTIALS"},
                {"count": 1, "max_severity": "MEDIUM", "type": "TLS_PROTOCOL_MISMATCH"},
            ],
        },
        [EvidenceCitation("investigation:1", "watchtower", "WatchTower investigation", kind="watchtower")],
    )

    answer = validate_answer("The analysis identifies 2 critical alerts.", [result], mode="investigate")

    assert "unsupported alert-severity count removed" in answer.text
    assert answer.status == "degraded"
    assert answer.blocked_claims == 1


def test_completed_investigation_has_direct_evidence_first_narrative():
    result = ToolResult(
        "investigate",
        {
            "target": "198.51.100.7",
            "summary": "2 flow(s), 2 alert(s), and 1 temporal correlation support this assessment.",
            "verdict": "CRITICAL",
            "risk_score": 85.0,
            "alert_groups": [
                {"count": 1, "max_severity": "CRITICAL", "type": "CLEARTEXT_CREDENTIALS", "refs": ["alert:11"]},
                {"count": 1, "max_severity": "MEDIUM", "type": "TLS_PROTOCOL_MISMATCH", "refs": ["alert:1"]},
            ],
            "asset_profile": {
                "role": "Client / Workstation", "role_confidence": 0.62,
                "identity_completeness": 0.0,
            },
            "next_actions": ["Review alert:11 evidence", "Inspect flow:1"],
        },
        complete=False,
        limitations=["Global identity was excluded because it cannot be attributed to this capture."],
    )

    answer = render_investigation_answer(result)

    assert answer.startswith("WatchTower investigated **198.51.100.7** in the selected capture.")
    assert "**CRITICAL — CLEARTEXT_CREDENTIALS**" in answer
    assert "**MEDIUM — TLS_PROTOCOL_MISMATCH**" in answer
    assert "not proof of compromise" in answer
    assert "Global identity was excluded" in answer
    assert "Review alert:11 evidence" in answer
    assert "85.0" not in answer


def test_investigation_narrative_does_not_misstate_grouped_alert_severity_counts():
    result = ToolResult(
        "investigate",
        {
            "target": "198.51.100.7",
            "summary": "3 alerts were observed.",
            "alert_groups": [
                {"count": 3, "max_severity": "CRITICAL", "type": "MIXED_FINDINGS", "refs": ["alert:1", "alert:2", "alert:3"]},
            ],
        },
    )

    answer = render_investigation_answer(result)

    assert "3 alerts (highest recorded severity: **CRITICAL**)" in answer
    assert "3 critical alerts" not in answer


def test_endpoint_process_tool_fails_closed_when_capture_provenance_is_missing():
    class Service:
        calls = []

        def endpoint_processes(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"id": "process-1"}]

    service = Service()
    tool = build_native_tools(db=None, service=service).get("endpoint_processes")
    scope = ScopedContext(
        source="live", interface="Wi-Fi", session_id="capture-1", node_id="node-1",
        time_start=100.0, time_end=200.0, target_ips=("10.1.2.3",),
    )

    result = tool.execute(scope, ip="10.1.2.3", limit=10)

    assert service.calls == []
    assert result.data["observations"] == []
    assert result.complete is False
    assert any("session provenance" in item for item in result.limitations)


def test_endpoint_process_tool_does_not_treat_case_id_as_a_supported_scope():
    class Service:
        calls = []

        def endpoint_processes(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"id": "unrelated-process"}]

    service = Service()
    tool = build_native_tools(db=None, service=service).get("endpoint_processes")

    result = tool.execute(ScopedContext(case_id="case-1"), limit=10)

    assert service.calls == []
    assert result.data["observations"] == []
    assert result.complete is False


def test_endpoint_process_tool_propagates_time_and_target_scope_when_supported():
    class Service:
        def __init__(self):
            self.calls = []

        def endpoint_processes(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"id": "process-1"}]

    service = Service()
    tool = build_native_tools(db=None, service=service).get("endpoint_processes")
    scope = ScopedContext(
        node_id="node-1", time_start=100.0, time_end=200.0, target_ips=("10.1.2.3",),
    )

    result = tool.execute(scope, ip="10.1.2.3", limit=10)

    assert service.calls == [(("10.1.2.3", "node-1", 10), {"time_start": 100.0, "time_end": 200.0})]
    assert result.data["observations"] == [{"id": "process-1"}]
    assert result.complete is True


def test_evidence_tool_requires_capture_scope_and_passes_all_selectors():
    class Service:
        def __init__(self):
            self.calls = []

        def evidence(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"id": "artifact-1", "entity_ip": args[1]}]

    service = Service()
    tool = build_native_tools(db=None, service=service).get("evidence")
    scope = ScopedContext(
        source="pcap:test", interface="Wi-Fi", session_id="capture-1", node_id="node-1",
        time_start=100.0, time_end=200.0, target_ips=("10.1.2.3",), max_records=25,
    )

    result = tool.execute(scope, ip="10.1.2.3")

    assert service.calls == [(("pcap:test", "10.1.2.3"), {
        "interface": "Wi-Fi", "capture_session_id": "capture-1", "sensor_node_id": "node-1",
        "time_start": 100.0, "time_end": 200.0, "limit": 25,
    })]
    assert result.data["items"][0]["id"] == "artifact-1"


def test_evidence_tool_refuses_case_only_scope_and_out_of_scope_endpoint():
    class Service:
        calls = []

        def evidence(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return [{"id": "unrelated-artifact"}]

    service = Service()
    tool = build_native_tools(db=None, service=service).get("evidence")

    case_only = tool.execute(ScopedContext(case_id="case-1"), ip="10.1.2.3")
    out_of_scope = tool.execute(
        ScopedContext(source="live", target_ips=("10.1.2.3",)), ip="10.9.8.7",
    )

    assert service.calls == []
    assert case_only.complete is False
    assert out_of_scope.complete is False
    assert any("outside the selected target scope" in item for item in out_of_scope.limitations)
    assert "0 redacted evidence" in out_of_scope.summary


def test_evidence_tool_filters_real_artifacts_by_capture_session_interface_and_time(tmp_path):
    from core.api.service import WatchtowerApiService

    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        for ip, digest, timestamp, session, interface in (
            ("10.1.2.3", "artifact-current", 150.0, "capture-current", "Wi-Fi"),
            ("10.1.2.3", "artifact-current-latest", 160.0, "capture-current", "Wi-Fi"),
            ("10.1.2.3", "artifact-session", 150.0, "capture-other", "Wi-Fi"),
            ("10.1.2.3", "artifact-interface", 150.0, "capture-current", "Ethernet"),
            ("10.1.2.3", "artifact-time", 250.0, "capture-current", "Wi-Fi"),
            ("10.9.8.7", "artifact-target", 150.0, "capture-current", "Wi-Fi"),
        ):
            db.insert_carved_file(
                entity_ip=ip, filename=f"{digest}.bin", extension="bin", sha256=digest,
                size=10, timestamp=timestamp, source="pcap:sample",
                capture_session_id=session, capture_interface=interface,
            )

        service = WatchtowerApiService(db=db)
        tool = build_native_tools(db=db, service=service).get("evidence")
        result = tool.execute(ScopedContext(
            source="pcap:sample", session_id="capture-current", interface="Wi-Fi",
            time_start=100.0, time_end=200.0, target_ips=("10.1.2.3",), max_records=1,
        ))

        assert [row["sha256"] for row in result.data["items"]] == ["artifact-current-latest"]
        assert result.complete is False
        assert any("lacking the selected" in item for item in result.limitations)
    finally:
        db.close()


@pytest.mark.parametrize("tool_name", ["lookup", "investigate"])
def test_endpoint_lookup_tools_refuse_case_only_and_out_of_scope_requests(tool_name):
    class Service:
        def __init__(self):
            self.calls = []

        def lookup(self, *args):
            self.calls.append(("lookup", args))
            return {"ip": args[0]}

        def investigate(self, *args):
            self.calls.append(("investigate", args))
            return {"ip": args[0]}

    service = Service()
    tool = build_native_tools(db=None, service=service).get(tool_name)

    case_only = tool.execute(ScopedContext(case_id="case-1"), ip="10.1.2.3")
    out_of_scope = tool.execute(
        ScopedContext(source="pcap:sample", target_ips=("10.1.2.3",)), ip="10.9.8.7",
    )
    scoped = tool.execute(ScopedContext(
        source="pcap:sample", interface="Wi-Fi", session_id="capture-1", node_id="node-1",
        time_start=100.0, time_end=200.0, target_ips=("10.1.2.3",),
    ), ip="10.1.2.3")

    assert [kind for kind, _ in service.calls] == [tool_name]
    assert service.calls[0][1] == (
        "10.1.2.3", "pcap:sample", "node-1", "Wi-Fi", "capture-1", 100.0, 200.0,
    )
    assert case_only.complete is False and out_of_scope.complete is False
    assert scoped.complete is True


def test_graph_tools_propagate_scope_and_enforce_target_allowlist():
    class Service:
        def __init__(self):
            self.calls = []

        def graph_neighborhood(self, *args):
            self.calls.append(("neighborhood", args))
            return {"nodes": []}

        def graph_path(self, *args):
            self.calls.append(("path", args))
            return {"nodes": []}

        def graph_timeline(self, *args):
            self.calls.append(("timeline", args))
            return {"items": []}

    service = Service()
    tools = build_native_tools(db=None, service=service)
    scope = ScopedContext(
        interface="Wi-Fi", session_id="capture-1", node_id="node-1", time_start=100.0,
        time_end=200.0, target_ips=("10.1.2.3", "10.1.2.4"),
    )

    neighborhood = tools.get("graph_neighborhood").execute(scope, ip="10.1.2.3", depth=2)
    path = tools.get("graph_path").execute(scope, source_ip="10.1.2.3", target_ip="10.1.2.4")
    timeline = tools.get("graph_timeline").execute(scope, ip="10.1.2.3")
    rejected = tools.get("graph_path").execute(
        scope, source_ip="10.1.2.3", target_ip="10.9.8.7",
    )

    assert service.calls == [
        ("neighborhood", ("10.1.2.3", "node-1", 2, 500, "Wi-Fi", "capture-1", 100.0, 200.0,
                           ["10.1.2.3", "10.1.2.4"])),
        ("path", ("10.1.2.3", "10.1.2.4", "node-1", "Wi-Fi", "capture-1", 100.0, 200.0)),
        ("timeline", ("10.1.2.3", "node-1", 100.0, 200.0, 500, "Wi-Fi", "capture-1")),
    ]
    assert neighborhood.complete and path.complete and timeline.complete
    assert rejected.complete is False


def test_identity_coverage_tool_passes_full_scope_and_refuses_case_only():
    class Service:
        def __init__(self):
            self.calls = []

        def identity_status(self, *args):
            self.calls.append(args)
            return {"flows": 1}

    service = Service()
    tool = build_native_tools(db=None, service=service).get("identity_coverage")
    case_only = tool.execute(ScopedContext(case_id="case-1"))
    scoped = tool.execute(ScopedContext(
        source="pcap:sample", interface="Wi-Fi", session_id="capture-1", node_id="node-1",
        target_ips=("10.1.2.3",), time_start=100.0, time_end=200.0,
    ))

    assert service.calls == [(
        "pcap:sample", "Wi-Fi", "capture-1", "node-1", ["10.1.2.3"], 100.0, 200.0,
    )]
    assert case_only.complete is False
    assert scoped.complete is True


def test_identity_coverage_database_result_respects_target_node_and_time(tmp_path):
    from core.api.service import WatchtowerApiService

    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="10.1.2.3", dst_ip="198.51.100.1", src_port=40000, dst_port=443,
                     protocol="TCP", start_time=150.0, last_seen=160.0, packet_count=2, byte_count=200,
                     source="pcap:sample", capture_session_id="capture-current",
                     capture_interface="Wi-Fi", sensor_node_id="node-current"),
                Flow(src_ip="10.1.2.3", dst_ip="198.51.100.2", src_port=40001, dst_port=443,
                     protocol="TCP", start_time=150.0, last_seen=160.0, packet_count=2, byte_count=200,
                     source="pcap:sample", capture_session_id="capture-current",
                     capture_interface="Wi-Fi", sensor_node_id="node-other"),
                Flow(src_ip="10.1.2.3", dst_ip="198.51.100.3", src_port=40002, dst_port=443,
                     protocol="TCP", start_time=250.0, last_seen=260.0, packet_count=2, byte_count=200,
                     source="pcap:sample", capture_session_id="capture-current",
                     capture_interface="Wi-Fi", sensor_node_id="node-current"),
                Flow(src_ip="10.9.8.7", dst_ip="198.51.100.4", src_port=40003, dst_port=443,
                     protocol="TCP", start_time=150.0, last_seen=160.0, packet_count=2, byte_count=200,
                     source="pcap:sample", capture_session_id="capture-current",
                     capture_interface="Wi-Fi", sensor_node_id="node-current"),
            ])

        tool = build_native_tools(db, WatchtowerApiService(db=db)).get("identity_coverage")
        result = tool.execute(ScopedContext(
            source="pcap:sample", interface="Wi-Fi", session_id="capture-current",
            node_id="node-current", target_ips=("10.1.2.3",),
            time_start=100.0, time_end=200.0,
        ))

        assert result.data["flows"] == 1
    finally:
        db.close()


def test_topology_tool_uses_only_fully_scoped_flows_and_avoids_global_entities():
    class DB:
        def __init__(self):
            self.flow_filters = None
            self.summary_filters = None

        def get_flows(self, **kwargs):
            self.flow_filters = kwargs
            return [
                {"src_ip": "10.1.2.3", "dst_ip": "198.51.100.10", "byte_count": 100, "packet_count": 2},
                {"src_ip": "10.1.2.3", "dst_ip": "198.51.100.20", "byte_count": 200, "packet_count": 3},
            ]

        def summarize_flows(self, **kwargs):
            self.summary_filters = kwargs
            return {"flow_count": 2}

    db = DB()
    tool = build_native_tools(db, service=object()).get("topology")
    scope = ScopedContext(
        source="pcap:sample", interface="Wi-Fi", session_id="capture-1", node_id="node-1",
        target_ips=("10.1.2.3",), time_start=100.0, time_end=200.0, max_records=50,
    )
    result = tool.execute(scope)
    no_scope = tool.execute(ScopedContext(case_id="case-1"))

    expected = {
        "source": "pcap:sample", "interface": "Wi-Fi", "capture_session_id": "capture-1",
        "sensor_node_id": "node-1", "target_ips": ["10.1.2.3"],
        "time_start": 100.0, "time_end": 200.0,
    }
    assert db.flow_filters == {**expected, "limit": 50}
    assert db.summary_filters == expected
    assert result.data["complete"] is True
    assert result.data["nodes"] == [
        {"id": "10.1.2.3", "label": "10.1.2.3", "type": "unknown"},
        {"id": "198.51.100.10", "label": "198.51.100.10", "type": "unknown"},
        {"id": "198.51.100.20", "label": "198.51.100.20", "type": "unknown"},
    ]
    assert no_scope.complete is False


def test_tool_result_contract_redacts_existing_scope_and_bounds_provider_limitations():
    from core.ai.contracts import ScopedContext
    from core.ai.orchestrator import _apply_tool_result_contract

    result = ToolResult(
        tool="scope_check", data={},
        effective_scope={"source": "pcap:test?api_key=secret"},
        limitations=[f"limitation {index}" for index in range(40)],
    )
    _apply_tool_result_contract(result, ScopedContext())
    provider_payload = json.loads(_tool_result_item(ToolCall("scope_check", {}), result)["content"])

    assert result.effective_scope["source"] == "pcap:test?api_key=[REDACTED]"
    assert len(provider_payload["limitations"]) <= 4


def test_evidence_excerpt_accepts_scope_limit_and_marks_its_smaller_result_cap_partial(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="192.0.2.1", dst_ip=f"198.51.100.{index}", src_port=40000 + index,
                     dst_port=443, protocol="TCP", start_time=float(index), last_seen=float(index),
                     packet_count=1, byte_count=60, source="pcap:scope")
                for index in range(1, 102)
            ])

        scope = ScopedContext(source="pcap:scope", max_records=250)
        tool = EvidenceExcerptTool(db)
        validate_tool_call(
            tool.manifest, {"limit": 250}, scope,
            RunPolicy(allowed_tools=("evidence_excerpt",), mode="investigate"),
        )

        result = tool.execute(scope, limit=250)

        assert len(result.data["items"]) == 100
        assert result.truncated is True
        assert result.complete is False
        assert any("100" in limitation for limitation in result.limitations)
    finally:
        db.close()


def test_evidence_excerpt_uses_endpoint_ip_selector_before_pagination(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="127.250.0.10", dst_ip="127.250.0.20", src_port=50000,
                     dst_port=21, protocol="TCP", start_time=1.0, last_seen=1.0,
                     packet_count=1, byte_count=60, source="pcap:scope"),
                *[
                    Flow(src_ip="192.0.2.1", dst_ip=f"198.51.100.{index}", src_port=40000 + index,
                         dst_port=443, protocol="TCP", start_time=float(index + 1), last_seen=float(index + 1),
                         packet_count=2, byte_count=120, source="pcap:scope")
                    for index in range(1, 103)
                ],
            ])

        result = EvidenceExcerptTool(db).execute(
            ScopedContext(source="pcap:scope", max_records=250),
            flow_id="127.250.0.10", limit=250,
        )

        assert [item["direction"] for item in result.data["items"]] == ["127.250.0.10 -> 127.250.0.20"]
        assert result.complete is True
        assert not result.limitations
    finally:
        db.close()


def test_answer_scope_aggregation_exposes_only_fields_shared_by_all_tools():
    from core.ai.orchestrator import _aggregate_effective_scope

    requested = ScopedContext(source="pcap:all", interface="Wi-Fi")
    first = ToolResult("flows", [], effective_scope={"source": "pcap:all", "interface": "Wi-Fi"})
    second = ToolResult("alerts", [], effective_scope={"source": "pcap:recent", "interface": "Wi-Fi"})

    assert _aggregate_effective_scope(requested, [first, second]) == {"interface": "Wi-Fi"}


def test_openai_output_text_supports_responses_message_content_when_convenience_field_is_missing():
    assert _openai_output_text({
        "output": [{"type": "message", "content": [
            {"type": "output_text", "text": "Evidence is limited."},
        ]}],
    }) == "Evidence is limited."


def test_answer_validation_removes_unsupported_endpoint_and_reports_degraded():
    report = validate_answer(
        "The endpoint 203.0.113.77 has a high risk score.",
        [ToolResult("facts", {"subject": "198.51.100.4"})],
        mode="investigate",
    )
    assert report.status == "degraded"
    assert "203.0.113.77" not in report.text
    assert report.blocked_claims >= 1


def test_answer_validation_rejects_contradictory_identity_summary():
    report = validate_answer(
        "The tool has not identified any entities in the capture.",
        [ToolResult("identity_coverage", {"endpoints": 12, "confirmed_endpoints": 4, "actionable_identities": 8})],
        mode="investigate",
    )
    assert report.status == "degraded"
    assert "not identified any entities" not in report.text
    assert "Identity confirmed endpoints: 4" in report.text


def test_general_explanation_can_use_example_ips_without_capture_evidence():
    report = validate_answer("An IPv4 address such as 8.8.8.8 identifies a host on a network.", [], mode="general")

    assert "8.8.8.8" in report.text
    assert report.status == "not_applicable"


def test_session_summary_reports_exact_flow_aggregates():
    data_dir = Path(tempfile.mkdtemp(prefix=".ai-aggregate-", dir=Path.cwd()))
    db = WatchtowerDB(data_dir=str(data_dir))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.1", src_port=40000, dst_port=443,
                     protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=4, byte_count=400,
                     source="pcap:aggregate", capture_session_id="session-1", capture_interface="Ethernet"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.2", src_port=40001, dst_port=53,
                     protocol="UDP", start_time=3.0, last_seen=4.0, packet_count=2, byte_count=120,
                     source="pcap:aggregate", capture_session_id="session-1", capture_interface="Ethernet"),
            ])
        result = _session_summary(db, ScopedContext(
            source="pcap:aggregate", interface="Ethernet", session_id="session-1",
        ))
        assert result["flow_count"] == 2
        assert result["packet_count"] == 6
        assert result["byte_count"] == 520
        assert result["bounded_rows"] == 2
        assert result["rows_limited"] is False
        assert result["protocols"] == {"TCP": 1, "UDP": 1}
    finally:
        db.close()
        shutil.rmtree(data_dir, ignore_errors=True)


def test_flow_scope_filters_target_and_time_before_pagination(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.10", src_port=1, dst_port=443,
                     protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=99, byte_count=99,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.20", src_port=2, dst_port=443,
                     protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=1, byte_count=1,
                     source="pcap:scope"),
            ])

        rows = db.get_flows(source="pcap:scope", target_ips=["198.51.100.20"],
                             time_start=9.0, time_end=12.0, limit=1)

        assert len(rows) == 1
        assert rows[0]["dst_ip"] == "198.51.100.20"
    finally:
        db.close()


def test_explicit_flow_time_scope_excludes_undated_rows_from_lists_and_aggregates(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.10", src_port=1, dst_port=443,
                     protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=3, byte_count=30,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.20", src_port=2, dst_port=443,
                     protocol="TCP", start_time=None, last_seen=None, packet_count=99, byte_count=990,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.30", src_port=3, dst_port=443,
                     protocol="TCP", start_time=10.0, last_seen=None, packet_count=2, byte_count=20,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.40", src_port=4, dst_port=443,
                     protocol="TCP", start_time=None, last_seen=11.0, packet_count=1, byte_count=10,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.50", src_port=5, dst_port=443,
                     protocol="TCP", start_time=1.0, last_seen=None, packet_count=4, byte_count=40,
                     source="pcap:scope"),
                Flow(src_ip="192.0.2.1", dst_ip="198.51.100.60", src_port=6, dst_port=443,
                     protocol="TCP", start_time=None, last_seen=20.0, packet_count=5, byte_count=50,
                     source="pcap:scope"),
            ])

        filters = {"source": "pcap:scope", "time_start": 9.0, "time_end": 12.0}
        listed = db.get_flows(**filters, limit=10)
        summarized = db.summarize_flows(**filters)
        endpoint = db.get_entity_flows("192.0.2.1", **filters, limit=10)

        expected = {"198.51.100.10", "198.51.100.30", "198.51.100.40"}
        assert {row["dst_ip"] for row in listed} == expected
        assert summarized["flow_count"] == 3
        assert summarized["packet_count"] == 6
        assert {row["dst_ip"] for row in endpoint} == expected
    finally:
        db.close()


def test_endpoint_investigation_applies_session_interface_and_time_scope(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with db.session_scope(write=True) as session:
            session.add_all([
                Flow(src_ip="198.51.100.40", dst_ip="192.0.2.1", src_port=443, dst_port=4000,
                     protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=2, byte_count=20,
                     source="pcap:scope", capture_session_id="other", capture_interface="Wi-Fi"),
                Flow(src_ip="198.51.100.40", dst_ip="192.0.2.1", src_port=443, dst_port=4001,
                     protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=3, byte_count=30,
                     source="pcap:scope", capture_session_id="wanted", capture_interface="Ethernet"),
            ])

        result = InvestigationService(db).investigate(
            "198.51.100.40", source="pcap:scope", persist=False,
            interface="Ethernet", capture_session_id="wanted", time_start=9.0, time_end=12.0,
        )

        assert len(result.evidence) == 1
        assert result.evidence[0]["details"]["capture_session_id"] == "wanted"
    finally:
        db.close()

import shutil
import tempfile
from pathlib import Path

from core.ai.contracts import RunPolicy, ScopedContext, ToolManifest, ToolResult
from core.ai.policy import PolicyError, validate_tool_call
from core.ai.providers import _ollama_transcript, _parse_text_tool_calls
from core.ai.orchestrator import (
    _normalize_tool_arguments,
    _normalize_research_arguments,
    _prompt_first_tool,
    _prompt_followup_tools,
    _prompt_has_specific_target,
    _prompt_ip,
    _prompt_public_indicators,
)
from core.ai.validation import validate_answer
from core.ai.tools import _session_summary
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


def test_research_repair_extracts_public_indicators_only():
    assert _prompt_public_indicators("Research 1.1.1.1 and CVE-2024-1234") == ["1.1.1.1", "CVE-2024-1234"]
    assert _prompt_public_indicators("Research 192.168.1.10 and localhost") == []


def test_research_arguments_coerce_local_model_scalar_types():
    assert _normalize_research_arguments({
        "indicators": "['1.1.1.1', '192.168.1.10']", "include_web": "false",
    }) == {"indicators": ["1.1.1.1"], "include_web": False}


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

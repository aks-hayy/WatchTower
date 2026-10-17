import json
import socket

import pytest

from core.ai.config import AIConfig
from core.ai.contracts import EvidenceCitation, ProviderTurn, RunPolicy, ScopedContext, ToolCall, ToolManifest, ToolResult
from core.ai.orchestrator import AIOrchestrator
from core.ai.providers import FakeProvider
from core.ai.redaction import is_public_indicator, redact_value
from core.ai.research import ResearchSafetyError, SafeHttpClient
from core.ai.tools import AITool, FlowTool, ResearchTool, ToolRegistry
from core.storage.database import WatchtowerDB


class StaticTool(AITool):
    manifest = ToolManifest("facts", "Return one stored WatchTower fact.")

    def execute(self, scope, **arguments):
        return ToolResult(
            "facts", {"subject": "198.51.100.4", "observation": "stored flow"},
            [EvidenceCitation("flow:1", "watchtower", "Stored WatchTower flow", kind="watchtower", scope=scope.to_dict())],
            summary="One stored flow returned.",
        )


class ConfirmTool(AITool):
    manifest = ToolManifest(
        "safe_action", "Perform a confirmed test action.",
        risk_tier="confirm", active=True,
    )

    def __init__(self):
        self.calls = 0

    def execute(self, scope, **arguments):
        self.calls += 1
        return ToolResult("safe_action", {"result": "completed"}, summary="Confirmed action completed.")


class SensitiveResearchTool(AITool):
    manifest = ToolManifest(
        "research", "Test external research.",
        {"type": "object", "properties": {
            "query": {"type": "string"},
            "indicators": {"type": "array", "items": {"type": "string"}},
        }},
        allows_external_network=True,
    )

    def __init__(self):
        self.calls = 0

    def execute(self, scope, **arguments):
        self.calls += 1
        return ToolResult("research", {"result": "unexpected"})


class TypedTool(AITool):
    manifest = ToolManifest(
        "typed", "Accept a bounded boolean parameter.",
        {"type": "object", "properties": {"enabled": {"type": "boolean"}}, "required": ["enabled"]},
    )

    def __init__(self):
        self.calls = []

    def execute(self, scope, **arguments):
        self.calls.append(arguments)
        return ToolResult("typed", {"enabled": arguments["enabled"]})


class StructuredInvestigationTool(AITool):
    manifest = ToolManifest(
        "investigate", "Build a scoped endpoint investigation.",
        {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]},
    )

    def execute(self, scope, **arguments):
        return ToolResult(
            "investigate",
            {
                "target": arguments["ip"],
                "summary": "2 flows and 2 alerts were observed.",
                "verdict": "CRITICAL",
                "risk_score": 85.0,
                "alert_groups": [
                    {"count": 1, "max_severity": "CRITICAL", "type": "CLEARTEXT_CREDENTIALS", "refs": ["alert:11"]},
                    {"count": 1, "max_severity": "MEDIUM", "type": "TLS_PROTOCOL_MISMATCH", "refs": ["alert:1"]},
                ],
                "next_actions": ["Review alert:11 evidence"],
            },
            complete=False,
            limitations=["Global identity was excluded because it cannot be attributed to this capture."],
        )


class PriorityTool(AITool):
    manifest = ToolManifest("priority_endpoints", "Return exact-scope V2 endpoint priorities.")

    def execute(self, scope, **arguments):
        return ToolResult(
            "priority_endpoints",
            {
                "top_endpoints": [
                    {"ip": "198.51.100.8", "priority_score": 0.0},
                    {"ip": "198.51.100.9", "priority_score": 0.0},
                ],
                "observed_endpoint_count": 2,
                "complete": True,
            },
            [EvidenceCitation("risk:scope-a", "watchtower", "Scoped V2 endpoint assessment", scope=scope.to_dict())],
        )


class PartialEvidenceTool(AITool):
    manifest = ToolManifest("partial_evidence", "Return a bounded partial evidence result.")

    def execute(self, scope, **arguments):
        return ToolResult(
            "partial_evidence",
            {
                "items": [{"ip": "198.51.100.4"}],
                "effective_scope": {
                    "source": scope.source,
                    "interface": scope.interface,
                    "session_id": scope.session_id,
                    "node_id": scope.node_id,
                    "time_start": scope.time_start,
                    "time_end": scope.time_end,
                    "target_ips": list(scope.target_ips),
                },
                "complete": False,
                "truncated": True,
                "total": 4,
                "limitations": ["Only the first page of matching evidence was returned."],
            },
            truncated=True,
            summary="One of four matching evidence records returned.",
        )


class TranscriptProvider:
    name = "ollama"

    def __init__(self):
        self.transcripts = []

    def respond(self, prompt, scope, tool_results, tools=(), transcript=None):
        self.transcripts.append(list(transcript or []))
        return ProviderTurn(text="I retained the conversation context.")


@pytest.fixture
def database(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    yield db
    db.close()


def test_analyst_persists_redacted_evidence_backed_conversation(database, monkeypatch):
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("facts")]),
        ProviderTurn(text="The captured flow supports a follow-up investigation."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StaticTool()]))

    run = analyst.start("Investigate the stored endpoint", scope=ScopedContext(source="pcap:test"), background=False)

    assert run["status"] == "COMPLETE", run.get("final_text")
    assert run["answer"]["version"] == 1
    assert run["answer"]["narrative"] == run["final_text"]
    assert "WatchTower evidence:" in run["final_text"]
    assert run["citations"][0]["reference"] == "flow:1"
    conversation = analyst.conversation(run["conversation_id"])
    assert [item["role"] for item in conversation["messages"]] == ["user", "assistant"]
    assert "reasoning" not in conversation["messages"][1]["content"].casefold()


@pytest.mark.parametrize("prompt", [
    "Research public IP 1.1.1.1",
    "Who owns 1.1.1.1?",
])
def test_scope_free_public_research_runs_with_capture_tools_registered(database, monkeypatch, prompt):
    class EmptyResearchBroker:
        def __init__(self):
            self.calls = []

        def research(self, indicators=(), query="", include_web=True, web_provider="brave"):
            self.calls.append((list(indicators), query, include_web, web_provider))
            return []

    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("research", {"indicators": ["1.1.1.1"], "include_web": False})]),
        ProviderTurn(text="No public source record was returned."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    broker = EmptyResearchBroker()
    registry = ToolRegistry([ResearchTool(broker), FlowTool(database)])
    analyst = AIOrchestrator(database, registry=registry)

    run = analyst.start(prompt, background=False)

    assert run["status"] != "NEEDS_SCOPE"
    assert run["mode"] == "investigate"
    assert len(broker.calls) == 1
    assert broker.calls[0][0] == ["1.1.1.1"]


def test_research_schema_does_not_offer_disabled_web_providers(database, monkeypatch):
    class ConfiguredResearchBroker:
        def __init__(self):
            self.config = AIConfig()
            self.calls = []

        def research(self, indicators=(), query="", include_web=True, web_provider="brave"):
            self.calls.append((list(indicators), query, include_web, web_provider))
            return []

    class SchemaAwareProvider:
        name = "ollama"

        def __init__(self):
            self.tool_schemas = []
            self.called_research = False

        def respond(self, prompt, scope, tool_results, tools=(), transcript=None):
            self.tool_schemas.append({tool.name: tool.input_schema for tool in tools})
            if not self.called_research:
                self.called_research = True
                schema = self.tool_schemas[-1]["research"]["properties"]
                arguments = {"indicators": ["1.1.1.1"], "include_web": True}
                providers = schema.get("web_provider", {}).get("enum", [])
                if providers:
                    arguments["web_provider"] = providers[0]
                return ProviderTurn(tool_calls=[ToolCall("research", arguments)])
            return ProviderTurn(text="I checked the configured public research sources.")

    broker = ConfiguredResearchBroker()
    provider = SchemaAwareProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, config=broker.config, registry=ToolRegistry([ResearchTool(broker)]))

    run = analyst.start("Research public IP 1.1.1.1", background=False)

    research_schema = provider.tool_schemas[0]["research"]["properties"]
    assert "web_provider" not in research_schema
    assert run["status"] != "AWAITING_APPROVAL", run
    assert broker.calls == [(["1.1.1.1"], "", True, "brave")]


def test_research_schema_only_offers_enabled_web_provider():
    config = AIConfig()
    config.brave.enabled = True
    config.openai.enabled = False

    tool = ResearchTool(type("Broker", (), {"config": config})())

    assert tool.manifest.input_schema["properties"]["web_provider"]["enum"] == ["brave"]


def test_public_research_plus_capture_pivot_still_requires_explicit_scope(database, monkeypatch):
    broker = SensitiveResearchTool()
    registry = ToolRegistry([broker, FlowTool(database)])
    analyst = AIOrchestrator(database, registry=registry)

    run = analyst.start(
        "Research public IP 1.1.1.1 and compare it with traffic in my capture",
        background=False,
    )

    assert run["status"] == "NEEDS_SCOPE"
    assert broker.calls == 0


def test_completed_single_ip_investigation_uses_evidence_first_shared_answer(database, monkeypatch):
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("investigate", {"ip": "198.51.100.7", "target_ips": ["198.51.100.7"]})]),
        ProviderTurn(tool_calls=[ToolCall("investigate", {"ip": "198.51.100.7"})]),
        ProviderTurn(text="This is a report generated by an unrelated threat intelligence platform."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StructuredInvestigationTool()]))

    run = analyst.start(
        "Investigate IP 198.51.100.7 and tell me what to verify next",
        scope=ScopedContext(source="pcap:test"), mode="investigate", background=False,
    )

    assert run["status"] == "DEGRADED"
    assert run["final_text"].startswith("WatchTower investigated **198.51.100.7**")
    assert "CLEARTEXT_CREDENTIALS" in run["final_text"]
    assert "Review alert:11 evidence" in run["final_text"]
    assert "Global identity was excluded" in run["final_text"]
    assert "unrelated threat intelligence platform" not in run["final_text"]


def test_unrecovered_blocked_investigation_does_not_publish_model_synthesis(database, monkeypatch):
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("investigate", {"ip": "198.51.100.7", "target_ips": ["198.51.100.7"]})]),
        ProviderTurn(text="The endpoint is confirmed compromised and is the highest-priority device."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StructuredInvestigationTool()]))

    run = analyst.start(
        "Investigate IP 198.51.100.7",
        scope=ScopedContext(source="pcap:test"), mode="investigate", background=False,
    )

    assert run["status"] == "DEGRADED"
    assert "couldn't complete the endpoint investigation" in run["final_text"].casefold()
    assert "confirmed compromised" not in run["final_text"]


def test_followup_explanation_reuses_prior_scoped_evidence_without_requery_or_model_guess(database, monkeypatch):
    class CountingProvider:
        name = "ollama"
        context_chars = 48000
        def __init__(self):
            self.calls = 0
            self.turns = [
                ProviderTurn(tool_calls=[ToolCall("investigate", {"ip": "198.51.100.7"})]),
                ProviderTurn(text="The endpoint has critical alerts."),
            ]
        def respond(self, *args, **kwargs):
            self.calls += 1
            return self.turns.pop(0)

    provider = CountingProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StructuredInvestigationTool()]))
    scope = ScopedContext(source="pcap:test")
    first = analyst.start("Investigate IP 198.51.100.7", scope=scope, mode="investigate", background=False)

    followup = analyst.start(
        "Why is it critical?", conversation_id=first["conversation_id"], background=False,
    )

    assert followup["scope"]["source"] == "pcap:test"
    assert followup["status"] == "DEGRADED"
    assert "CLEARTEXT_CREDENTIALS" in followup["final_text"]
    assert "alert:11" in followup["final_text"]
    assert "not proof of compromise" in followup["final_text"]
    assert followup["answer"]["tool_results"][0]["tool"] == "investigate"
    assert provider.calls == 2
    saved_conversation = database.get_ai_conversation(first["conversation_id"])
    assert saved_conversation["scope"]["source"] == "pcap:test"


def test_followup_with_explicit_new_scope_does_not_reuse_old_investigation(database, monkeypatch):
    class CountingProvider:
        name = "ollama"
        context_chars = 48000
        def __init__(self):
            self.calls = 0
            self.turns = [
                ProviderTurn(tool_calls=[ToolCall("investigate", {"ip": "198.51.100.7"})]),
                ProviderTurn(text="The endpoint has critical alerts."),
                ProviderTurn(text="No prior-scope evidence was reused."),
            ]
        def respond(self, *args, **kwargs):
            self.calls += 1
            return self.turns.pop(0)

    provider = CountingProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StructuredInvestigationTool()]))
    first = analyst.start(
        "Investigate IP 198.51.100.7", scope=ScopedContext(source="pcap:old"),
        mode="investigate", background=False,
    )

    followup = analyst.start(
        "Why is it critical?", conversation_id=first["conversation_id"],
        scope=ScopedContext(source="pcap:new"), background=False,
    )

    assert followup["scope"]["source"] == "pcap:new"
    assert all(item["tool"] != "investigate" for item in followup["answer"]["tool_results"])
    assert "CLEARTEXT_CREDENTIALS" not in followup["final_text"]
    assert provider.calls == 3
    assert database.get_ai_conversation(first["conversation_id"])["scope"]["source"] == "pcap:new"


def test_priority_question_uses_v2_result_and_reports_ties_not_model_guess(database, monkeypatch):
    class Provider:
        calls = 0
        context_chars = 48000
        def respond(self, *args, **kwargs):
            self.calls += 1
            return ProviderTurn(text="The highest-volume NTP host is the top priority and looks clean.")

    provider = Provider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([PriorityTool()]))

    run = analyst.start(
        "What should I investigate first?", scope=ScopedContext(source="pcap:test"), background=False,
    )

    assert run["status"] == "COMPLETE", run.get("final_text")
    assert "198.51.100.8" in run["final_text"] and "198.51.100.9" in run["final_text"]
    assert "no unique first endpoint" in run["final_text"]
    assert "not a clean bill of health" in run["final_text"]
    assert "highest-volume NTP" not in run["final_text"]
    assert provider.calls == 0


def test_investigate_highest_priority_does_not_choose_arbitrarily_from_a_tie(database, monkeypatch):
    class Provider:
        context_chars = 48000
        calls = 0
        def respond(self, *args, **kwargs):
            self.calls += 1
            return ProviderTurn(text="I selected the highest-volume endpoint and investigated it.")

    provider = Provider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([PriorityTool()]))

    run = analyst.start(
        "Investigate the highest-priority endpoint", scope=ScopedContext(source="pcap:test"), background=False,
    )

    assert run["status"] == "COMPLETE", run.get("final_text")
    assert "no unique first endpoint" in run["final_text"]
    assert "did not choose one arbitrarily" in run["final_text"]
    assert provider.calls == 0


def test_analyst_answer_preserves_effective_scope_and_partial_tool_limits(database, monkeypatch):
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("partial_evidence")]),
        ProviderTurn(text="One matching endpoint was found in the bounded evidence."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([PartialEvidenceTool()]))
    scope = ScopedContext(
        source="pcap:test", interface="Wi-Fi", session_id="session-1", node_id="sensor-1",
        time_start=10.0, time_end=20.0, target_ips=("198.51.100.4",), max_records=7,
    )

    run = analyst.start("Investigate the endpoint in this capture", scope=scope, background=False)

    expected_scope = {
        "source": "pcap:test", "interface": "Wi-Fi", "session_id": "session-1",
        "node_id": "sensor-1", "time_start": 10.0, "time_end": 20.0,
        "target_ips": ["198.51.100.4"],
    }
    assert run["status"] == "DEGRADED"
    assert run["answer"]["effective_scope"] == expected_scope
    assert run["answer"]["requested_scope"] == scope.to_dict()
    assert run["answer"]["completeness"] == "partial"
    assert run["answer"]["tool_results"] == [{
        "tool": "partial_evidence", "effective_scope": expected_scope,
        "complete": False, "truncated": True, "total": 4,
        "limitations": [
            "Only the first page of matching evidence was returned.",
            "One of four matching evidence records returned.",
        ],
    }]
    assert "Only the first page of matching evidence was returned." in run["answer"]["limitations"]
    persisted = __import__("json").loads(run["tool_calls"][0]["result_json"])
    assert persisted["effective_scope"] == expected_scope
    assert persisted["complete"] is False
    assert persisted["limitations"] == [
        "Only the first page of matching evidence was returned.",
        "One of four matching evidence records returned.",
    ]


def test_confirmed_action_never_runs_before_explicit_approval(database, monkeypatch):
    action = ConfirmTool()
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("safe_action")]),
        ProviderTurn(text="The approved action completed."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([action]))

    waiting = analyst.start("Perform the action", background=False)
    assert waiting["status"] == "AWAITING_APPROVAL"
    assert action.calls == 0
    approved = analyst.approve(waiting["approvals"][0]["id"], background=False)

    assert approved["status"] == "COMPLETE"
    assert action.calls == 1
    with pytest.raises(ValueError, match="no longer pending"):
        analyst.approve(waiting["approvals"][0]["id"], background=False)
    assert action.calls == 1


def test_private_context_never_reaches_automatic_external_research(database, monkeypatch):
    research = SensitiveResearchTool()
    provider = FakeProvider([ProviderTurn(tool_calls=[ToolCall("research", {"query": "10.0.0.8", "indicators": ["10.0.0.8"]})])])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([research]))

    run = analyst.start("Research this internal endpoint", background=False)

    assert run["status"] == "AWAITING_APPROVAL"
    assert research.calls == 0
    assert run["approvals"][0]["risk_tier"] == "confirm"


def test_research_client_rejects_private_resolution_before_http(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("127.0.0.1", 443))])
    with pytest.raises(ResearchSafetyError):
        SafeHttpClient().get("https://example.test/research")


def test_ai_config_round_trip_keeps_only_public_provider_configuration(tmp_path):
    path = tmp_path / "ai.yaml"
    config = AIConfig.load(path)
    config.openai.enabled = True
    config.openai.credential_ref = "watchtower-openai-test"
    config.save(path)

    loaded = AIConfig.load(path)
    assert loaded.openai.enabled
    assert loaded.openai.credential_ref == "watchtower-openai-test"
    assert "secret" not in path.read_text(encoding="utf-8").casefold()


def test_tool_schema_rejects_unexpected_arguments_and_preserves_boolean_types(database, monkeypatch):
    tool = TypedTool()
    provider = FakeProvider([ProviderTurn(tool_calls=[ToolCall("typed", {"enabled": False, "unsafe": "value"})])])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([tool]))

    rejected = analyst.start("Run typed tool", background=False)
    assert rejected["status"] == "DEGRADED"
    assert rejected["answer"]["completeness"] == "partial"
    assert any("rejected" in item.casefold() for item in rejected["answer"]["limitations"])
    assert rejected["tool_calls"][0]["status"] == "BLOCKED"
    blocked_result = json.loads(rejected["tool_calls"][0]["result_json"])
    assert blocked_result["effective_scope"] == rejected["scope"]
    assert blocked_result["complete"] is False
    assert tool.calls == []

    provider = FakeProvider([ProviderTurn(tool_calls=[ToolCall("typed", {"enabled": False})]), ProviderTurn(text="Done")])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    accepted = analyst.start("Run typed tool", background=False)
    assert accepted["status"] == "COMPLETE"
    assert tool.calls == [{"enabled": False}]
    assert redact_value({"enabled": False, "count": 7}) == {"enabled": False, "count": 7}


def test_public_research_identifiers_include_cves_asns_and_https_urls():
    assert is_public_indicator("CVE-2025-12345")
    assert is_public_indicator("AS13335")
    assert is_public_indicator("https://example.com/advisory")
    assert not is_public_indicator("http://example.com/advisory")
    assert not is_public_indicator("https://router.local/advisory")


def test_follow_up_provider_request_contains_persisted_conversation_history(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    first = analyst.start("Explain the selected capture", scope=ScopedContext(source="pcap:test"), background=False)
    analyst.start("What did you mean by that?", conversation_id=first["conversation_id"],
                  scope=ScopedContext(source="pcap:test"), background=False)

    assert provider.transcripts[-1][0] == {"role": "user", "content": "Explain the selected capture"}
    assert provider.transcripts[-1][1]["role"] == "assistant"
    assert provider.transcripts[-1][-1] == {"role": "user", "content": "What did you mean by that?"}


def test_duplicate_client_request_returns_same_run_without_duplicate_user_message(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    first = analyst.start("Explain this capture", client_request_id="request-1", background=False)
    duplicate = analyst.start("Explain this capture", client_request_id="request-1", background=False)

    assert duplicate["id"] == first["id"]
    conversation = analyst.conversation(first["conversation_id"])
    assert [item["role"] for item in conversation["messages"]] == ["user", "assistant"]


def test_conversation_rejects_a_second_active_run(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    conversation = analyst.create_conversation()
    database.create_ai_run("active-run", conversation["id"], "ollama", "hash", {}, {"allowed_tools": [], "mode": "general"})
    with pytest.raises(ValueError, match="active analyst run"):
        analyst.start("Do not overlap this run", conversation_id=conversation["id"], background=True)


def test_rejected_overlapping_run_does_not_change_saved_conversation_scope(database, monkeypatch):
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))
    conversation = analyst.create_conversation(scope=ScopedContext(source="pcap:original"))
    database.create_ai_run(
        "active-run", conversation["id"], "ollama", "hash", {},
        {"allowed_tools": [], "mode": "general"},
    )

    with pytest.raises(ValueError, match="active analyst run"):
        analyst.start(
            "Do not overwrite scope on a rejected run", conversation_id=conversation["id"],
            scope=ScopedContext(source="pcap:replacement"), background=True,
        )

    assert database.get_ai_conversation(conversation["id"])["scope"]["source"] == "pcap:original"


def test_educational_network_question_without_scope_stays_general(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    run = analyst.start("What is a capture session?", background=False)

    assert run["status"] == "COMPLETE"
    assert run["mode"] == "general"


def test_educational_question_does_not_investigate_just_because_live_scope_is_selected(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([StaticTool()]))

    run = analyst.start(
        "I’m new to network security. In plain language, what is a network capture, "
        "what can WatchTower learn from it, and what can’t it prove?",
        scope=ScopedContext(source="live"), background=False,
    )

    assert run["mode"] == "general"
    assert run["tool_calls"] == []
    assert run["citations"] == []
    assert run["operation"]["next_actions"] == ["Ask a follow-up, or choose an investigation prompt."]


def test_resume_inputs_use_the_run_origin_not_the_latest_conversation_message(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    first = analyst.start("Original approval question", background=False)
    analyst.start("A later unrelated question", conversation_id=first["conversation_id"], background=False)

    prompt, _scope, _policy = analyst._resume_inputs(first)
    assert prompt == "Original approval question"


def test_retry_interrupted_run_reuses_origin_and_excludes_later_conversation_turns(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))

    original = analyst.start(
        "Investigate this endpoint",
        scope=ScopedContext(source="pcap:origin", target_ips=("198.51.100.4",)),
        mode="investigate",
        background=False,
    )
    database.update_ai_run(original["id"], "INTERRUPTED", error="simulated process stop")
    analyst.start(
        "A later unrelated question",
        conversation_id=original["conversation_id"],
        scope=ScopedContext(source="pcap:later"),
        mode="general",
        background=False,
    )
    database.update_ai_run(original["id"], "INTERRUPTED", error="simulated process stop")
    user_message_count = sum(
        item["role"] == "user"
        for item in analyst.conversation(original["conversation_id"])["messages"]
    )

    retried = analyst.retry(original["id"], background=False)

    assert retried["status"] == "COMPLETE"
    assert retried["parent_run_id"] == original["id"]
    assert retried["user_message_id"] == original["user_message_id"]
    conversation = analyst.conversation(original["conversation_id"])
    assert sum(item["role"] == "user" for item in conversation["messages"]) == user_message_count
    assert provider.transcripts[-1][-1] == {"role": "user", "content": "Investigate this endpoint"}
    assert all(item.get("content") != "A later unrelated question" for item in provider.transcripts[-1])
    assert retried["scope"]["source"] == "pcap:origin"
    analyst.close()


def test_interrupted_state_changing_run_cannot_be_retried_automatically(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))
    original = analyst.start("Promote this detector", mode="action", background=False)
    database.update_ai_run(original["id"], "INTERRUPTED", error="simulated process stop")

    with pytest.raises(ValueError, match="state-changing run"):
        analyst.retry(original["id"], background=False)

    assert provider.transcripts
    assert analyst.run(original["id"])["status"] == "INTERRUPTED"
    analyst.close()


def test_cancelled_run_stays_terminal_and_is_not_restarted(database, monkeypatch):
    provider = TranscriptProvider()
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))
    conversation = analyst.create_conversation()
    database.create_ai_run("queued-run", conversation["id"], "ollama", "hash", {}, {"allowed_tools": [], "mode": "general"})

    cancelled = analyst.cancel("queued-run")

    assert cancelled["status"] == "CANCELLED"
    analyst.execute("queued-run", "should not execute", ScopedContext(), RunPolicy(allowed_tools=(), mode="general"))
    assert analyst.run("queued-run")["status"] == "CANCELLED"


def test_cancelling_pending_approval_invalidates_the_action(database, monkeypatch):
    action = ConfirmTool()
    provider = FakeProvider([ProviderTurn(tool_calls=[ToolCall("safe_action")])])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(database, registry=ToolRegistry([action]))

    waiting = analyst.start("Perform the action", mode="action", background=False)
    analyst.cancel(waiting["id"])

    with pytest.raises(ValueError, match="no longer pending"):
        analyst.approve(waiting["approvals"][0]["id"], background=False)
    assert action.calls == 0


def test_event_sequences_remain_monotonic_when_old_events_are_evicted(database):
    analyst = AIOrchestrator(database, registry=ToolRegistry([]))
    for index in range(205):
        analyst._emit("run", "progress", str(index))

    events = analyst.events("run")
    sequences = [item["sequence"] for item in events]
    assert len(events) == 200
    assert sequences == list(range(6, 206))

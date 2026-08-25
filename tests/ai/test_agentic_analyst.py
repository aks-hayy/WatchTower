import socket

import pytest

from core.ai.config import AIConfig
from core.ai.contracts import EvidenceCitation, ProviderTurn, ScopedContext, ToolCall, ToolManifest, ToolResult
from core.ai.orchestrator import AIOrchestrator
from core.ai.providers import FakeProvider
from core.ai.redaction import is_public_indicator, redact_value
from core.ai.research import ResearchSafetyError, SafeHttpClient
from core.ai.tools import AITool, ToolRegistry
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

    assert run["status"] == "COMPLETE"
    assert "WatchTower evidence:" in run["final_text"]
    assert run["citations"][0]["reference"] == "flow:1"
    conversation = analyst.conversation(run["conversation_id"])
    assert [item["role"] for item in conversation["messages"]] == ["user", "assistant"]
    assert "reasoning" not in conversation["messages"][1]["content"].casefold()


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
    assert rejected["status"] == "COMPLETE"
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

from core.ai.contracts import EvidenceCitation, ProviderTurn, ScopedContext, ToolCall, ToolManifest, ToolResult
from core.ai.orchestrator import AIOrchestrator
from core.ai.providers import FakeProvider, _context_text
from core.ai.tools import AITool, ToolRegistry
from core.storage.database import WatchtowerDB


class RoundTool(AITool):
    manifest = ToolManifest("round_facts", "Return bounded facts.")

    def execute(self, scope, **arguments):
        return ToolResult(
            "round_facts", {"subject": "198.51.100.10", "count": 2},
            [EvidenceCitation("flow:round", "watchtower", "Stored flow", scope=scope.to_dict())],
            summary="One bounded fact set returned.",
        )


def test_iterative_agent_records_rounds_and_tool_budget(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("round_facts")]),
        ProviderTurn(tool_calls=[ToolCall("round_facts")]),
        ProviderTurn(text="The stored evidence supports a follow-up investigation."),
    ])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    analyst = AIOrchestrator(db, registry=ToolRegistry([RoundTool()]))
    run = analyst.start("Investigate the endpoint and its flows", scope=ScopedContext(source="pcap:test"), background=False)
    analyst.close()
    db.close()

    assert run["status"] == "COMPLETE"
    assert run["rounds"] == 3
    assert run["tool_call_count"] == 2
    assert run["citation_coverage"] > 0


def test_context_packing_is_field_aware_and_bounded():
    value = {"items": [{"id": index, "payload": "x" * 5000} for index in range(1000)], "status": "complete"}
    result = ToolResult("evidence", value, summary="Large bounded evidence result")
    packed = _context_text("summarize", ScopedContext(source="pcap:test"), [result], max_chars=12000)

    assert len(packed) <= 12020
    assert '"items"' in packed
    assert "omitted" in packed

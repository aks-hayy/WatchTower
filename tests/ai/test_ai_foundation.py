from core.ai.contracts import (
    EvaluationCase, ProviderTurn, RunPolicy, ScopedContext, ToolCall,
)
from core.ai.evaluation import evaluate
from core.ai.providers import FakeProvider
from core.ai.session import AISession
from core.ai.tools import FlowTool, StreamTool, ToolRegistry, build_native_tools


class FakeDB:
    def get_flows(self, **kwargs):
        return [{"id": 1, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.3", "source": "pcap:test", "last_seen": 3.0}]


def test_fake_provider_tool_session_is_deterministic_and_cited():
    provider = FakeProvider([
        ProviderTurn(tool_calls=[ToolCall("flows", {"limit": 10})]),
        ProviderTurn(text="One stored flow supports the finding."),
    ])
    session = AISession(provider, ToolRegistry([FlowTool(FakeDB())]))
    run = session.run("investigate", ScopedContext(source="pcap:test"), RunPolicy(("flows",)))
    assert run.status == "COMPLETE"
    assert run.final_text.startswith("One stored flow")
    assert run.tool_results[0].citations[0].reference == "flow:1"
    result = evaluate(EvaluationCase("flow evidence", "investigate", ("flow:1",), ("flows",)), run)
    assert result.passed and result.citation_recall == 1.0


def test_ai_policy_blocks_unapproved_tools_and_has_no_reasoning_trace():
    provider = FakeProvider([ProviderTurn(tool_calls=[ToolCall("case_export", {"ip": "10.0.0.2"})])])
    session = AISession(provider, ToolRegistry([FlowTool(FakeDB())]))
    try:
        session.run("export", ScopedContext(), RunPolicy(("flows",)))
        assert False, "policy should block the call"
    except PermissionError:
        pass
    assert "reasoning" not in ProviderTurn.__dataclass_fields__
    assert "thought" not in ProviderTurn.__dataclass_fields__


def test_stream_tool_returns_bounded_cited_evidence():
    class Engine:
        def load_stream(self, flow_id, report): return {"to_server": b"abcdef", "to_client": b"reply"}
    flow_id = ("10.0.0.2", "10.0.0.3", 1234, 80, "TCP")
    result = StreamTool(Engine()).execute(ScopedContext(source="pcap:test"), flow_id=flow_id, max_bytes=3)
    assert result.truncated
    assert result.data["to_server"]["excerpt"] == "abc"
    assert "preview_base64" not in result.data["to_server"]
    assert result.citations[0].reference.startswith("stream:10.0.0.2")


def test_ai_can_propose_a_confirmation_gated_detector_scaffold():
    calls = []

    class Service:
        def plugin_scaffold_detector(self, detector_id, finding_type, input_kind, description):
            calls.append((detector_id, finding_type, input_kind, description))
            return {
                "detector_id": detector_id,
                "finding_type": finding_type,
                "status": "scaffolded_uncalibrated",
            }

    registry = build_native_tools(FakeDB(), service=Service())
    tool = registry.get("plugin_scaffold_detector")

    assert tool.manifest.risk_tier == "confirm"
    result = tool.execute(
        ScopedContext(),
        detector_id="custom.tls.downgrade",
        finding_type="tls.downgrade.suspected",
        input_kind="stream",
        description="Detect repeated TLS downgrade negotiation evidence.",
    )

    assert result.data["status"] == "scaffolded_uncalibrated"
    assert calls == [(
        "custom.tls.downgrade",
        "tls.downgrade.suspected",
        "stream",
        "Detect repeated TLS downgrade negotiation evidence.",
    )]


def test_ai_can_create_a_bounded_threshold_detector_for_calibration():
    calls = []

    class Service:
        def plugin_create_threshold_detector(self, **values):
            calls.append(values)
            return {"status": "created_uncalibrated", **values}

    registry = build_native_tools(FakeDB(), service=Service())
    tool = registry.get("plugin_create_threshold_detector")
    arguments = {
        "detector_id": "custom.flow.large",
        "finding_type": "exfil.custom.large_flow",
        "description": "Detect unusually large directional flows.",
        "metric": "byte_count",
        "operator": "gte",
        "threshold": 1048576,
        "category": "ANOMALY",
        "impact": "MEDIUM",
        "confidence_percent": 80,
    }

    assert tool.manifest.risk_tier == "confirm"
    result = tool.execute(ScopedContext(), **arguments)

    assert result.data["status"] == "created_uncalibrated"
    assert calls == [arguments]

from core.ai.contracts import (
    EvaluationCase, ProviderTurn, RunPolicy, ScopedContext, ToolCall,
)
from core.ai.evaluation import evaluate
from core.ai.providers import FakeProvider
from core.ai.session import AISession
from core.ai.tools import (AlertTool, AssetTool, EvidenceExcerptTool, FlowTool, SigmaPreviewTool,
                           StreamTool, TimelineTool, ToolRegistry, _session_summary, build_native_tools)


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


def test_asset_tool_only_profiles_endpoints_observed_in_the_exact_scope():
    class ScopedDB:
        def __init__(self):
            self.flow_queries = []
            self.entity_queries = []
            self.endpoint_queries = []

        def get_flows(self, **kwargs):
            self.flow_queries.append(kwargs)
            return [{"id": 1, "src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "source": "pcap:a",
                     "capture_interface": "eth0", "capture_session_id": "capture-a",
                     "sensor_node_id": "node-a", "start_time": 10.0, "last_seen": 20.0,
                     "packet_count": 5, "byte_count": 500, "src_port": 51000, "dst_port": 443,
                     "protocol": "TCP"}]

        def get_all_entities(self, **kwargs):
            self.entity_queries.append(kwargs)
            return [{"ip": "10.0.0.2", "source": "pcap:a", "role": "client"}]

        def get_entity(self, ip):
            return {"ip": ip, "source": "global", "role": "server"}

        def get_entity_flows(self, ip, **kwargs):
            self.endpoint_queries.append((ip, kwargs))
            return [{"id": 1, "src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "source": "pcap:a",
                     "capture_interface": "eth0", "capture_session_id": "capture-a",
                     "sensor_node_id": "node-a", "start_time": 10.0, "last_seen": 20.0,
                     "packet_count": 5, "byte_count": 500, "src_port": 51000, "dst_port": 443,
                     "protocol": "TCP"}]

    db = ScopedDB()
    scope = ScopedContext(source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
                          time_start=10.0, time_end=20.0, max_records=50)
    tool = AssetTool(db)
    result = tool.execute(scope, ips=["10.0.0.2", "203.0.113.77"])

    assert tool.manifest.requires_scope
    assert [row["ip"] for row in result.data] == ["10.0.0.2"]
    expected_scope = {
        "source": "pcap:a", "interface": "eth0", "capture_session_id": "capture-a",
        "sensor_node_id": "node-a", "time_start": 10.0, "time_end": 20.0,
    }
    assert all({key: query.get(key) for key in expected_scope} == expected_scope
               for query in db.flow_queries)
    assert all({key: query.get(key) for key in expected_scope} == expected_scope
               for query in db.entity_queries)
    assert all(ip == "10.0.0.2" and {key: query.get(key) for key in expected_scope} == expected_scope
               for ip, query in db.endpoint_queries)


def test_asset_tool_does_not_expand_an_explicit_ip_outside_target_scope():
    class DB:
        def __init__(self): self.queries = 0
        def get_flows(self, **kwargs):
            self.queries += 1
            return [{"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8"}]
        def get_all_entities(self, **kwargs): return [{"ip": "10.0.0.2"}]
        def get_entity_flows(self, ip, **kwargs): return []

    db = DB()
    result = AssetTool(db).execute(
        ScopedContext(source="pcap:a", target_ips=("10.0.0.2",)),
        ips=["203.0.113.77"],
    )

    assert result.data == []
    assert db.queries == 0


def test_asset_tool_does_not_treat_case_only_context_as_a_flow_scope():
    class DB:
        def __init__(self): self.queries = 0
        def get_flows(self, **kwargs):
            self.queries += 1
            return [{"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8"}]

    db = DB()
    result = AssetTool(db).execute(ScopedContext(case_id="case-a"))

    assert result.data == []
    assert db.queries == 0


def test_timeline_tool_applies_every_explicit_scope_filter_before_aggregation():
    class DB:
        def __init__(self): self.flow_query = None; self.timeline_queries = 0
        def get_flows(self, **kwargs):
            self.flow_query = kwargs
            return [{"src_ip": "10.0.0.2", "dst_ip": "8.8.8.8", "last_seen": 600.0,
                     "packet_count": 3, "byte_count": 300}]
        def get_timeline(self, **kwargs):
            self.timeline_queries += 1
            return []

    db = DB()
    scope = ScopedContext(source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
                          time_start=500.0, time_end=700.0, target_ips=("10.0.0.2",), max_records=20)
    result = TimelineTool(db).execute(scope)

    assert db.flow_query == {
        "source": "pcap:a", "interface": "eth0", "capture_session_id": "capture-a",
        "limit": 21, "target_ips": ["10.0.0.2"], "time_start": 500.0,
        "time_end": 700.0, "sensor_node_id": "node-a",
    }
    assert db.timeline_queries == 0
    assert result.data == [{"timestamp": 600, "packets": 3, "bytes": 300}]


def test_finding_tool_forwards_the_complete_visible_scope():
    calls = []

    class Service:
        def scoring_findings(self, **kwargs):
            calls.append(kwargs)
            return []

    tool = build_native_tools(FakeDB(), service=Service()).get("findings")
    tool.execute(ScopedContext(source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
                               time_start=100.0, time_end=200.0, target_ips=("10.0.0.2",)))

    assert calls == [{
        "source": "pcap:a", "interface": "eth0", "session": "capture-a",
        "finding_type": None, "limit": 500, "sensor_node_id": "node-a",
        "time_start": 100.0, "time_end": 200.0, "target_ips": ["10.0.0.2"],
    }]


def test_identity_tool_forwards_target_and_time_scope():
    calls = []

    class Service:
        def endpoint_identities(self, *args):
            calls.append(args)
            return []

    tool = build_native_tools(FakeDB(), service=Service()).get("identities")
    tool.execute(ScopedContext(source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
                               time_start=100.0, time_end=200.0, target_ips=("10.0.0.2",)), limit=12)

    assert calls == [("pcap:a", "eth0", "capture-a", 12, "node-a", ["10.0.0.2"], 100.0, 200.0)]


def test_risk_tool_forwards_target_and_time_scope_to_ephemeral_assessment():
    calls = []

    class Service:
        def scoring_risk(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"subject": args[0], "priority_score": 12.0}

    tool = build_native_tools(FakeDB(), service=Service()).get("risk_explain")
    tool.execute(ScopedContext(source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
                               time_start=100.0, time_end=200.0, target_ips=("10.0.0.2",)), ip="10.0.0.2")

    assert calls == [(("10.0.0.2", "pcap:a", "eth0", "capture-a"), {
        "explain": True, "sensor_node_id": "node-a", "time_start": 100.0,
        "time_end": 200.0, "target_ips": ["10.0.0.2"],
    })]


def test_risk_tool_refuses_an_endpoint_outside_the_visible_target_allowlist():
    calls = []

    class Service:
        def scoring_risk(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"subject": args[0], "priority_score": 12.0}

    tool = build_native_tools(FakeDB(), service=Service()).get("risk_explain")
    result = tool.execute(ScopedContext(source="pcap:a", target_ips=("10.0.0.2",)), ip="8.8.8.8")

    assert result.data["error"] == "out_of_scope"
    assert calls == []


def test_priority_endpoint_tool_scores_only_observed_targets_in_exact_scope():
    class ScopedDB:
        def __init__(self): self.queries = []
        def get_flows(self, **kwargs):
            self.queries.append(kwargs)
            return [
                {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.3"},
                {"src_ip": "203.0.113.77", "dst_ip": "8.8.8.8"},
            ]

    class Service:
        def __init__(self): self.assessments = []
        def scoring_risk(self, subject, source=None, interface=None, session=None, **kwargs):
            self.assessments.append((subject, source, interface, session, kwargs))
            score = {"10.0.0.2": 10.0, "10.0.0.3": 5.0}[subject]
            return {"subject": subject, "priority_score": score, "risk_level": "LOW",
                    "assessment_confidence": 0.5, "contributors": []}

    db, service = ScopedDB(), Service()
    scope = ScopedContext(
        source="pcap:a", interface="eth0", session_id="capture-a", node_id="node-a",
        time_start=100.0, time_end=200.0, target_ips=("10.0.0.2", "10.0.0.3"),
    )
    tool = build_native_tools(db, service=service).get("priority_endpoints")

    result = tool.execute(scope)

    assert result.data["top_priority_score"] == 10.0
    assert result.data["top_endpoints"] == [{
        "ip": "10.0.0.2", "priority_score": 10.0, "risk_level": "LOW",
        "assessment_confidence": 0.5,
    }]
    assert len(service.assessments) == 2
    assert db.queries == [{
        "source": "pcap:a", "interface": "eth0", "capture_session_id": "capture-a",
        "sensor_node_id": "node-a", "limit": 500, "offset": 0,
        "target_ips": ["10.0.0.2", "10.0.0.3"], "time_start": 100.0, "time_end": 200.0,
    }]
    assert result.data["effective_scope"]["target_ips"] == ["10.0.0.2", "10.0.0.3"]


def test_priority_endpoint_prompt_exposes_canonical_priority_tool_first():
    class Service:
        def scoring_risk(self, *args, **kwargs):
            return {"priority_score": 0}

    registry = build_native_tools(FakeDB(), service=Service())
    names = [item.name for item in registry.manifests_for_prompt("What should I investigate first?", registry.tools)]
    assert names[0] == "priority_endpoints"


def test_capture_tools_do_not_treat_case_id_alone_as_a_capture_filter():
    class DB:
        def __init__(self): self.calls = []
        def get_flows(self, **kwargs): self.calls.append(("flows", kwargs)); return []
        def get_alerts(self, **kwargs): self.calls.append(("alerts", kwargs)); return []
        def get_timeline(self, **kwargs): self.calls.append(("timeline", kwargs)); return []
        def get_detection_findings(self, **kwargs): self.calls.append(("findings", kwargs)); return []
        def summarize_flows(self, **kwargs): self.calls.append(("summary", kwargs)); return {"flow_count": 0}
        def get_all_entities(self, **kwargs): self.calls.append(("entities", kwargs)); return []
        def get_entity_flows(self, ip, **kwargs): self.calls.append(("entity_flows", ip, kwargs)); return []

    db = DB()
    scope = ScopedContext(case_id="case-a")
    tools = [FlowTool(db), AlertTool(db), AssetTool(db), TimelineTool(db), EvidenceExcerptTool(db)]
    sigma = SigmaPreviewTool(db)
    sigma_calls = []
    sigma.engine.run_hunt = lambda *args, **kwargs: sigma_calls.append((args, kwargs)) or []

    for tool in tools:
        tool.execute(scope)
    sigma.execute(scope)
    summary = _session_summary(db, scope)

    assert summary["flow_count"] == 0
    assert db.calls == []
    assert sigma_calls == []


def test_sigma_preview_preserves_incomplete_hunt_limits_for_the_analyst():
    sigma = SigmaPreviewTool(FakeDB())
    sigma.engine.run_hunt_report = lambda *args, **kwargs: {
        "alerts": [], "complete": False,
        "limitations": ["Flow evaluation reached the 1-record limit; matches may be missing."],
        "evaluated_flows": 1, "evaluated_identity_observations": None,
    }

    result = sigma.execute(ScopedContext(source="pcap:case"))

    assert result.complete is False
    assert result.limitations == ["Flow evaluation reached the 1-record limit; matches may be missing."]


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

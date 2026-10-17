from core.graph.service import EvidenceGraphService


class FakeDb:
    def local_sensor_node_id(self):
        return "node-a"


def _service(captured):
    service = EvidenceGraphService.__new__(EvidenceGraphService)
    service.db = FakeDb()
    service._require_available = lambda: None
    service.status = lambda: {"freshness": "current"}
    service._run = lambda query, parameters: (captured.append((query, parameters)) or [{
        "node_rows": [], "edge_rows": [], "items": [],
    }])
    return service


def test_graph_neighborhood_returns_effective_scope_and_passes_filters_to_query():
    captured = []
    result = _service(captured).neighborhood(
        "203.0.113.10", sensor_node_id="node-a", scope={
            "interface": "Ethernet", "session_id": "session-1", "time_start": 10,
            "time_end": 20, "target_ips": ["203.0.113.10"],
        },
    )

    assert result["effective_scope"]["interface"] == "Ethernet"
    assert result["effective_scope"]["session_id"] == "session-1"
    assert result["effective_scope"]["time_start"] == 10.0
    assert result["completeness"] == {"complete": True, "truncated": False}
    assert captured[0][1]["interface"] == "Ethernet"
    assert captured[0][1]["session_id"] == "session-1"
    assert captured[0][1]["time_start"] == 10.0


def test_graph_timeline_defaults_to_a_bounded_time_window_and_reports_limitations():
    captured = []
    service = _service(captured)
    service.status = lambda: {"freshness": "stale"}
    result = service.timeline("203.0.113.10", limit=25)

    assert captured[0][1]["time_start"] == 0.0
    assert captured[0][1]["time_end"] > 0.0
    assert result["completeness"]["complete"] is False
    assert result["limitations"]

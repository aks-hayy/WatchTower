from core.api.service import WatchtowerApiService
from core.mesh.service import MeshControllerService


class _Db:
    def list_sensor_nodes(self, _limit):
        return [{
            "id": "local-node",
            "status": "local",
            "last_seen_at": 100.0,
            "health": {"captured_at": 100.0},
            "capabilities": {"capture_devices": []},
        }]

    def fleet_node_counters(self, _node_id):
        return {
            "active_sessions": 0,
            "alert_count": 0,
            "urgent_alerts": 0,
            "finding_count": 0,
            "priority_score": 0,
        }

    def count_detection_fingerprints(self):
        return 0


class _Mesh:
    @staticmethod
    def _health_view(node):
        return MeshControllerService._health_view(node)


def test_local_sensor_is_not_ready_when_daemon_is_offline(monkeypatch):
    monkeypatch.setattr("core.api.service.time.time", lambda: 1000.0)
    service = WatchtowerApiService(db=_Db(), daemon=object())
    service._mesh = _Mesh()
    monkeypatch.setattr(service, "daemon_status", lambda: {"running": False, "engines": {}})
    monkeypatch.setattr(service, "mesh_status", lambda: {"authority_ready": False})

    fleet = service.fleet_summary()

    assert fleet["totals"]["ready"] == 0
    assert fleet["nodes"][0]["readiness"] == "offline"
    assert fleet["nodes"][0]["ingestion_lag_seconds"] == 900.0

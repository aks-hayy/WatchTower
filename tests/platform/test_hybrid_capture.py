from core.mesh import hybrid


class FakeDb:
    def __init__(self, nodes, sessions=None):
        self.nodes = nodes
        self.sessions = sessions or []

    def list_sensor_nodes(self, limit=500):
        return self.nodes

    def get_capture_sessions(self, sensor_node_id, limit=500):
        return self.sessions


def _node(node_id="native-one"):
    return {
        "id": node_id,
        "name": "This device",
        "status": "online",
        "capabilities": {"capture_devices": [{
            "device_id": "Ethernet", "name": "Ethernet", "available": True,
            "source_type": "network", "backends": ["rust", "python"],
        }]},
    }


def test_hybrid_capture_routes_to_the_only_enrolled_native_sensor(monkeypatch):
    queued = []

    class Controller:
        def __init__(self, db):
            self.db = db

        def queue_command(self, node_id, action, arguments, requested_by):
            queued.append((node_id, action, arguments, requested_by))
            return {"id": "command-1", "action": action}

    monkeypatch.setattr(hybrid, "MeshControllerService", Controller)
    db = FakeDb([{"id": "controller", "status": "local", "capabilities": {}}, _node()])

    result = hybrid.start_capture(db, "Ethernet", "rust")

    assert result["action"] == "capture.start"
    assert queued == [("native-one", "capture.start", {
        "interface": "Ethernet", "source_type": "network", "backend": "rust",
    }, "hybrid-controller-cli")]


def test_hybrid_stop_without_an_interface_targets_active_native_sessions(monkeypatch):
    queued = []

    class Controller:
        def __init__(self, db):
            self.db = db

        def queue_command(self, node_id, action, arguments, requested_by):
            queued.append((node_id, action, arguments))
            return {"id": arguments["interface"]}

    monkeypatch.setattr(hybrid, "MeshControllerService", Controller)
    db = FakeDb([_node()], [
        {"interface": "Wi-Fi", "processing_state": "running"},
        {"interface": "Ethernet", "status": "STOPPED"},
    ])

    result = hybrid.stop_capture(db)

    assert result == [{"id": "Wi-Fi"}]
    assert queued == [("native-one", "capture.stop", {"interface": "Wi-Fi"})]

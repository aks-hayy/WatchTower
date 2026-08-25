from core.mesh import bootstrap


def test_local_bootstrap_returns_short_lived_join_package_and_runtime_status(tmp_path, monkeypatch):
    class FakeRuntime:
        def __init__(self, data_dir):
            self.data_dir = data_dir

        def start_controller(self):
            return {"state": "running", "running": True}

    monkeypatch.setattr(bootstrap, "MeshRuntimeManager", FakeRuntime)

    result = bootstrap.provision_local_controller(str(tmp_path), node_name="desktop-sensor", ttl_seconds=30)

    assert result["controller"] == "127.0.0.1"
    assert result["join_code"].startswith("WTJ1-")
    assert result["runtime"]["running"] is True


def test_local_controller_ensure_does_not_issue_an_enrollment(tmp_path, monkeypatch):
    class FakeRuntime:
        def __init__(self, data_dir):
            self.data_dir = data_dir

        def start_controller(self):
            return {"state": "running", "running": True}

    monkeypatch.setattr(bootstrap, "MeshRuntimeManager", FakeRuntime)
    result = bootstrap.ensure_local_controller(str(tmp_path))

    assert result == {"controller": "127.0.0.1", "runtime": {"state": "running", "running": True}}

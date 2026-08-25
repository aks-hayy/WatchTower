import threading

import pytest
from pydantic import ValidationError

from core.ai.contracts import ScopedContext
from core.ai.tools import build_native_tools
from core.api.schemas import CaptureActionRequest
from core.api.service import WatchtowerApiService
from core.backend_policy import BackendPolicyError, CaptureBackendPolicy
from core.capture_sources.base import CaptureDevice
from core.daemon.client import DaemonClient
from core.daemon.server import EngineManager
from core.mesh.agent import MeshAgent
from core.packet_engine.config import PacketEngineConfig


def test_packet_engine_config_uses_policy_for_defaults_and_environment(monkeypatch):
    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    assert PacketEngineConfig().capture_backend == "rust"

    monkeypatch.setenv("WATCHTOWER_CAPTURE_BACKEND", "python")
    assert PacketEngineConfig().capture_backend == "python"

    monkeypatch.setenv("WATCHTOWER_CAPTURE_BACKEND", "invalid")
    with pytest.raises(BackendPolicyError, match="Unsupported backend request: invalid"):
        PacketEngineConfig()


def test_policy_chooses_only_supported_idle_device_backends(monkeypatch):
    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    policy = CaptureBackendPolicy()

    assert policy.capture_backend(source_backends=["python", "rust"]) == "rust"
    assert policy.capture_backend(source_backends=["python"]) == "python"
    with pytest.raises(BackendPolicyError, match="no supported capture backend"):
        policy.capture_backend(source_backends=[])


def test_cli_start_path_uses_rust_when_backend_is_omitted(monkeypatch):
    import core.cli.modules.auth as auth_module
    import core.cli.modules.capture as capture_module
    import core.packet_engine.main as main_module

    selected = {}

    class FakeAuthModule:
        def __init__(self, console=None):
            pass

        def ensure_unlocked(self, **kwargs):
            return True

        def close(self):
            pass

    def capture_run(module, background=False):
        selected["backend"] = module.config.capture_backend
        selected["background"] = background

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    monkeypatch.setattr(main_module.sys, "argv", ["tower", "start", "-i", "Ethernet"])
    monkeypatch.setattr(main_module.DaemonManager, "ensure_running", lambda *args, **kwargs: True)
    monkeypatch.setattr(auth_module, "AuthModule", FakeAuthModule)
    monkeypatch.setattr(capture_module.CaptureModule, "run", capture_run)

    main_module.main()

    assert selected == {"backend": "rust", "background": False}


def test_cli_bluetooth_omission_applies_source_policy_before_backend_resolution(monkeypatch):
    import core.cli.modules.auth as auth_module
    import core.cli.modules.capture as capture_module
    import core.packet_engine.main as main_module

    selected = {}

    class FakeAuthModule:
        def __init__(self, console=None):
            pass

        def ensure_unlocked(self, **kwargs):
            return True

        def close(self):
            pass

    def capture_run(module, background=False):
        selected.update(
            backend=module.config.capture_backend,
            source_type=module.config.source_type,
            background=background,
        )

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["tower", "start", "-i", "hci0", "--source-type", "bluetooth"],
    )
    monkeypatch.setattr(main_module.DaemonManager, "ensure_running", lambda *args, **kwargs: True)
    monkeypatch.setattr(auth_module, "AuthModule", FakeAuthModule)
    monkeypatch.setattr(capture_module.CaptureModule, "run", capture_run)

    main_module.main()

    assert selected == {
        "backend": "python",
        "source_type": "bluetooth",
        "background": False,
    }


def test_capture_action_schema_uses_source_policy(monkeypatch):
    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)

    assert CaptureActionRequest(interface="Ethernet").backend == "rust"
    assert CaptureActionRequest(interface="hci0", source_type="bluetooth").backend == "python"
    assert CaptureActionRequest(
        interface="Ethernet", backend="python", source_type="network"
    ).backend == "python"
    with pytest.raises(ValidationError, match="does not support backend: rust"):
        CaptureActionRequest(interface="hci0", backend="rust", source_type="bluetooth")


def test_api_pcap_submission_uses_replay_policy_when_backend_is_omitted(monkeypatch, tmp_path):
    class Jobs:
        def submit(self, path, filename, mode, backend):
            return {"path": path, "filename": filename, "mode": mode, "backend": backend}

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    service = object.__new__(WatchtowerApiService)
    service.jobs = Jobs()
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap")

    result = service.submit_pcap(str(capture), capture.name, "auto", None)

    assert result["backend"] == "rust"


def test_daemon_client_delegates_policy_defaults_and_explicit_python(monkeypatch):
    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    client = DaemonClient()
    sent = []
    monkeypatch.setattr(
        client,
        "_send_command",
        lambda command: sent.append(command) or {
            "status": "started",
            "backend": command.get("backend"),
        },
    )

    assert client.start_engine("Ethernet")["backend"] == "rust"
    assert client.start_engine("Ethernet", backend="python")["backend"] == "python"
    assert client.start_engine("hci0", source_type="bluetooth")["backend"] == "python"
    with pytest.raises(BackendPolicyError, match="does not support backend: rust"):
        client.start_engine("hci0", backend="rust", source_type="bluetooth")

    assert [command["backend"] for command in sent] == ["rust", "python", "python"]


def test_daemon_dispatcher_preserves_an_omitted_backend_for_manager_policy():
    import core.daemon.server as server_module

    class Manager:
        def start_engine(self, interface, backend=None, source_type="network"):
            return {
                "interface": interface,
                "backend": backend,
                "source_type": source_type,
            }

    result = server_module._start_engine_from_request(
        Manager(), {"action": "start", "interface": "Ethernet"}
    )

    assert result == {
        "interface": "Ethernet",
        "backend": None,
        "source_type": "network",
    }


def test_missing_rust_sensor_fails_before_capture_session_is_created(monkeypatch):
    import core.daemon.server as server_module
    from core.capture_sources.network import NetworkInterfaceSource

    manager = object.__new__(EngineManager)
    manager.engines = {}
    manager.lock = threading.Lock()
    manager.sysmon_collector = None
    manager.config = PacketEngineConfig()

    device = CaptureDevice(
        source_type="network",
        device_id="Ethernet",
        name="Ethernet",
        backends=["python", "rust"],
    )
    monkeypatch.setattr(NetworkInterfaceSource, "get_device", lambda self, value: device)
    monkeypatch.setattr(server_module, "rust_sensor_available", lambda: False)

    class ForbiddenSessionDatabase:
        def __init__(self, *args, **kwargs):
            raise AssertionError("capture session persistence must not be reached")

    monkeypatch.setattr(server_module, "WatchtowerDB", ForbiddenSessionDatabase)

    result = manager.start_engine("Ethernet")

    assert result["status"] == "error"
    assert "build_rust_sensor.ps1" in result["message"]


def test_failed_rust_child_readiness_is_not_persisted_or_published(monkeypatch, tmp_path):
    import core.daemon.server as server_module
    from core.capture_sources.network import NetworkInterfaceSource

    manager = object.__new__(EngineManager)
    manager.engines = {}
    manager.lock = threading.Lock()
    manager.config = PacketEngineConfig(data_dir=str(tmp_path))
    manager.local_node_id = "node-local"
    manager.daemon_instance_id = "daemon-test"

    class Collector:
        def __init__(self):
            self.starts = 0

        def start(self):
            self.starts += 1

    manager.sysmon_collector = Collector()
    device = CaptureDevice(
        source_type="network",
        device_id="Ethernet",
        name="Ethernet",
        backends=["python", "rust"],
    )
    monkeypatch.setattr(NetworkInterfaceSource, "get_device", lambda self, value: device)
    monkeypatch.setattr(server_module, "rust_sensor_available", lambda: True)
    monkeypatch.setattr(server_module, "reported_backend_version", lambda backend: "2.0.0")

    persisted = []

    class SessionDatabase:
        def __init__(self, *args, **kwargs):
            pass

        def create_capture_session(self, **kwargs):
            persisted.append(kwargs)

        def close(self):
            pass

    class FakeProcess:
        def __init__(self, target, args, daemon):
            self.target = target
            self.args = args
            self.daemon = daemon
            self.started = False
            self.terminated = False

        def start(self):
            self.started = True
            if self.target is server_module.start_rust_capture:
                readiness = self.args[-1]
                if hasattr(readiness, "put"):
                    readiness.put({
                        "status": "error",
                        "message": "sensor interface open denied",
                    })

        def is_alive(self):
            return self.started and not self.terminated

        def terminate(self):
            self.terminated = True

        def join(self, timeout=None):
            pass

    monkeypatch.setattr(server_module, "WatchtowerDB", SessionDatabase)
    monkeypatch.setattr(server_module.multiprocessing, "Process", FakeProcess)

    result = manager.start_engine("Ethernet")

    assert result == {
        "status": "error",
        "message": "sensor interface open denied",
    }
    assert persisted == []
    assert manager.engines == {}
    assert manager.sysmon_collector.starts == 0


def test_ai_capture_action_delegates_policy_defaults_and_explicit_python(monkeypatch):
    class Service:
        def start_capture(self, interface, backend, source_type):
            return {
                "interface": interface,
                "backend": backend,
                "source_type": source_type,
            }

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    tool = build_native_tools(object(), service=Service()).get("capture_start")

    omitted = tool.execute(ScopedContext(), interface="Ethernet").data
    explicit = tool.execute(
        ScopedContext(), interface="Ethernet", backend="python", source_type="network"
    ).data
    bluetooth = tool.execute(
        ScopedContext(), interface="hci0", source_type="bluetooth"
    ).data

    assert omitted["backend"] == "rust"
    assert explicit["backend"] == "python"
    assert bluetooth["backend"] == "python"


def test_ai_survey_omission_reaches_operator_backend_policy(monkeypatch):
    seen = []

    class Service:
        def run_survey(self, duration_seconds, active, backend):
            seen.append(backend)
            return {
                "backend": CaptureBackendPolicy().capture_backend(
                    requested_backend=backend
                )
            }

    monkeypatch.setenv("WATCHTOWER_CAPTURE_BACKEND", "python")
    tool = build_native_tools(object(), service=Service()).get("network_survey")

    omitted = tool.execute(ScopedContext(), duration_seconds=0, active="safe").data
    explicit = tool.execute(
        ScopedContext(), duration_seconds=0, active="safe", backend="rust"
    ).data

    assert seen == [None, "rust"]
    assert omitted["backend"] == "python"
    assert explicit["backend"] == "rust"


def test_mesh_capture_action_delegates_policy_defaults_and_explicit_python(
    monkeypatch, tmp_path
):
    import core.mesh.agent as agent_module

    calls = []

    class FakeDaemon:
        def start_engine(self, interface, backend=None, source_type="network"):
            calls.append((interface, backend, source_type))
            return {"status": "started", "backend": backend}

    class Database:
        data_dir = tmp_path

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    monkeypatch.setattr(agent_module, "DaemonClient", FakeDaemon)
    agent = MeshAgent(Database())

    assert agent._execute_command("capture.start", {"interface": "Ethernet"})["backend"] == "rust"
    assert agent._execute_command(
        "capture.start", {"interface": "Ethernet", "backend": "python"}
    )["backend"] == "python"

    assert calls == [
        ("Ethernet", "rust", "network"),
        ("Ethernet", "python", "network"),
    ]


def test_capture_session_projection_exposes_only_reported_backend_version():
    reported = WatchtowerApiService._capture_session_projection({
        "id": "session-rust",
        "backend": "rust",
        "metadata_json": '{"backend_version": "2.0.0"}',
        "processing_state": "running",
    })
    unreported = WatchtowerApiService._capture_session_projection({
        "id": "session-python",
        "backend": "python",
        "metadata_json": "{}",
        "processing_state": "running",
    })

    assert reported["backend_version"] == "2.0.0"
    assert "backend_version" not in unreported


def test_backend_version_uses_engine_report_and_never_backend_name(monkeypatch):
    import core.packet_engine.backend_provenance as provenance

    monkeypatch.setattr(provenance, "rust_sensor_version", lambda: "2.0.0")

    assert provenance.reported_backend_version("rust") == "2.0.0"
    assert provenance.reported_backend_version("python")
    assert provenance.reported_backend_version("unknown") is None


def test_survey_default_honors_operator_backend_environment(monkeypatch):
    from core.survey.runner import SurveyConfig

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    assert SurveyConfig().capture_backend == "rust"

    monkeypatch.setenv("WATCHTOWER_CAPTURE_BACKEND", "python")
    assert SurveyConfig().capture_backend == "python"


def test_scoring_rebuild_uses_rust_replay_policy_when_no_backend_is_requested(
    monkeypatch, tmp_path
):
    import core.forensics.engine as engine_module
    from core.detection.operations import ScoringOperations

    capture = tmp_path / "available.pcap"
    capture.write_bytes(b"pcap")
    seen = []

    class Database:
        data_dir = tmp_path

        def get_reports(self):
            return [{"source": "pcap:available.pcap"}]

    class Engine:
        def __init__(self, **kwargs):
            pass

        def analyze_pcap(self, path, **kwargs):
            seen.append(kwargs["backend"])

    monkeypatch.delenv("WATCHTOWER_CAPTURE_BACKEND", raising=False)
    monkeypatch.setattr(engine_module, "ForensicsEngine", Engine)

    ScoringOperations(Database()).rebuild_available_pcaps()

    assert seen == ["rust"]

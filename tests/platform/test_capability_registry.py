from pathlib import Path

from core.backend_policy import BackendPolicyError, CaptureBackendPolicy
from core.operations.capabilities import CapabilityRegistry


def test_backend_policy_falls_back_from_unavailable_rust_to_python():
    policy = CaptureBackendPolicy(environment={})

    assert policy.capture_backend(
        source_type="network",
        runtime_capabilities={"rust_sensor": False},
    ) == "python"


def test_backend_policy_rejects_explicit_unavailable_rust():
    policy = CaptureBackendPolicy(environment={})

    try:
        policy.capture_backend(
            source_type="network",
            requested_backend="rust",
            runtime_capabilities={"rust_sensor": False},
        )
    except BackendPolicyError as exc:
        assert "Rust sensor" in str(exc)
    else:
        raise AssertionError("explicit unavailable Rust backend must be rejected")


def test_capability_registry_returns_actionable_runtime_summary():
    registry = CapabilityRegistry(
        rust_sensor_probe=lambda: (False, "sensor binary is missing"),
        npcap_probe=lambda: (False, "Npcap is not installed"),
        ollama_probe=lambda: (False, "Ollama is disabled"),
        graph_probe=lambda: (False, "Neo4j is disabled"),
        mesh_probe=lambda: (True, "controller is ready"),
    )

    summary = registry.summary()

    assert summary["rust_sensor"]["available"] is False
    assert summary["rust_sensor"]["next_action"]
    assert summary["npcap"]["reason"] == "Npcap is not installed"
    assert summary["mesh"]["state"] == "ready"
    assert set(summary) >= {"rust_sensor", "npcap", "ollama", "graph", "mesh"}

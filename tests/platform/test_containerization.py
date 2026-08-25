from pathlib import Path

import yaml

from core.ai.config import AIConfig
from core.graph.service import GraphConfig


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_compose_keeps_controller_internal_and_ui_loopback_only():
    compose = yaml.safe_load((_root() / "compose.yaml").read_text(encoding="utf-8"))
    controller = compose["services"]["controller"]
    ui = compose["services"]["ui"]
    assert "ports" not in controller
    assert ui["ports"] == ["127.0.0.1:${WATCHTOWER_UI_PORT:-4173}:4173"]
    assert controller["secrets"] == ["watchtower_master_key"]
    assert controller["environment"]["WATCHTOWER_CREDENTIAL_BACKEND"] == "encrypted_file"
    assert compose["services"]["sensor-linux"]["profiles"] == ["linux-sensor"]
    assert compose["services"]["sensor-linux"]["environment"]["WATCHTOWER_SENSOR_INTERFACE"] == "${WATCHTOWER_SENSOR_INTERFACE:-}"


def test_container_descriptors_use_nonroot_runtime_and_explicit_sensor_capabilities():
    dockerfile = (_root() / "Dockerfile").read_text(encoding="utf-8")
    sensor = (_root() / "deploy" / "container" / "sensor-entrypoint.sh").read_text(encoding="utf-8")
    assert "USER watchtower" in dockerfile
    assert "WATCHTOWER_CREDENTIAL_BACKEND=encrypted_file" in dockerfile
    assert "--backend rust" in sensor
    assert "core.mesh.sensor_service" in sensor
    assert "tower mesh agent run" not in sensor


def test_container_environment_selects_internal_ollama_and_neo4j(monkeypatch, tmp_path):
    monkeypatch.setenv("WATCHTOWER_OLLAMA_BASE_URL", "http://ollama:11434")
    monkeypatch.setenv("WATCHTOWER_NEO4J_ENABLED", "true")
    monkeypatch.setenv("WATCHTOWER_NEO4J_URI", "bolt://neo4j:7687")
    config = AIConfig()
    graph = GraphConfig.load(str(tmp_path))
    assert config.ollama.base_url == "http://ollama:11434"
    assert graph.enabled is True
    assert graph.uri == "bolt://neo4j:7687"

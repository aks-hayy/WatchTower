import os
from types import SimpleNamespace

import pytest

import core.packet_engine.rust_capture as rust_capture
from core.packet_engine.backend_provenance import reported_backend_version


def test_rust_backend_version_probe_uses_npcap_runtime_path(monkeypatch, tmp_path):
    if os.name != "nt":
        pytest.skip("Npcap DLL lookup is Windows-specific")

    windows = tmp_path / "Windows"
    npcap = windows / "System32" / "Npcap"
    npcap.mkdir(parents=True)
    binary = tmp_path / "watchtower-sensor.exe"
    binary.touch()
    monkeypatch.setenv("WINDIR", str(windows))
    monkeypatch.setenv("PATH", str(windows / "System32"))
    monkeypatch.setattr(rust_capture, "sensor_binary", lambda: binary)
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs.get("env")
        return SimpleNamespace(returncode=0, stdout="watchtower-sensor 2.0.0\n")

    monkeypatch.setattr(rust_capture.subprocess, "run", run)

    assert reported_backend_version("rust") == "2.0.0"
    assert captured["command"] == [str(binary), "--version"]
    assert captured["env"]["PATH"].split(os.pathsep)[0] == str(npcap)

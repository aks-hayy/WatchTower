"""Truthful runtime capability probes shared by setup, status, and selection."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Callable, Dict, Tuple


Probe = Callable[[], Tuple[bool, str] | bool]


@dataclass(frozen=True)
class CapabilityResult:
    name: str
    available: bool
    state: str
    reason: str = ""
    next_action: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "state": self.state,
            "reason": self.reason,
            "next_action": self.next_action,
            "details": dict(self.details),
        }


class CapabilityRegistry:
    """Probe capabilities without leaking credentials or requiring a task run."""

    def __init__(self, *, data_dir: str | None = None, rust_sensor_probe: Probe | None = None,
                 npcap_probe: Probe | None = None, ollama_probe: Probe | None = None,
                 graph_probe: Probe | None = None, mesh_probe: Probe | None = None):
        self.data_dir = Path(data_dir) if data_dir else None
        self._probes = {
            "rust_sensor": rust_sensor_probe or self._rust_sensor,
            "npcap": npcap_probe or self._npcap,
            "ollama": ollama_probe or self._ollama,
            "graph": graph_probe or self._graph,
            "mesh": mesh_probe or self._mesh,
        }

    def probe(self) -> Dict[str, CapabilityResult]:
        results: Dict[str, CapabilityResult] = {}
        for name, callback in self._probes.items():
            try:
                value = callback()
                available, reason = value if isinstance(value, tuple) else (bool(value), "")
            except Exception as exc:
                available, reason = False, str(exc)
            if available:
                results[name] = CapabilityResult(name, True, "ready", reason=reason)
            else:
                results[name] = CapabilityResult(
                    name,
                    False,
                    "unavailable",
                    reason=reason or f"{name} is unavailable",
                    next_action=self._next_action(name),
                )
        return results

    def summary(self) -> Dict[str, Dict[str, Any]]:
        return {name: item.as_dict() for name, item in self.probe().items()}

    def flags(self) -> Dict[str, bool]:
        """Return the minimal boolean view used at execution boundaries."""
        return {name: item.available for name, item in self.probe().items()}

    @staticmethod
    def _next_action(name: str) -> str:
        return {
            "rust_sensor": "Build or configure the WatchTower Rust sensor, or select the Python backend.",
            "npcap": "Install Npcap and restart WatchTower.",
            "ollama": "Start Ollama, install the configured model, and run the AI provider test.",
            "graph": "Enable Neo4j and run the graph health check, or continue with flow-based evidence.",
            "mesh": "Start the controller or enroll an available native sensor.",
        }.get(name, "Run tower doctor and retry.")

    @staticmethod
    def _rust_sensor() -> Tuple[bool, str]:
        from core.packet_engine.rust_capture import rust_sensor_available
        available = bool(rust_sensor_available())
        return available, "" if available else "Rust sensor binary is missing"

    @staticmethod
    def _npcap() -> Tuple[bool, str]:
        if os.name != "nt":
            return True, "platform packet-capture runtime"
        root = Path(os.environ.get("WINDIR", r"C:\Windows"))
        if (root / "System32" / "Npcap" / "wpcap.dll").is_file():
            return True, "Npcap runtime found"
        return False, "Npcap runtime is missing"

    @staticmethod
    def _ollama() -> Tuple[bool, str]:
        # Status must not perform an unbounded network request. The provider's
        # explicit test command performs the live chat/tool probe.
        try:
            from core.ai.config import AIConfig
            config = AIConfig.load()
            if not config.ollama.enabled:
                return False, "Ollama is disabled"
            return False, "Ollama is configured but requires an explicit provider test"
        except Exception as exc:
            return False, f"Ollama configuration could not be loaded: {exc}"

    def _graph(self) -> Tuple[bool, str]:
        try:
            from core.graph.service import GraphConfig
            config = GraphConfig.load(str(self.data_dir or Path.cwd()))
            if config.enabled:
                return False, "Neo4j is configured but requires a graph connectivity check"
            return False, "Neo4j is disabled"
        except Exception as exc:
            return False, f"Graph configuration could not be loaded: {exc}"

    @staticmethod
    def _mesh() -> Tuple[bool, str]:
        return False, "Mesh controller readiness requires a database-backed service check"

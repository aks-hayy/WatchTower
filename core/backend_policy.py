"""Central backend selection rules for capture and offline replay."""

from __future__ import annotations

from collections.abc import Iterable
import os


class BackendPolicyError(ValueError):
    """Raised when a caller asks for an unavailable backend."""


class CaptureBackendPolicy:
    """Rust-first policy that preserves explicit backend choices."""

    _SUPPORTED_BACKENDS = frozenset({"python", "rust"})

    def __init__(self, environment=None):
        self._environment = environment if environment is not None else os.environ

    def capture_backend(
        self,
        source_type: str = "network",
        requested_backend: str | None = None,
        source_backends: Iterable[str] | None = None,
    ) -> str:
        source_type = str(source_type or "network").strip().lower()
        if source_type not in {"network", "bluetooth"}:
            raise BackendPolicyError(f"Unknown capture source type: {source_type}")

        operator_default = self._environment.get("WATCHTOWER_CAPTURE_BACKEND")
        requested = self._validate_request(
            requested_backend if requested_backend is not None else operator_default
        )
        if source_backends is None:
            supported = frozenset({"python"} if source_type == "bluetooth" else self._SUPPORTED_BACKENDS)
        else:
            supported = frozenset(
                str(backend).strip().lower()
                for backend in source_backends
                if str(backend).strip().lower() in self._SUPPORTED_BACKENDS
            )
        if not supported:
            raise BackendPolicyError(f"Source type {source_type} has no supported capture backend")

        if requested is not None:
            selected = requested
        elif "rust" in supported:
            selected = "rust"
        else:
            selected = "python"
        if selected not in supported:
            raise BackendPolicyError(f"Source type {source_type} does not support backend: {selected}")
        return selected

    def replay_backend(self, requested_backend: str | None = None) -> str:
        operator_default = self._environment.get("WATCHTOWER_CAPTURE_BACKEND")
        return self._validate_request(
            requested_backend if requested_backend is not None else operator_default
        ) or "rust"

    def _validate_request(self, requested_backend: str | None) -> str | None:
        if requested_backend is None:
            return None
        selected = requested_backend.strip().lower()
        if selected not in self._SUPPORTED_BACKENDS:
            raise BackendPolicyError(f"Unsupported backend request: {requested_backend}")
        return selected


backend_policy = CaptureBackendPolicy()

"""Stable contracts for pluggable packet and hardware capture sources."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Iterable, List


CAPTURE_SOURCE_API_VERSION = 1


@dataclass(frozen=True)
class CaptureDevice:
    source_type: str
    device_id: str
    name: str
    description: str = ""
    addresses: List[str] = field(default_factory=list)
    backends: List[str] = field(default_factory=list)
    available: bool = True
    unavailable_reason: str = ""


class CaptureSource(ABC):
    source_type = "unknown"
    api_version = CAPTURE_SOURCE_API_VERSION

    @abstractmethod
    def list_devices(self) -> Iterable[CaptureDevice]:
        """Return devices without starting capture."""

    def validate_backend(self, backend: str) -> None:
        supported = {backend_name for device in self.list_devices() for backend_name in device.backends}
        if backend not in supported:
            raise ValueError(f"Backend {backend!r} is unavailable for source type {self.source_type!r}")

    def metadata(self) -> Dict:
        return {"source_type": self.source_type, "api_version": self.api_version}


class CaptureSourceRegistry:
    def __init__(self):
        self._sources: Dict[str, CaptureSource] = {}

    def register(self, source: CaptureSource) -> None:
        if source.api_version != CAPTURE_SOURCE_API_VERSION:
            raise ValueError(
                f"Capture source {source.source_type!r} uses API {source.api_version}; "
                f"expected {CAPTURE_SOURCE_API_VERSION}"
            )
        self._sources[source.source_type] = source

    def get(self, source_type: str) -> CaptureSource:
        try:
            return self._sources[source_type]
        except KeyError as exc:
            raise KeyError(f"Unknown capture source type: {source_type}") from exc

    def list_devices(self) -> List[CaptureDevice]:
        devices = []
        for source_type in sorted(self._sources):
            devices.extend(self._sources[source_type].list_devices())
        return devices

    def list_sources(self) -> List[Dict]:
        result = []
        for source_type in sorted(self._sources):
            source = self._sources[source_type]
            try:
                devices = list(source.list_devices())
                error = ""
            except Exception as exc:
                devices = []
                error = str(exc)
            result.append({
                **source.metadata(),
                "name": source.__class__.__name__,
                "enabled": not bool(error),
                "valid": not bool(error),
                "errors": 1 if error else 0,
                "last_error": error,
                "device_count": len(devices),
                "backends": sorted({backend for device in devices for backend in device.backends}),
            })
        return result

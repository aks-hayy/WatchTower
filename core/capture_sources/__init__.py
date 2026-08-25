"""Capture source registry and common source contracts."""

from core.capture_sources.base import CaptureDevice, CaptureSource, CaptureSourceRegistry
from core.capture_sources.network import NetworkInterfaceSource


def default_registry() -> CaptureSourceRegistry:
    registry = CaptureSourceRegistry()
    registry.register(NetworkInterfaceSource())
    try:
        from core.capture_sources.bluetooth import BluetoothHCISource

        registry.register(BluetoothHCISource())
    except ImportError:
        pass
    return registry


__all__ = [
    "CaptureDevice",
    "CaptureSource",
    "CaptureSourceRegistry",
    "NetworkInterfaceSource",
    "default_registry",
]

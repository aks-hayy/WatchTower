"""Default network-interface capture source."""

import os
from typing import Iterable

import psutil
import scapy.all as scapy

from core.capture_sources.base import CaptureDevice, CaptureSource


class NetworkInterfaceSource(CaptureSource):
    source_type = "network"

    @staticmethod
    def resolve_interface(identifier):
        """Resolve a friendly name, index, description, or Npcap name."""
        requested = str(identifier).strip()
        if requested == "auto":
            from core.packet_engine.config import auto_detect_interface

            requested = str(auto_detect_interface())

        exact_matches = []
        folded_matches = []
        requested_folded = requested.casefold()
        for iface in scapy.conf.ifaces.values():
            aliases = {
                str(getattr(iface, "name", "")),
                str(getattr(iface, "description", "")),
                str(getattr(iface, "network_name", "")),
                str(getattr(iface, "index", "")),
            }
            aliases.discard("")
            if requested in aliases:
                exact_matches.append(iface)
            elif requested_folded in {alias.casefold() for alias in aliases}:
                folded_matches.append(iface)

        matches = exact_matches or folded_matches
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"Network interface {requested!r} is ambiguous")
        raise ValueError(f"Network interface {requested!r} was not found")

    def get_device(self, identifier) -> CaptureDevice:
        iface = self.resolve_interface(identifier)
        return self._to_device(iface)

    @staticmethod
    def _to_device(iface) -> CaptureDevice:
        name = str(iface.name)
        addresses = []
        if getattr(iface, "ip", None) and iface.ip != "0.0.0.0":
            addresses.append(str(iface.ip))

        interface_stats = psutil.net_if_stats().get(name)
        available = interface_stats is not None and interface_stats.isup
        unavailable_reason = ""
        if interface_stats is None:
            unavailable_reason = (
                f"The operating system could not confirm that network interface {name!r} is active. "
                "Select an interface reported as available."
            )
        elif not interface_stats.isup:
            unavailable_reason = (
                f"Network interface {name!r} is disconnected or disabled. "
                "Connect or enable it before starting capture."
            )

        capture_runtime_available = True
        capture_runtime_reason = ""
        if os.name == "nt":
            try:
                from core.operations.capabilities import CapabilityRegistry

                capture_runtime_available, capture_runtime_reason = CapabilityRegistry._npcap()
            except Exception as exc:
                capture_runtime_available = False
                capture_runtime_reason = f"Npcap readiness could not be checked: {exc}"

        backends = ["python"] if capture_runtime_available else []
        if capture_runtime_available:
            try:
                from core.packet_engine.rust_capture import rust_sensor_available

                if rust_sensor_available():
                    backends.append("rust")
            except (ImportError, OSError):
                pass
        elif available:
            available = False
            unavailable_reason = capture_runtime_reason or "Live capture runtime is unavailable"

        return CaptureDevice(
            source_type="network",
            device_id=name,
            name=name,
            description=str(getattr(iface, "description", "") or ""),
            addresses=addresses,
            backends=backends,
            available=available,
            unavailable_reason=unavailable_reason,
        )

    def list_devices(self) -> Iterable[CaptureDevice]:
        return [self._to_device(iface) for iface in scapy.conf.ifaces.values()]

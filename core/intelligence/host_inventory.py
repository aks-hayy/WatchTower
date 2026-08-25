"""Passive local host-network inventory used by endpoint identity resolution.

The inventory reads local interface, routing-role, and neighbor-cache state. It
never sends a packet or performs a name lookup. Cache observations are marked as
current host state so historical analysis cannot mistake them for packet-time
evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
import os
import re
import socket
import subprocess
import time
from typing import Callable, Dict, Iterable, Optional, Sequence


_IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,})(?![0-9A-Fa-f:.])")
_ARP_RE = re.compile(
    r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<mac>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+",
    re.MULTILINE,
)


def _normal_ip(value: str) -> Optional[str]:
    try:
        return str(ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def _normal_mac(value: str) -> Optional[str]:
    parts = re.findall(r"[0-9A-Fa-f]{2}", str(value))
    if len(parts) != 6:
        return None
    return ":".join(part.lower() for part in parts)


def _addresses(text: str) -> Iterable[str]:
    for candidate in _IP_RE.findall(text):
        normalized = _normal_ip(candidate)
        if normalized:
            yield normalized


@dataclass
class HostNetworkInventory:
    """A timestamped snapshot of passive local networking facts."""

    hostname: str
    observed_at: float
    local_addresses: Dict[str, Dict[str, str]] = field(default_factory=dict)
    neighbors: Dict[str, str] = field(default_factory=dict)
    roles: Dict[str, set[str]] = field(default_factory=dict)

    @staticmethod
    def add_role(roles: Dict[str, set[str]], ip: str, role: str) -> None:
        normalized = _normal_ip(ip)
        if normalized:
            roles.setdefault(normalized, set()).add(role)

    @classmethod
    def parse_arp_output(cls, output: str) -> Dict[str, str]:
        neighbors: Dict[str, str] = {}
        for match in _ARP_RE.finditer(output or ""):
            ip = _normal_ip(match.group("ip"))
            mac = _normal_mac(match.group("mac"))
            if ip and mac:
                neighbors[ip] = mac
        return neighbors

    @classmethod
    def parse_ipconfig_output(cls, output: str) -> Dict[str, set[str]]:
        """Extract explicit Windows gateway, DHCP, and DNS server roles."""
        roles: Dict[str, set[str]] = {}
        active_role: Optional[str] = None
        labels = {
            "default gateway": "default_gateway",
            "dhcp server": "dhcp_server",
            "dns servers": "dns_server",
        }
        for raw_line in (output or "").splitlines():
            line = raw_line.strip()
            if not line:
                active_role = None
                continue
            normalized = line.lower()
            matched_role = None
            value = ""
            for label, role in labels.items():
                if normalized.startswith(label):
                    matched_role = role
                    value = line[len(label):].lstrip(" .:")
                    break
            if matched_role:
                active_role = matched_role
            elif active_role and ":" not in line:
                value = line
            else:
                active_role = None
                continue
            for ip in _addresses(value):
                cls.add_role(roles, ip, active_role)
        return roles

    @staticmethod
    def _run(command: Sequence[str]) -> str:
        try:
            completed = subprocess.run(
                list(command), capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=5, check=False,
            )
            return completed.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    @classmethod
    def collect(cls, runner: Optional[Callable[[Sequence[str]], str]] = None) -> "HostNetworkInventory":
        """Collect a best-effort inventory without requiring elevated privileges."""
        run = runner or cls._run
        local_addresses: Dict[str, Dict[str, str]] = {}
        try:
            import psutil
            for interface, addresses in psutil.net_if_addrs().items():
                mac = next(
                    (
                        _normal_mac(item.address)
                        for item in addresses
                        if getattr(item, "family", None) == psutil.AF_LINK and item.address
                    ),
                    None,
                )
                for item in addresses:
                    if getattr(item, "family", None) not in {socket.AF_INET, socket.AF_INET6}:
                        continue
                    ip = _normal_ip(str(item.address or ""))
                    if ip:
                        local_addresses[ip] = {"interface": interface, "mac": mac or ""}
        except Exception:
            pass

        arp_output = run(["arp", "-a"])
        roles: Dict[str, set[str]] = {}
        if os.name == "nt":
            roles = cls.parse_ipconfig_output(run(["ipconfig", "/all"]))
        return cls(
            hostname=socket.gethostname() or "local-host",
            observed_at=time.time(),
            local_addresses=local_addresses,
            neighbors=cls.parse_arp_output(arp_output),
            roles=roles,
        )


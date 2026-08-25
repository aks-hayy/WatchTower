"""Bounded, evidence-backed endpoint-to-flow attribution."""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple
import time

import psutil


def _endpoint_tuple(value: Any) -> Tuple[Optional[str], Optional[int]]:
    if not value:
        return None, None
    try:
        return str(value.ip), int(value.port)
    except (AttributeError, TypeError, ValueError):
        try:
            return str(value[0]), int(value[1])
        except (IndexError, TypeError, ValueError):
            return None, None


class ServiceResolver:
    """Maps PIDs to Windows services without creating a WMI dependency."""

    def __init__(self, refresh_seconds: float = 15.0):
        self.refresh_seconds = max(1.0, float(refresh_seconds))
        self._expires_at = 0.0
        self._by_pid: Dict[int, List[str]] = {}

    def services_for_pid(self, pid: Optional[int]) -> List[str]:
        if not pid:
            return []
        now = time.monotonic()
        if now >= self._expires_at:
            self._refresh(now)
        return list(self._by_pid.get(int(pid), ()))

    def _refresh(self, now: float) -> None:
        values: Dict[int, List[str]] = {}
        try:
            iterator = getattr(psutil, "win_service_iter", None)
            if iterator is not None:
                for service in iterator():
                    try:
                        info = service.as_dict()
                        pid = int(info.get("pid") or 0)
                        name = str(info.get("display_name") or info.get("name") or "").strip()
                        if pid and name:
                            values.setdefault(pid, []).append(name)
                    except (psutil.Error, OSError, ValueError, TypeError):
                        continue
        except (psutil.Error, OSError):
            values = {}
        self._by_pid = {pid: sorted(set(names))[:16] for pid, names in values.items()}
        self._expires_at = now + self.refresh_seconds


class EndpointAttributor:
    """Prefer exact Sysmon tuples, then label a live socket fallback clearly."""

    def __init__(self, db, sensor_node_id: Optional[str] = None, skew_seconds: float = 15.0):
        self.db = db
        self.sensor_node_id = sensor_node_id or db.local_sensor_node_id()
        self.skew_seconds = max(1.0, float(skew_seconds))
        self.services = ServiceResolver()

    def attribute(
        self, *, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
        protocol: str, observed_at: float,
    ) -> Dict[str, Any]:
        protocol = str(protocol or "").upper()
        exact = []
        for endpoint, local_ip, local_port, remote_ip, remote_port in (
            ("source", src_ip, src_port, dst_ip, dst_port),
            ("destination", dst_ip, dst_port, src_ip, src_port),
        ):
            rows = self.db.find_endpoint_process_observations(
                sensor_node_id=self.sensor_node_id, protocol=protocol, local_ip=local_ip,
                local_port=local_port, remote_ip=remote_ip, remote_port=remote_port,
                observed_at=observed_at, skew_seconds=self.skew_seconds,
            )
            exact.extend((endpoint, row) for row in rows)
        if exact:
            return self._sysmon_result(exact)
        fallback = self._socket_fallback(src_ip, src_port, dst_ip, dst_port, protocol)
        if fallback:
            return fallback
        return {
            "provenance": "unattributed",
            "confidence": 0.0,
            "reason": "No matching Sysmon network event or local socket was available.",
        }

    def _sysmon_result(self, matches: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        unique = {(row.get("pid"), row.get("process_guid"), row.get("image")): (endpoint, row) for endpoint, row in matches}
        candidates = list(unique.values())[:8]
        if len(candidates) == 1:
            endpoint, row = candidates[0]
            return self._result_from_observation(endpoint, row, "sysmon_exact", 0.98)
        return {
            "provenance": "ambiguous",
            "confidence": 0.55,
            "reason": "More than one Sysmon process matched this network tuple and time window.",
            "candidates": [self._result_from_observation(endpoint, row, "sysmon_exact", 0.55) for endpoint, row in candidates],
        }

    @staticmethod
    def _result_from_observation(endpoint: str, row: Dict[str, Any], provenance: str, confidence: float) -> Dict[str, Any]:
        return {
            "provenance": provenance,
            "confidence": confidence,
            "endpoint": endpoint,
            "observation_id": row.get("id"),
            "evidence_ref": row.get("evidence_ref"),
            "event_record_id": row.get("event_record_id"),
            "observed_at": row.get("observed_at"),
            "pid": row.get("pid"),
            "parent_pid": row.get("parent_pid"),
            "process_guid": row.get("process_guid"),
            "image": row.get("image"),
            "user_name": row.get("user_name"),
            "hashes": row.get("hashes") or {},
            "service_names": row.get("service_names") or [],
            "initiated": row.get("initiated"),
        }

    def _socket_fallback(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Optional[Dict[str, Any]]:
        socket_kind = "tcp" if protocol == "TCP" else "udp" if protocol == "UDP" else None
        if socket_kind is None:
            return None
        for endpoint, local_ip, local_port, remote_ip, remote_port in (
            ("source", src_ip, src_port, dst_ip, dst_port),
            ("destination", dst_ip, dst_port, src_ip, src_port),
        ):
            try:
                connections = psutil.net_connections(kind=socket_kind)
            except (psutil.Error, OSError):
                return None
            for connection in connections:
                current_local_ip, current_local_port = _endpoint_tuple(connection.laddr)
                current_remote_ip, current_remote_port = _endpoint_tuple(connection.raddr)
                if (current_local_ip, current_local_port, current_remote_ip, current_remote_port) != (
                    local_ip, int(local_port or 0), remote_ip, int(remote_port or 0),
                ):
                    continue
                if not connection.pid:
                    continue
                try:
                    process = psutil.Process(connection.pid)
                    image = process.exe() or process.name()
                    user = process.username()
                except (psutil.Error, OSError):
                    image, user = None, None
                return {
                    "provenance": "socket_fallback",
                    "confidence": 0.35,
                    "endpoint": endpoint,
                    "pid": int(connection.pid),
                    "image": image,
                    "user_name": user,
                    "service_names": self.services.services_for_pid(connection.pid),
                    "evidence_ref": "socket:" + sha256(
                        f"{connection.pid}:{local_ip}:{local_port}:{remote_ip}:{remote_port}".encode("utf-8")
                    ).hexdigest()[:20],
                    "reason": "Live socket correlation; Sysmon network evidence was unavailable.",
                }
        return None


def legacy_process_label(attribution: Dict[str, Any]) -> str:
    """Compatibility projection for current CLI/UI metadata consumers."""
    if attribution.get("provenance") == "ambiguous":
        return "Ambiguous endpoint process"
    image = attribution.get("image")
    pid = attribution.get("pid")
    if image and pid:
        return f"{image} ({pid})"
    return "Unknown"

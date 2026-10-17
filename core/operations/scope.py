"""Canonical evidence scope and completeness contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from math import isfinite
from typing import Any, Dict, Generic, Iterable, List, Optional, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class EffectiveScope:
    source: Optional[str] = None
    interface: Optional[str] = None
    session_id: Optional[str] = None
    node_id: Optional[str] = None
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    target_ips: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: Optional[Dict[str, Any]]) -> "EffectiveScope":
        value = dict(value or {})
        start = float(value["time_start"]) if value.get("time_start") is not None else None
        end = float(value["time_end"]) if value.get("time_end") is not None else None
        if start is not None and not isfinite(start):
            raise ValueError("time_start must be finite")
        if end is not None and not isfinite(end):
            raise ValueError("time_end must be finite")
        if start is not None and end is not None and start > end:
            raise ValueError("time_start must not be after time_end")
        targets: list[str] = []
        for item in value.get("target_ips") or ():
            try:
                normalized = str(ip_address(str(item)))
            except ValueError as exc:
                raise ValueError(f"target_ips contains an invalid IP address: {item}") from exc
            if normalized not in targets:
                targets.append(normalized)
        return cls(
            source=str(value.get("source") or "") or None,
            interface=str(value.get("interface") or "") or None,
            session_id=str(value.get("session_id") or value.get("session") or "") or None,
            node_id=str(value.get("node_id") or value.get("sensor_node_id") or "") or None,
            time_start=start,
            time_end=end,
            target_ips=tuple(targets),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "interface": self.interface,
            "session_id": self.session_id,
            "node_id": self.node_id,
            "time_start": self.time_start,
            "time_end": self.time_end,
            "target_ips": list(self.target_ips),
        }


@dataclass(frozen=True)
class ScopeResult(Generic[T]):
    items: List[T]
    effective_scope: EffectiveScope
    complete: bool = True
    truncated: bool = False
    total: Optional[int] = None
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "items": list(self.items),
            "effective_scope": self.effective_scope.to_dict(),
            "complete": self.complete,
            "truncated": self.truncated,
            "total": self.total,
            "limitations": list(self.limitations),
        }

"""Controller-side capture routing for the managed local hybrid deployment."""

from __future__ import annotations

import os
import uuid
from typing import Any

from core.mesh.service import MeshControllerService


def hybrid_enabled() -> bool:
    return os.environ.get("WATCHTOWER_HYBRID_BRIDGE", "").strip().lower() in {"1", "true", "yes"}


def capture_node(db) -> dict[str, Any]:
    """Return the selected native sensor or fail with an actionable message."""
    configured = os.environ.get("WATCHTOWER_CAPTURE_TARGET_NODE", "").strip()
    candidates = []
    for node in db.list_sensor_nodes(limit=500):
        if node.get("status") in {"local", "revoked", "decommissioned"}:
            continue
        devices = (node.get("capabilities") or {}).get("capture_devices") or []
        if any(item.get("available", True) for item in devices if isinstance(item, dict)):
            candidates.append(node)
    if configured:
        selected = next((node for node in candidates if node.get("id") == configured), None)
        if selected:
            return selected
        raise RuntimeError(f"Configured hybrid capture node {configured!r} is not available")
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise RuntimeError("No enrolled native sensor is available. Start WatchTower with scripts/watchtower.ps1 start.")
    raise RuntimeError("More than one sensor is available. Select a sensor in the UI or set WATCHTOWER_CAPTURE_TARGET_NODE.")


def devices(db) -> list[dict[str, Any]]:
    node = capture_node(db)
    items = (node.get("capabilities") or {}).get("capture_devices") or []
    return [dict(item) for item in items if isinstance(item, dict)]


def start_capture(db, interface: str, backend: str | None = None, source_type: str = "network") -> dict[str, Any]:
    node = capture_node(db)
    if not interface:
        available = [item for item in devices(db) if item.get("available", True)]
        if len(available) != 1:
            names = ", ".join(str(item.get("name") or item.get("device_id")) for item in available) or "none"
            raise RuntimeError(f"Choose a capture interface with -i. Available sensor interfaces: {names}")
        interface = str(available[0].get("device_id") or available[0].get("name") or "")
    return MeshControllerService(db).queue_command(
        str(node["id"]),
        "capture.start",
        {"interface": interface, "source_type": source_type, **({"backend": backend} if backend else {})},
        requested_by="hybrid-controller-cli",
        # Each operator invocation represents a new capture session. The
        # command remains idempotent when the caller retries the same request
        # with an explicit key, while a later start is not mistaken for the
        # already-completed command from an earlier session.
        idempotency_key=f"capture.start:{node['id']}:{interface}:{uuid.uuid4().hex}",
    )


def stop_capture(db, interface: str | None = None) -> list[dict[str, Any]]:
    node = capture_node(db)
    interfaces = [interface] if interface else sorted({
        str(session.get("interface") or session.get("device_id") or "")
        for session in db.get_capture_sessions(sensor_node_id=str(node["id"]), limit=500)
        if str(session.get("processing_state") or session.get("status") or "").lower() in {"running", "active", "draining"}
    } - {""})
    if not interfaces:
        return []
    controller = MeshControllerService(db)
    return [
        controller.queue_command(
            str(node["id"]), "capture.stop", {"interface": item}, requested_by="hybrid-controller-cli",
            idempotency_key=f"capture.stop:{node['id']}:{item}:{uuid.uuid4().hex}",
        )
        for item in interfaces
    ]


def status(db) -> dict[str, Any]:
    node = capture_node(db)
    sessions = db.get_capture_sessions(sensor_node_id=str(node["id"]), limit=100)
    return {
        "node_id": node["id"], "node_name": node.get("name"), "devices": devices(db),
        "sessions": sessions,
    }

"""Run one expressly approved, isolated 30-minute Rust live capture."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_DURATION_SECONDS = 30 * 60


class CaptureBlocked(RuntimeError):
    """A safety or environment precondition prevents capture from starting."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_request(interface: str, ipv4: str, duration_seconds: int) -> Path:
    if os.environ.get("WATCHTOWER_ACCEPTANCE_LIVE_APPROVED") != "1":
        raise CaptureBlocked("An explicit capture approval is required; no daemon or capture was started.")
    if duration_seconds != REQUIRED_DURATION_SECONDS:
        raise CaptureBlocked("Live acceptance requires exactly 1800 seconds; no daemon or capture was started.")
    if not interface.strip() or not ipv4.strip():
        raise CaptureBlocked("An explicitly scoped interface and IPv4 address are required.")
    home = os.environ.get("WATCHTOWER_HOME", "").strip()
    if not home:
        raise CaptureBlocked("WATCHTOWER_HOME must point to the isolated acceptance home.")
    home_path = Path(home).resolve()
    if not home_path.is_absolute():
        raise CaptureBlocked("WATCHTOWER_HOME must be an absolute isolated path.")
    if home_path.name.casefold() != "watchtower-home" or not home_path.parent.name.casefold().startswith("wt-accept-"):
        raise CaptureBlocked(
            "WATCHTOWER_HOME must be watchtower-home under the unique temporary acceptance directory."
        )
    try:
        daemon_port = int(os.environ.get("WATCHTOWER_DAEMON_PORT", ""))
    except ValueError as exc:
        raise CaptureBlocked("An isolated WatchTower daemon port is required.") from exc
    if not 1 <= daemon_port <= 65535:
        raise CaptureBlocked("An isolated WatchTower daemon port is required.")
    return home_path


def _interface_scope(interface: str, expected_ipv4: str) -> tuple[str, str]:
    import psutil

    from core.capture_sources.network import NetworkInterfaceSource

    try:
        selected = NetworkInterfaceSource.resolve_interface(interface)
    except (ValueError, OSError) as exc:
        raise CaptureBlocked(f"Capture interface {interface!r} is unavailable: {exc}") from exc
    capture_name = str(getattr(selected, "name", "") or "")
    if not capture_name:
        raise CaptureBlocked("The selected capture interface has no stable device identity.")
    stats = psutil.net_if_stats().get(capture_name)
    if not stats or not stats.isup:
        raise CaptureBlocked(f"Authorized interface {interface!r} is not connected; no capture was started.")
    addresses = {
        str(item.address).split("%", 1)[0]
        for item in psutil.net_if_addrs().get(capture_name, [])
        if getattr(item, "family", None) == socket.AF_INET
    }
    if expected_ipv4 not in addresses:
        current = ", ".join(sorted(addresses)) or "none"
        raise CaptureBlocked(
            f"Authorized interface {interface!r} no longer has IPv4 {expected_ipv4} (current: {current}); no capture was started."
        )
    return capture_name, expected_ipv4


def _owns_daemon(client: Any, state_path: Path) -> bool:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        status = client.get_status()
    except (OSError, ValueError, TypeError):
        return False
    return bool(
        status.get("running")
        and state.get("daemon_instance_id")
        and status.get("daemon_instance_id") == state.get("daemon_instance_id")
        and int(status.get("pid") or 0) == int(state.get("pid") or -1)
    )


def run_capture(interface: str, ipv4: str, duration_seconds: int = REQUIRED_DURATION_SECONDS) -> dict[str, Any]:
    home_path = _validate_request(interface, ipv4, duration_seconds)
    capture_name, _ = _interface_scope(interface, ipv4)

    from core.daemon.client import DaemonClient
    from core.daemon.manager import DaemonManager
    from core.storage.database import WatchtowerDB

    client = DaemonClient()
    initial_status = client.get_status()
    if initial_status.get("running"):
        raise CaptureBlocked("The isolated acceptance daemon port is already in use; refusing to attach to or stop it.")

    db = WatchtowerDB()
    instance_path = home_path / "data" / "daemon.instance.json"
    owned_daemon = False
    capture_interface = ""
    session_id = ""
    started_epoch: float | None = None
    capture_ended_at: str | None = None
    capture_ended_epoch: float | None = None
    final_status: dict[str, Any] = {}
    stop_result: dict[str, Any] = {}
    error = ""
    try:
        if not DaemonManager.ensure_running(silent=True):
            raise CaptureBlocked("The isolated WatchTower daemon could not start; verify elevation and retry.")
        owned_daemon = _owns_daemon(client, instance_path)
        if not owned_daemon:
            raise CaptureBlocked("Could not verify ownership of the isolated WatchTower daemon; refusing to start capture.")

        result = client.start_engine(interface, backend="rust", source_type="network")
        if result.get("status") != "started":
            raise CaptureBlocked(str(result.get("message") or result.get("status") or "Rust capture did not start"))
        capture_interface = str(result.get("interface") or capture_name)
        session_id = str(result.get("session_id") or "")
        if not session_id:
            raise RuntimeError("Rust capture started without returning a capture session ID")

        started_epoch = time.time()
        started_monotonic = time.monotonic()
        deadline = started_monotonic + duration_seconds
        next_progress = started_monotonic + 60.0
        while time.monotonic() < deadline:
            _interface_scope(interface, ipv4)
            status = client.get_status()
            engine = (status.get("engines") or {}).get(capture_interface) or {}
            if not status.get("running") or engine.get("session_id") != session_id:
                raise RuntimeError("The isolated Rust capture session stopped or changed before its 30-minute window completed")
            final_status = dict(engine)
            now = time.monotonic()
            if now >= next_progress:
                print(json.dumps({
                    "event": "progress",
                    "elapsed_seconds": int(now - started_monotonic),
                    "required_seconds": duration_seconds,
                    "received_packets": int(engine.get("received_packets") or 0),
                    "processed_packets": int(engine.get("processed_packets") or 0),
                    "dropped_packets": int(engine.get("dropped_packets") or 0),
                }, sort_keys=True), flush=True)
                next_progress = now + 60.0
            time.sleep(min(5.0, max(0.0, deadline - now)))
        capture_ended_at = _utc_now()
        capture_ended_epoch = time.time()
    except Exception as exc:
        error = str(exc)[:1000]
        if session_id:
            capture_ended_at = _utc_now()
            capture_ended_epoch = time.time()
    finally:
        if session_id and capture_interface:
            try:
                stop_result = client.stop_engine(capture_interface)
                final_status = dict(stop_result.get("metrics") or final_status)
                if stop_result.get("session_id") not in (None, session_id):
                    error = error or "Stop response referred to a different capture session"
                if stop_result.get("status") not in {"stopped", "not_running"}:
                    error = error or f"Capture stop did not complete cleanly: {stop_result.get('status')}"
            except Exception as exc:
                error = error or f"Capture stop failed: {str(exc)[:700]}"

    session = db.get_capture_session(session_id) if session_id else None
    if session:
        final_status = {**final_status, **{
            key: session.get(key) for key in (
                "backend", "status", "processing_state", "complete", "received_packets",
                "emitted_packets", "processed_packets", "dropped_packets", "queue_full_events",
                "detector_errors", "evidence_dropped", "snapshot_dropped", "pending_packets",
                "queue_depth_high_watermark", "queue_lag_ms", "queue_lag_max_ms",
                "worker_acknowledged", "evidence_acknowledged", "completion_reason", "error",
            )
        }}
    db.close()

    measured_seconds = (
        max(0.0, capture_ended_epoch - started_epoch)
        if started_epoch is not None and capture_ended_epoch is not None else 0.0
    )
    completed = bool(
        not error
        and session
        and measured_seconds >= duration_seconds
        and session.get("backend") == "rust"
        and session.get("processing_state") == "complete"
        and session.get("complete") is True
        and int(session.get("pending_packets") or 0) == 0
    )

    daemon_shutdown = False
    if owned_daemon and _owns_daemon(client, instance_path):
        shutdown = client.shutdown()
        if shutdown.get("status") == "error":
            error = error or "The isolated WatchTower daemon did not acknowledge shutdown"
            completed = False
        else:
            shutdown_deadline = time.monotonic() + 10.0
            while time.monotonic() < shutdown_deadline:
                if not client.get_status().get("running"):
                    daemon_shutdown = True
                    break
                time.sleep(0.25)
            if not daemon_shutdown:
                error = error or "The isolated WatchTower daemon remained active after shutdown was requested"
                completed = False

    summary = {
        "event": "complete",
        "status": "passed" if completed else ("blocked" if not session else "failed"),
        "interface": interface,
        "capture_device": capture_interface or None,
        "ipv4": ipv4,
        "backend": (session or {}).get("backend"),
        "session_id": session_id or None,
        "capture_started_at": datetime.fromtimestamp(started_epoch, timezone.utc).isoformat() if started_epoch else None,
        "capture_ended_at": capture_ended_at,
        "duration_seconds": round(measured_seconds, 3),
        "processing_state": (session or {}).get("processing_state"),
        "complete": bool((session or {}).get("complete")),
        "received_packets": int((session or {}).get("received_packets") or 0),
        "emitted_packets": int((session or {}).get("emitted_packets") or 0),
        "processed_packets": int((session or {}).get("processed_packets") or 0),
        "dropped_packets": int((session or {}).get("dropped_packets") or 0),
        "queue_full_events": int((session or {}).get("queue_full_events") or 0),
        "pending_packets": int((session or {}).get("pending_packets") or 0),
        "queue_depth_high_watermark": int((session or {}).get("queue_depth_high_watermark") or 0),
        "queue_lag_ms": float((session or {}).get("queue_lag_ms") or 0.0),
        "worker_acknowledged": bool((session or {}).get("worker_acknowledged")),
        "evidence_acknowledged": bool((session or {}).get("evidence_acknowledged")),
        "completion_reason": (session or {}).get("completion_reason"),
        "error": error or (session or {}).get("error"),
        "daemon_shutdown": daemon_shutdown,
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    args = parser.parse_args()
    try:
        summary = run_capture(args.interface, args.ipv4, args.duration_seconds)
        print(json.dumps(summary, sort_keys=True), flush=True)
        return 0 if summary["status"] == "passed" else 1
    except CaptureBlocked as exc:
        print(json.dumps({"event": "complete", "status": "blocked", "error": str(exc)}, sort_keys=True), flush=True)
        return 2
    except Exception as exc:
        print(json.dumps({"event": "complete", "status": "failed", "error": str(exc)[:1000]}, sort_keys=True), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

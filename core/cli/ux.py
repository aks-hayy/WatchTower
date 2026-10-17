"""Human-first helpers for the public WatchTower CLI."""

from __future__ import annotations

from typing import Any


_COMMAND_FAMILIES = {
    "ui": "open",
    "open": "open",
    "monitor": "monitor",
    "investigate": "investigate",
    "sensors": "sensors",
    "extensions": "extensions",
    "rules": "rules",
    "chat": "analyst",
    "ai": "analyst",
    "flows": "monitor",
    "stats": "monitor",
    "sources": "monitor",
    "endpoint": "monitor",
    "graph": "monitor",
    "mesh": "sensors",
    "alerts": "alerts",
    "lookup": "investigate",
    "hunt": "investigate",
    "dive": "investigate",
    "forensics": "investigate",
    "plugins": "extensions",
    "sigma": "rules",
    "scoring": "advanced",
    "enrich": "advanced",
    "identity": "advanced",
    "daemon": "service",
    "background": "service",
}


def command_family(command: str) -> str:
    """Return the task-oriented family for a legacy or current command."""

    return _COMMAND_FAMILIES.get(command, command)


def quick_status(status: dict[str, Any], *, configured: bool) -> str:
    """Render the no-argument CLI response without opening an interactive shell."""

    if not configured:
        return (
            "WatchTower is not configured yet.\n"
            "Next step: run 'tower setup' to secure the local workspace and choose a capture source."
        )

    if not status.get("running"):
        message = str(status.get("message") or "The local service is stopped.")
        return (
            "WatchTower is stopped.\n"
            f"Detail: {message}\n"
            "Next step: run 'tower start'."
        )

    engines = status.get("engines") or {}
    active = [name for name, engine in engines.items() if (engine or {}).get("capture_alive")]
    capture = f"Monitoring {', '.join(active)}." if active else "Capture is ready; no adapter is monitoring yet."
    return (
        "WatchTower is running.\n"
        f"{capture}\n"
        "Next step: run 'tower open' for the dashboard or 'tower alerts' for recent findings."
    )


def capture_completion_message(*, background: bool, started: int, failures: list[str]) -> str:
    """Describe capture completion without claiming success after a failed start."""

    if failures and started == 0:
        return (
            "Capture did not start on any selected adapter.\n"
            f"Detail: {', '.join(failures)}\n"
            "Next step: run 'tower doctor', then retry capture."
        )
    if failures:
        return (
            f"Capture started on {started} adapter(s), but {len(failures)} did not start.\n"
            f"Detail: {', '.join(failures)}\n"
            "Next step: run 'tower doctor' to review the failed adapter(s)."
        )
    if background:
        return (
            f"Capture is running in the background on {started} adapter(s).\n"
            "Use 'tower status' to check monitoring or 'tower stop' to stop it."
        )
    return f"Capture started on {started} adapter(s)."


def capture_succeeded(*, started: int, failures: list[str]) -> bool:
    """Return whether a capture command can report success to automation."""

    return started > 0 and not failures


def calibration_verification_summary(report: dict[str, Any]) -> str:
    """Render calibration verification as a concise, human-first CLI result."""

    targets = report.get("targets") or []
    errors = [str(error) for error in report.get("errors") or []]
    invalid_count = sum(1 for item in targets if not bool(item.get("valid", False)))
    invalid_count = max(invalid_count, len(errors))
    uncalibrated_count = sum(
        1 for item in targets
        if str(item.get("level") or item.get("calibration_level") or "").upper() == "UNCALIBRATED"
    )
    target_label = "target" if len(targets) == 1 else "targets"
    lines = [
        f"Calibration verification: {'PASS' if report.get('valid') else 'FAIL'}",
        f"{len(targets)} {target_label} checked; {invalid_count} invalid; {uncalibrated_count} uncalibrated.",
    ]

    if errors:
        grouped: dict[str, int] = {}
        for error in errors:
            _target, separator, reason = error.partition(": ")
            detail = reason if separator else error
            grouped[detail] = grouped.get(detail, 0) + 1
        for detail, count in sorted(grouped.items())[:3]:
            suffix = f" ({count} targets)" if count > 1 else ""
            lines.append(f"- {detail}{suffix}")
        if len(grouped) > 3:
            lines.append(f"- {len(grouped) - 3} additional error categories; use --format json for details.")
        lines.append(
            "Next step: rerun calibration for affected findings, then have a reviewer assess any promotion."
        )
    elif uncalibrated_count:
        lines.append("Verification does not qualify uncalibrated findings or grant them additional trust.")
    else:
        lines.append("All checked attestations match current sources and scoring policy.")

    return "\n".join(lines)


def capture_source_inventory(devices: list[Any]) -> dict[str, Any]:
    """Serialize source inventory consistently for CLI automation."""
    rows = []
    for device in devices:
        get = device.get if isinstance(device, dict) else lambda key, default=None: getattr(device, key, default)
        rows.append({
            "source_type": str(get("source_type", "network") or "network"),
            "device_id": str(get("device_id", "") or get("name", "") or ""),
            "name": str(get("name", "") or ""),
            "description": str(get("description", "") or ""),
            "addresses": [str(value) for value in get("addresses", []) or []],
            "backends": [str(value) for value in get("backends", []) or []],
            "available": bool(get("available", True)),
            "unavailable_reason": str(get("unavailable_reason", "") or ""),
        })
    return {
        "schema_version": 1,
        "devices": rows,
        "available_count": sum(1 for row in rows if row["available"]),
        "unavailable_count": sum(1 for row in rows if not row["available"]),
    }

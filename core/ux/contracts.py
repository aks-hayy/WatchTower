"""Small, stable UX vocabulary shared across WatchTower surfaces.

This module intentionally contains no runtime or framework dependencies.  The
browser UI, tray controller, and CLI can each consume the same status labels
and structured operation shape without importing one another.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ExperienceMode(str, Enum):
    SIMPLE = "simple"
    STANDARD = "standard"
    ANALYST = "analyst"


class DeploymentRole(str, Enum):
    NATIVE = "native"
    CONTROLLER = "controller"
    OFFLINE = "offline"


class ServiceState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPING = "stopping"
    FAILED = "failed"


class CaptureState(str, Enum):
    UNAVAILABLE = "unavailable"
    IDLE = "idle"
    STARTING = "starting"
    ACTIVE = "active"
    STOPPING = "stopping"
    FAILED = "failed"


@dataclass(frozen=True)
class OperationResult:
    """The result shape used for user-visible operations."""

    operation_id: str
    state: str
    summary: str
    error: dict[str, Any] | None = None
    next_actions: list[str] | None = None
    effective_scope: dict[str, Any] | None = None
    completeness: str = "complete"

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "state": self.state,
            "summary": self.summary,
            "error": self.error,
            "next_actions": list(self.next_actions or []),
            "effective_scope": dict(self.effective_scope or {}),
            "completeness": self.completeness,
        }


def build_operation_failure(
    *,
    operation_id: str,
    code: str,
    title: str,
    detail: str,
    recovery_action: str,
) -> OperationResult:
    return OperationResult(
        operation_id=operation_id,
        state="failed",
        summary=title,
        error={
            "code": code,
            "title": title,
            "detail": detail,
            "recovery_action": recovery_action,
        },
        next_actions=[recovery_action],
    )


def describe_status(
    *,
    service: ServiceState,
    capture: CaptureState,
    deployment: DeploymentRole = DeploymentRole.NATIVE,
    issue: str | None = None,
) -> dict[str, Any]:
    """Return plain-language status labels and one useful next action."""

    service_labels = {
        ServiceState.STOPPED: "Stopped",
        ServiceState.STARTING: "Starting",
        ServiceState.RUNNING: "Running",
        ServiceState.DEGRADED: "Needs attention",
        ServiceState.STOPPING: "Stopping",
        ServiceState.FAILED: "Service needs attention",
    }
    capture_labels = {
        CaptureState.UNAVAILABLE: "Capture unavailable",
        CaptureState.IDLE: "Capture ready",
        CaptureState.STARTING: "Starting capture",
        CaptureState.ACTIVE: "Monitoring",
        CaptureState.STOPPING: "Stopping capture",
        CaptureState.FAILED: "Capture needs attention",
    }

    if service in {ServiceState.STOPPED, ServiceState.FAILED}:
        next_action = "Start the sensor for live capture with tower start."
    elif capture is CaptureState.FAILED:
        next_action = "Check the selected adapter and retry capture."
    elif capture is CaptureState.UNAVAILABLE and deployment is DeploymentRole.CONTROLLER:
        next_action = "Pair a native sensor to begin live monitoring."
    elif capture is CaptureState.UNAVAILABLE and deployment is DeploymentRole.OFFLINE:
        next_action = "Import a capture file to begin analysis."
    elif capture is CaptureState.IDLE:
        next_action = "Choose an adapter to begin monitoring."
    else:
        next_action = "Review recent activity and alerts."

    return {
        "service": service.value,
        "capture": capture.value,
        "deployment": deployment.value,
        "service_label": service_labels[service],
        "capture_label": capture_labels[capture],
        "next_action": next_action,
        "issue": issue,
    }

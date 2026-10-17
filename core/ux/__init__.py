"""Shared user-experience contracts used by the CLI and local UI."""

from .contracts import (
    CaptureState,
    DeploymentRole,
    ExperienceMode,
    OperationResult,
    ServiceState,
    build_operation_failure,
    describe_status,
)

__all__ = [
    "CaptureState",
    "DeploymentRole",
    "ExperienceMode",
    "OperationResult",
    "ServiceState",
    "build_operation_failure",
    "describe_status",
]

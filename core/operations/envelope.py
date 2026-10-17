"""Stable operation results shared by API, UI, CLI, and mesh boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional


@dataclass(frozen=True)
class OperationEnvelope:
    operation_id: str
    state: str
    summary: str
    error: Optional[Dict[str, str]] = None
    next_actions: tuple[str, ...] = field(default_factory=tuple)
    effective_scope: Dict[str, Any] = field(default_factory=dict)
    completeness: str = "complete"

    @classmethod
    def from_result(cls, result: Dict[str, Any], *, operation_id: str, summary: str,
                    effective_scope: Optional[Dict[str, Any]] = None,
                    next_actions: Iterable[str] = ()) -> "OperationEnvelope":
        """Project legacy status fields into an additive, truthful operation contract."""
        payload = result if isinstance(result, dict) else {}
        status = str(payload.get("status") or payload.get("state") or "unknown").strip().casefold()
        state = {
            "queued": "queued", "pending": "queued",
            "started": "running", "running": "running", "draining": "running",
            "already_running": "running", "cancelling": "running", "canceling": "running",
            "awaiting_approval": "needs_approval", "needs_scope": "needs_input",
            "complete": "complete", "completed": "complete", "success": "complete",
            "succeeded": "complete", "stopped": "complete", "not_running": "complete",
            "initialized": "complete", "configured": "complete", "decommissioned": "complete",
            "rotated": "complete", "created": "complete",
            "partial": "partial", "degraded": "partial",
            "failed": "failed", "error": "failed",
            "rejected": "rejected",
            "cancelled": "cancelled", "canceled": "cancelled",
            "interrupted": "interrupted",
        }.get(status, "unknown")
        if state == "queued":
            defaults = ("Wait for the operation to start.",)
            completeness = "not_applicable"
        elif state == "running":
            defaults = ("Refresh this operation to see progress.",)
            completeness = "not_applicable"
        elif state == "complete":
            defaults = ("Review the operation results.",)
            completeness = "complete"
        elif state == "partial":
            defaults = ("Review the reported limitations.",)
            completeness = "partial"
        elif state == "failed":
            defaults = ("Review the error and retry when resolved.",)
            completeness = "partial"
        elif state == "rejected":
            defaults = ("No change was made; revise or dismiss the request.",)
            completeness = "partial"
        elif state == "cancelled":
            defaults = ("Review completed work; retry explicitly if needed.",)
            completeness = "partial"
        elif state == "needs_approval":
            defaults = ("Review and approve or reject the proposed operation.",)
            completeness = "not_applicable"
        elif state == "needs_input":
            defaults = ("Provide the missing scope and retry.",)
            completeness = "not_applicable"
        elif state == "interrupted":
            defaults = ("Review saved progress and explicitly retry if needed.",)
            completeness = "partial"
        else:
            defaults = ("Inspect operation status before taking further action.",)
            completeness = "not_applicable"

        raw_error = payload.get("error")
        error = None
        if isinstance(raw_error, dict):
            error = {
                "code": str(raw_error.get("code") or "operation_failed"),
                "detail": str(raw_error.get("detail") or raw_error.get("message") or "Operation failed."),
            }
        elif raw_error:
            error = {"code": "operation_failed", "detail": str(raw_error)}
        elif state == "failed":
            error = {"code": "operation_failed", "detail": str(payload.get("message") or "Operation failed.")}

        return cls(
            operation_id=str(operation_id),
            state=state,
            summary=summary,
            error=error,
            next_actions=tuple(next_actions) or defaults,
            effective_scope=dict(effective_scope or {}),
            completeness=completeness,
        )

    @classmethod
    def failure(cls, *, operation_id: str, code: str, summary: str, detail: str,
                next_actions: Iterable[str] = ()) -> "OperationEnvelope":
        return cls(
            operation_id=operation_id,
            state="failed",
            summary=summary,
            error={"code": code, "detail": detail},
            next_actions=tuple(next_actions),
            completeness="partial",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "state": self.state,
            "summary": self.summary,
            "error": dict(self.error) if self.error else None,
            "next_actions": list(self.next_actions),
            "effective_scope": dict(self.effective_scope),
            "completeness": self.completeness,
        }

import pytest

from core.operations.envelope import OperationEnvelope


def test_operation_envelope_exposes_stable_failure_and_recovery_fields():
    envelope = OperationEnvelope.failure(
        operation_id="op-1",
        code="sensor_unavailable",
        summary="Capture could not start",
        detail="The native sensor is offline.",
        next_actions=["Start the native sensor and retry."],
    )

    assert envelope.as_dict() == {
        "operation_id": "op-1",
        "state": "failed",
        "summary": "Capture could not start",
        "error": {
            "code": "sensor_unavailable",
            "detail": "The native sensor is offline.",
        },
        "next_actions": ["Start the native sensor and retry."],
        "effective_scope": {},
        "completeness": "partial",
    }


@pytest.mark.parametrize(
    ("status", "state", "completeness", "next_action"),
    [
        ("QUEUED", "queued", "not_applicable", "Wait for the operation to start."),
        ("RUNNING", "running", "not_applicable", "Refresh this operation to see progress."),
        ("COMPLETE", "complete", "complete", "Review the operation results."),
        ("DEGRADED", "partial", "partial", "Review the reported limitations."),
        ("FAILED", "failed", "partial", "Review the error and retry when resolved."),
        ("REJECTED", "rejected", "partial", "No change was made; revise or dismiss the request."),
        ("CANCELLED", "cancelled", "partial", "Review completed work; retry explicitly if needed."),
    ],
)
def test_status_projection_never_marks_unfinished_or_unsuccessful_work_complete(
    status, state, completeness, next_action,
):
    envelope = OperationEnvelope.from_result(
        {"status": status, "error": "fixture error" if status == "FAILED" else None},
        operation_id="op-stable-1",
        summary="Fixture operation",
        effective_scope={"interface": "Wi-Fi"},
    ).as_dict()

    assert envelope == {
        "operation_id": "op-stable-1",
        "state": state,
        "summary": "Fixture operation",
        "error": {"code": "operation_failed", "detail": "fixture error"} if status == "FAILED" else None,
        "next_actions": [next_action],
        "effective_scope": {"interface": "Wi-Fi"},
        "completeness": completeness,
    }

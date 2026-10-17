import pytest

from core.ai.orchestrator import AIOrchestrator
from core.ai.tools import ToolRegistry
from core.storage.database import WatchtowerDB


def test_ai_events_survive_a_new_orchestrator_instance(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    first = AIOrchestrator(db, registry=ToolRegistry([]))
    first._emit("run-1", "running", "Started")
    first._emit("run-1", "complete", "Finished")
    first.close()

    second = AIOrchestrator(db, registry=ToolRegistry([]))
    assert second.events("run-1") == [
        {**second.events("run-1")[0], "sequence": 1},
        {**second.events("run-1")[1], "sequence": 2},
    ]
    assert [item["message"] for item in second.events("run-1", after=1)] == ["Finished"]
    second.close()


def test_startup_marks_abandoned_ai_runs_interrupted_without_replaying_them(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.create_ai_conversation("conversation", "Test", "ollama", {})
    db.append_ai_message("message", "conversation", "user", "Investigate")
    db.create_ai_run("run-1", "conversation", "ollama", "hash", {}, {}, user_message_id="message")
    db.update_ai_run("run-1", "RUNNING")

    analyst = AIOrchestrator(db, registry=ToolRegistry([]))
    run = db.get_ai_run("run-1")
    assert run["status"] == "INTERRUPTED"
    assert "stopped" in run["error"].lower()
    assert [item["kind"] for item in analyst.events("run-1")] == ["interrupted"]
    analyst.close()


def test_startup_invalidates_approvals_for_interrupted_runs(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.create_ai_conversation("conversation", "Test", "ollama", {})
    db.create_ai_run("run-approval", "conversation", "ollama", "hash", {}, {"mode": "action"})
    db.update_ai_run("run-approval", "AWAITING_APPROVAL")
    invocation = db.create_ai_tool_invocation(
        "invocation-approval", "run-approval", "state_change", "confirm", {}, "AWAITING_APPROVAL"
    )
    approval = db.create_ai_approval(
        "approval-1", "run-approval", invocation["id"], "state_change", "confirm",
        "args-hash", {}, None, "idempotency-key", 9_999_999_999,
    )

    analyst = AIOrchestrator(db, registry=ToolRegistry([]))

    assert db.get_ai_run("run-approval")["status"] == "INTERRUPTED"
    assert db.get_ai_approval(approval["id"])["status"] == "CANCELLED"
    assert db.get_ai_run("run-approval")["tool_calls"][0]["status"] == "CANCELLED"
    with pytest.raises(ValueError, match="no longer pending"):
        analyst.approve(approval["id"], background=False)
    analyst.close()

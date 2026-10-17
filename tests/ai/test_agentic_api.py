import pytest
import sqlite3


fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from core.api.server import create_app
from core.ai.contracts import ProviderTurn
from core.ai.providers import FakeProvider
from core.storage.database import WatchtowerDB


def test_ai_conversation_api_round_trip_and_delete(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    try:
        with TestClient(app) as client:
            created = client.post("/api/v2/ai/conversations", json={
                "title": "Scoped analyst test",
                "provider": "ollama",
                "scope": {"source": "pcap:fixture", "interface": "Ethernet", "max_records": 20},
            })
            assert created.status_code == 201
            conversation = created.json()
            assert conversation["scope"]["source"] == "pcap:fixture"

            listed = client.get("/api/v2/ai/conversations")
            assert listed.status_code == 200
            assert [item["id"] for item in listed.json()] == [conversation["id"]]

            fetched = client.get(f"/api/v2/ai/conversations/{conversation['id']}")
            assert fetched.status_code == 200
            assert fetched.json()["messages"] == []

            deleted = client.delete(f"/api/v2/ai/conversations/{conversation['id']}")
            assert deleted.status_code == 200
            assert client.get(f"/api/v2/ai/conversations/{conversation['id']}").status_code == 404
    finally:
        database.close()


def test_editing_user_message_creates_idempotent_branch_with_only_prior_history(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    try:
        parent = database.create_ai_conversation(
            "parent-conversation", "Original investigation", "ollama",
            {"source": "pcap:authorized-fixture", "time_start": 10},
        )
        database.append_ai_message("user-before", parent["id"], "user", "First question")
        database.append_ai_message(
            "assistant-before", parent["id"], "assistant", "First answer",
            citations=[{"id": "flow:fixture-1", "label": "Fixture flow"}], run_id="prior-run",
        )
        database.append_ai_message("user-edit", parent["id"], "user", "Old second question")
        database.append_ai_message("assistant-after", parent["id"], "assistant", "Answer that must not branch")

        branch = database.branch_ai_conversation(
            parent["id"], "user-edit", "Revised second question", "edit-request-1",
        )
        duplicate = database.branch_ai_conversation(
            parent["id"], "user-edit", "Revised second question", "edit-request-1",
        )
        with pytest.raises(ValueError, match="already used"):
            database.branch_ai_conversation(
                parent["id"], "user-edit", "A different edited question", "edit-request-1",
            )

        assert branch["id"] == duplicate["id"]
        assert branch["parent_conversation_id"] == parent["id"]
        assert branch["branched_from_message_id"] == "user-edit"
        assert "branch_request_id" not in branch
        assert "branch_prompt_hash" not in branch
        assert branch["scope"] == database.get_ai_conversation(parent["id"])["scope"]
        assert [(item["role"], item["content"]) for item in branch["messages"]] == [
            ("user", "First question"),
            ("assistant", "First answer"),
        ]
        assert branch["messages"][1]["run_id"] == "prior-run"
        assert branch["messages"][1]["citations"] == [{"id": "flow:fixture-1", "label": "Fixture flow"}]
        original = database.get_ai_conversation(parent["id"])
        assert [(item["id"], item["content"]) for item in original["messages"]][-2:] == [
            ("user-edit", "Old second question"),
            ("assistant-after", "Answer that must not branch"),
        ]
        assert all(item["id"] not in {"user-edit", "assistant-after"} for item in branch["messages"])
    finally:
        database.close()


def test_edit_branch_api_preserves_scope_and_is_idempotent(tmp_path, monkeypatch):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    service = app.state.service
    parent = service.ai_create_conversation(
        "Original investigation", "ollama", {"source": "pcap:fixture", "time_start": 10},
    )
    database.append_ai_message("branch-origin", parent["id"], "user", "Explain this IP")
    provider = FakeProvider([ProviderTurn(text="The revised question was answered.")])
    monkeypatch.setattr("core.ai.orchestrator.provider_for", lambda *_args, **_kwargs: provider)
    branch_message = service.ai.branch_message

    def run_synchronously(*args, **kwargs):
        kwargs["background"] = False
        return branch_message(*args, **kwargs)

    monkeypatch.setattr(service.ai, "branch_message", run_synchronously)
    payload = {
        "message_id": "branch-origin",
        "prompt": "Compare this IP to the other endpoint",
        "client_request_id": "branch-api-request",
    }
    try:
        with TestClient(app) as client:
            first = client.post(f"/api/v2/ai/conversations/{parent['id']}/branch", json=payload)
            repeated = client.post(f"/api/v2/ai/conversations/{parent['id']}/branch", json=payload)

        assert first.status_code == 202
        assert repeated.status_code == 202
        first_result = first.json()
        repeated_result = repeated.json()
        assert first_result["conversation"]["id"] == repeated_result["conversation"]["id"]
        assert first_result["conversation"]["scope"]["source"] == "pcap:fixture"
        assert first_result["run"]["id"] == repeated_result["run"]["id"]
        assert first_result["run"]["status"] == "COMPLETE"
        assert len(provider.turns) == 0
        branch_messages = database.get_ai_conversation(first_result["conversation"]["id"])["messages"]
        assert [(item["role"], item["content"]) for item in branch_messages] == [
            ("user", payload["prompt"]),
            ("assistant", first_result["run"]["final_text"]),
        ]
        assert first_result["run"]["final_text"].startswith("The revised question was answered.")
        assert database.get_ai_conversation(parent["id"])["messages"][0]["content"] == "Explain this IP"
    finally:
        database.close()


def test_edit_branch_api_rejects_non_user_message_without_creating_child(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    parent = database.create_ai_conversation("branch-parent", "Original", "ollama", {})
    database.append_ai_message("assistant-only", parent["id"], "assistant", "Not editable")
    try:
        with TestClient(app) as client:
            response = client.post(
                f"/api/v2/ai/conversations/{parent['id']}/branch",
                json={
                    "message_id": "assistant-only",
                    "prompt": "Revised prompt",
                    "client_request_id": "invalid-branch-request",
                },
            )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "ai_branch_invalid"
        assert [item["id"] for item in database.list_ai_conversations()] == [parent["id"]]
    finally:
        database.close()


def test_existing_ai_conversation_schema_gets_additive_branch_migration(tmp_path):
    database_path = tmp_path / "watchtower.db"
    connection = sqlite3.connect(database_path)
    try:
        connection.execute(
            "CREATE TABLE ai_conversations ("
            "id TEXT PRIMARY KEY, title TEXT NOT NULL, provider TEXT, scope_json TEXT NOT NULL, "
            "created_at REAL NOT NULL, updated_at REAL NOT NULL, archived BOOLEAN NOT NULL DEFAULT 0)"
        )
    finally:
        connection.close()

    database = WatchtowerDB(data_dir=str(tmp_path))
    try:
        with database.engine.connect() as connection:
            columns = {item[1] for item in connection.exec_driver_sql("PRAGMA table_info(ai_conversations)")}
            indexes = connection.exec_driver_sql("PRAGMA index_list(ai_conversations)").fetchall()
        assert {
            "parent_conversation_id", "branched_from_message_id", "branch_request_id", "branch_prompt_hash",
        }.issubset(columns)
        assert any(item[1] == "idx_ai_conversation_branch_request_unique" and item[2] == 1 for item in indexes)
    finally:
        database.close()


def test_ai_run_cancel_endpoint_returns_cancelled_run(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    try:
        with TestClient(app) as client:
            created = client.post("/api/v2/ai/conversations", json={"title": "Cancel test"})
            conversation = created.json()
            database.create_ai_run(
                "cancel-api-run", conversation["id"], "ollama", "hash", {},
                {"allowed_tools": [], "mode": "general"},
            )

            response = client.post("/api/v2/ai/runs/cancel-api-run/cancel")

            assert response.status_code == 200
            assert response.json()["status"] == "CANCELLED"
            operation = response.json()["operation"]
            assert operation["operation_id"] == "cancel-api-run"
            assert operation["state"] == "cancelled"
            assert operation["completeness"] == "partial"
            assert operation["next_actions"] == [
                "Review completed work; retry explicitly if needed.",
            ]
    finally:
        database.close()


def test_ai_run_retry_endpoint_creates_a_linked_child_run(tmp_path, monkeypatch):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    service = app.state.service
    calls = []

    def retry(run_id, operator_session_id=None):
        calls.append((run_id, operator_session_id))
        return {
            "id": "retry-child",
            "conversation_id": "retry-conversation",
            "parent_run_id": run_id,
            "status": "QUEUED",
        }

    monkeypatch.setattr(service.ai, "retry", retry)
    monkeypatch.setattr(service.ai, "run", lambda run_id: {"id": run_id})
    try:
        with TestClient(app) as client:
            response = client.post("/api/v2/ai/runs/interrupted-parent/retry")

        assert response.status_code == 200
        assert response.json()["parent_run_id"] == "interrupted-parent"
        assert calls == [("interrupted-parent", None)]
    finally:
        database.close()


def _seed_completed_ai_run(database, run_id="sse-replay-run"):
    conversation = database.create_ai_conversation(
        f"conversation-{run_id}", "SSE replay test", "ollama", {}
    )
    database.create_ai_run(
        run_id, conversation["id"], "ollama", "prompt-hash", {}, {"mode": "general"}
    )
    database.append_ai_event(run_id, "running", "Started", {})
    database.append_ai_event(run_id, "tool_complete", "Evidence checked", {})
    database.append_ai_event(run_id, "complete", "Finished", {})
    database.update_ai_run(run_id, "COMPLETE", final_text="Finished")


def test_ai_sse_replays_after_last_event_id_without_duplicate_events(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    run_id = "sse-replay-run"
    try:
        _seed_completed_ai_run(database, run_id)
        with TestClient(app) as client:
            response = client.get(
                f"/api/v2/ai/runs/{run_id}/events?after=0",
                headers={"Last-Event-ID": "1"},
            )

        assert response.status_code == 200
        assert "id: 2\nevent: tool_complete\n" in response.text
        assert "id: 3\nevent: complete\n" in response.text
        assert "id: 1\nevent:" not in response.text
        assert response.text.count("id: ") == 2
    finally:
        database.close()


def test_ai_sse_after_query_remains_a_compatible_replay_cursor(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    run_id = "sse-query-replay-run"
    try:
        _seed_completed_ai_run(database, run_id)
        with TestClient(app) as client:
            response = client.get(f"/api/v2/ai/runs/{run_id}/events?after=1")

        assert response.status_code == 200
        assert "id: 2\nevent: tool_complete\n" in response.text
        assert "id: 3\nevent: complete\n" in response.text
        assert "id: 1\nevent:" not in response.text
    finally:
        database.close()


def test_ai_sse_rejects_malformed_or_negative_last_event_id(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    run_id = "sse-invalid-cursor-run"
    try:
        _seed_completed_ai_run(database, run_id)
        with TestClient(app) as client:
            malformed = client.get(
                f"/api/v2/ai/runs/{run_id}/events",
                headers={"Last-Event-ID": "not-a-sequence"},
            )
            negative = client.get(
                f"/api/v2/ai/runs/{run_id}/events",
                headers={"Last-Event-ID": "-1"},
            )

        assert malformed.status_code == 422
        assert negative.status_code == 422
    finally:
        database.close()


def test_ai_sse_terminates_for_interrupted_run_after_restart(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from time import perf_counter

    import core.api.server as server_module

    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    run_id = "sse-interrupted-run"
    try:
        conversation = database.create_ai_conversation(
            f"conversation-{run_id}", "Interrupted replay", "ollama", {}
        )
        database.create_ai_run(
            run_id, conversation["id"], "ollama", "prompt-hash", {}, {"mode": "general"}
        )
        database.append_ai_event(
            run_id, "interrupted", "This run was interrupted when WatchTower stopped.", {}
        )
        database.update_ai_run(run_id, "INTERRUPTED", error="process stopped")

        ticks = iter((0.0, 1.0, 61.0))
        monkeypatch.setattr(
            server_module,
            "time",
            SimpleNamespace(
                monotonic=lambda: next(ticks),
                sleep=lambda _seconds: None,
                perf_counter=perf_counter,
            ),
        )
        with TestClient(app) as client:
            response = client.get(f"/api/v2/ai/runs/{run_id}/events")

        assert response.status_code == 200
        assert "id: 1\nevent: interrupted\n" in response.text
        assert 'event: terminal\ndata: {"status": "INTERRUPTED"}' in response.text
    finally:
        database.close()

from rich.console import Console
import pytest

from core.api.service import ApiServiceError
from core.cli.modules.ai import AIModule


class ProviderService:
    def ai_provider_models(self, provider, refresh):
        return {
            "models": [
                {"id": "known-yes", "supports_tools": True, "local": True},
                {"id": "known-no", "supports_tools": False, "local": False},
                {"id": "unknown", "supports_tools": None, "local": True},
            ]
        }

    def ai_provider_test(self, provider):
        return {
            "provider": provider,
            "available": True,
            "model_catalog_available": True,
            "selected_model_available": False,
            "model": "qwen2.5-coder:latest",
            "models": [{"id": "qwen2.5-coder:latest"}],
            "capability": {
                "chat_ready": True,
                "agentic_ready": False,
                "detail": "model responded without a native tool call",
            },
            "agentic_ready": False,
        }


class UnavailableProviderService:
    def ai_provider_models(self, provider, refresh):
        raise ApiServiceError(503, "ai_provider_unavailable", "connection refused")

    def ai_provider_test(self, provider):
        raise ApiServiceError(503, "ai_provider_unavailable", "connection refused")

def test_models_cli_does_not_render_unknown_tool_support_as_no():
    console = Console(record=True, width=100)
    AIModule(ProviderService(), console).models("ollama")

    output = console.export_text()
    assert "known-yes" in output and "yes" in output
    assert "known-no" in output and "no" in output
    assert "unknown" in output and "not tested" in output


def test_provider_test_cli_explains_chat_versus_tool_readiness():
    console = Console(record=True, width=100)
    AIModule(ProviderService(), console).provider_test("ollama")

    output = console.export_text()
    assert "qwen2.5-coder:latest" in output
    assert "model catalog available" in output.lower()
    assert "chat ready" in output.lower()
    assert "agentic tools" in output.lower()
    assert "model responded without a native tool call" in output
    assert "selected model is not in the installed model list" in output


def test_provider_unavailable_is_reported_without_traceback_and_with_recovery_guidance():
    console = Console(record=True, width=100)
    module = AIModule(UnavailableProviderService(), console)

    result = module.models("ollama", refresh=True)

    output = console.export_text()
    assert "Could not reach Ollama" in output
    assert "tower ai provider test ollama" in output
    assert "Traceback" not in output
    assert result is None
    assert module.last_error.code == "ai_provider_unavailable"


def test_provider_test_uses_same_recovery_message_for_unavailable_service():
    console = Console(record=True, width=100)
    module = AIModule(UnavailableProviderService(), console)

    assert module.provider_test("ollama") is None

    output = console.export_text()
    assert "Could not reach Ollama" in output
    assert "start Ollama" in output
    assert "then rerun this check" in output
    assert "Traceback" not in output


def test_analyst_cli_renders_evidence_completeness_and_effective_scope():
    console = Console(record=True, width=120)
    module = AIModule(service=object(), console=console)

    module._render({
        "status": "DEGRADED",
        "operation": {
            "state": "partial",
            "next_actions": ["Review the reported limitations."],
        },
        "final_text": "One endpoint was found.",
        "answer": {
            "narrative": "One endpoint was found.",
            "completeness": "partial",
            "effective_scope": {
                "source": "pcap:test", "interface": "Wi-Fi", "session_id": "session-1",
                "node_id": "sensor-1", "time_start": 10.0, "time_end": 20.0,
                "target_ips": ["198.51.100.4"],
            },
            "limitations": ["Only the first page of evidence was returned."],
        },
        "citations": [],
    })

    output = console.export_text()
    assert "Evidence completeness: partial" in output
    assert "pcap:test" in output and "Wi-Fi" in output and "session-1" in output
    assert "Only the first page of evidence was returned." in output
    assert "Operation state: partial" in output
    assert "Review the reported limitations." in output


class ConversationCliService:
    def __init__(self, ids):
        self.ids = ids
        self.started_with = []
        self.run = {
            "id": "run-1", "conversation_id": ids[0], "status": "COMPLETE",
            "answer": {"narrative": "Follow-up answered from the existing conversation."},
            "final_text": "Follow-up answered from the existing conversation.",
        }

    def ai_conversations(self):
        return [{"id": value, "title": "Synthetic case", "provider": "ollama", "updated_at": 1}
                for value in self.ids]

    def ai_start_run(self, prompt, conversation_id, *args):
        self.started_with.append(conversation_id)
        return self.run

    def ai_run(self, run_id):
        return self.run


def test_cli_resumes_conversation_from_the_displayed_unique_id_prefix():
    full_id = "9119c25f-14e0-4f55-a95c-29c84f68cc53"
    service = ConversationCliService([full_id])
    console = Console(record=True, width=120)
    module = AIModule(service, console)

    result = module.chat(conversation_id=full_id[:12], prompt="Why is it critical?")

    assert result["status"] == "COMPLETE"
    assert service.started_with == [full_id]
    assert "Follow-up answered" in console.export_text()


def test_cli_reports_ambiguous_conversation_prefixes_without_starting_a_run():
    service = ConversationCliService([
        "9119c25f-14e0-4f55-a95c-29c84f68cc53",
        "9119c25f-14e0-4f55-b55c-29c84f68cc53",
    ])
    console = Console(record=True, width=120)
    module = AIModule(service, console)

    result = module.chat(conversation_id="9119c25f-14e", prompt="Why is it critical?")

    output = console.export_text()
    assert result is None
    assert service.started_with == []
    assert "matches more than one" in output
    assert service.ids[0] in output and service.ids[1] in output
    assert "Traceback" not in output


def test_cli_reports_missing_conversation_prefix_without_starting_a_run():
    service = ConversationCliService(["9119c25f-14e0-4f55-a95c-29c84f68cc53"])
    console = Console(record=True, width=120)
    module = AIModule(service, console)

    result = module.chat(conversation_id="missing", prompt="Why is it critical?")

    assert result is None
    assert service.started_with == []
    assert "No analyst conversation matches" in console.export_text()
    assert module.last_error.status_code == 404


def test_cli_reports_start_errors_without_a_python_traceback():
    class FailingService(ConversationCliService):
        def ai_start_run(self, *args):
            raise ApiServiceError(404, "ai_invalid_run", "AI conversation was not found")

    full_id = "9119c25f-14e0-4f55-a95c-29c84f68cc53"
    console = Console(record=True, width=120)
    module = AIModule(FailingService([full_id]), console)

    result = module.chat(conversation_id=full_id, prompt="Why is it critical?")

    assert result is None
    assert "Could not start the analyst run" in console.export_text()
    assert "Traceback" not in console.export_text()
    assert module.last_error.status_code == 404


def test_cli_conversation_list_explains_how_to_resume_from_the_visible_id():
    service = ConversationCliService(["9119c25f-14e0-4f55-a95c-29c84f68cc53"])
    console = Console(record=True, width=120)

    AIModule(service, console).conversations()

    output = console.export_text()
    assert "tower chat --conversation <ID>" in output
    assert "unique ID prefix" in output


def test_chat_command_exits_nonzero_when_conversation_id_is_invalid(monkeypatch):
    import sys
    from core.packet_engine.main import main

    class FailedChatModule:
        last_error = ApiServiceError(404, "ai_conversation_not_found", "No matching conversation")
        def __init__(self, console=None): pass
        def chat(self, **kwargs): pass

    class UnlockedAuth:
        def __init__(self, console=None): pass
        def ensure_unlocked(self, **kwargs): return True
        def close(self): pass

    monkeypatch.setattr("core.cli.modules.ai.AIModule", FailedChatModule)
    monkeypatch.setattr("core.cli.modules.auth.AuthModule", UnlockedAuth)
    monkeypatch.setattr(sys, "argv", ["tower", "chat", "--conversation", "missing", "--prompt", "Why?"])

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2


class RetryService:
    def __init__(self):
        self.retry_calls = []
        self.run = {
            "id": "retry-child",
            "conversation_id": "conversation-1",
            "parent_run_id": "interrupted-parent",
            "status": "COMPLETE",
            "final_text": "Retried from the original question.",
            "answer": {"narrative": "Retried from the original question."},
        }

    def ai_retry(self, run_id, operator_session_id=None):
        self.retry_calls.append((run_id, operator_session_id))
        return self.run

    def ai_run(self, run_id):
        return self.run


def test_cli_can_explicitly_retry_an_interrupted_read_only_run():
    service = RetryService()
    console = Console(record=True, width=100)

    result = AIModule(service, console).retry("interrupted-parent")

    assert result["parent_run_id"] == "interrupted-parent"
    assert service.retry_calls == [("interrupted-parent", None)]
    assert "Retried from the original question." in console.export_text()


def test_cli_explains_when_an_interrupted_action_cannot_be_retried():
    class UnsafeRetryService:
        def ai_retry(self, run_id, operator_session_id=None):
            raise ApiServiceError(
                409,
                "ai_run_not_retryable",
                "A state-changing run cannot be retried automatically; review it and submit a new action explicitly",
            )

    console = Console(record=True, width=100)
    result = AIModule(UnsafeRetryService(), console).retry("interrupted-action")

    assert result is None
    assert "cannot be retried automatically" in console.export_text()

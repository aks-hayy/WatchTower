import requests

from core.ai.config import ProviderConfig
from core.ai.contracts import ScopedContext
from core.ai.providers import OllamaProvider


def test_ollama_readiness_hides_transport_trace_and_says_how_to_recover(monkeypatch):
    endpoint = "http://user:secret@127.0.0.1:11434"
    provider = OllamaProvider(ProviderConfig(True, "model-x", endpoint, ""))

    def offline(*_args, **_kwargs):
        raise requests.ConnectTimeout(f"connection to {endpoint} timed out")

    monkeypatch.setattr("core.ai.providers.requests.get", offline)

    status = provider.status()

    assert status["available"] is False
    assert "endpoint is unreachable" in status["detail"].lower()
    assert "check that ollama is running" in status["detail"].lower()
    assert "user:secret" not in status["detail"]
    assert "ConnectTimeout" not in status["detail"]


def test_ollama_general_guidance_distinguishes_packet_metadata_payload_and_visibility(monkeypatch):
    provider = OllamaProvider(ProviderConfig(True, "model-x", "http://127.0.0.1:11434", ""))
    sent = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "A packet capture can reveal network activity."}}

    def capture_request(_url, *, json, **_kwargs):
        sent.update(json)
        return Response()

    monkeypatch.setattr("core.ai.providers.requests.post", capture_request)

    provider.respond(
        "What can a network capture show?", ScopedContext(source="live"), [],
        transcript=[{"role": "user", "content": "What can a network capture show?"}],
    )

    system = sent["messages"][0]["content"].casefold()
    assert "not necessarily all network traffic" in system
    assert "encrypted payload" in system
    assert "capture point" in system
    assert "ip address proves a person's identity" in system

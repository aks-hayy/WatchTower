from core.ai.config import AIConfig
from core.ai.contracts import ProviderTurn
from core.ai.provider_service import AIProviderService
from core.ai.providers import AIProvider, ProviderManifest, ProviderRegistry
from core.storage.database import WatchtowerDB
from core.storage.models import AIProviderModelCache


class MemoryCredentials:
    def __init__(self):
        self.values = {}

    def set(self, reference, secret):
        self.values[reference] = secret

    def get(self, reference):
        return self.values.get(reference)

    def delete(self, reference):
        return self.values.pop(reference, None) is not None


class InspectingOpenAIProvider(AIProvider):
    name = "openai"
    discoveries = []

    def __init__(self, config, credentials):
        self.config = config
        self.credentials = credentials

    def respond(self, prompt, scope, tool_results, tools=()):
        return ProviderTurn(text="ok")

    def discover_models(self, secret_override=None):
        self.discoveries.append((self.config.base_url, secret_override))
        return [{
            "id": "gpt-test",
            "label": "gpt-test",
            "supports_tools": True,
            "provider": "openai",
            "local": False,
        }]

    def status(self):
        return {"name": self.name, "available": bool(self.credentials.get(self.config.credential_ref))}


def test_provider_connection_tests_candidate_without_persisting_secret(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    config = AIConfig()
    config.save = lambda *_args, **_kwargs: None
    credentials = MemoryCredentials()
    registry = ProviderRegistry()
    registry.register(
        ProviderManifest(
            name="openai",
            label="OpenAI API",
            local=False,
            requires_credential=True,
            supports_research=True,
        ),
        InspectingOpenAIProvider,
    )
    InspectingOpenAIProvider.discoveries.clear()
    service = AIProviderService(db, config, credentials, registry, clock=lambda: 1000.0)

    connected = service.connect(
        "openai",
        secret="sk-test-secret",
        model="gpt-test",
        base_url="https://api.example.test/v1",
    )

    assert connected["model"] == "gpt-test"
    assert InspectingOpenAIProvider.discoveries == [
        ("https://api.example.test/v1", "sk-test-secret"),
    ]
    assert credentials.values == {"watchtower-openai": "sk-test-secret"}
    assert "sk-test-secret" not in str(config.public_dict())
    cache = db._get_session().query(AIProviderModelCache).one()
    assert "sk-test-secret" not in cache.models_json
    assert service.models("openai")["cached"] is True

    disconnected = service.disconnect("openai")
    assert disconnected["credential_deleted"] is True
    assert credentials.values == {}
    assert db._get_session().query(AIProviderModelCache).count() == 0
    db.close()

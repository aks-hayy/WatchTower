"""Provider enrollment, model discovery, and credential-safe configuration."""

from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
import json
import time
from typing import Any, Dict, Optional

from core.ai.config import AIConfig, CredentialStore, ProviderConfig
from core.ai.providers import ProviderRegistry, ProviderUnavailable, default_provider_registry
from core.storage.models import AIProviderModelCache


MODEL_CACHE_SECONDS = 24 * 60 * 60


class AIProviderService:
    def __init__(self, db, config: AIConfig = None, credentials: CredentialStore = None,
                 registry: ProviderRegistry = None, clock=time.time):
        self.db = db
        self.config = config or AIConfig.load()
        self.credentials = credentials or CredentialStore()
        self.registry = registry or default_provider_registry()
        self.clock = clock
        self._capabilities: Dict[str, Dict[str, Any]] = {}

    def inventory(self) -> list[Dict[str, Any]]:
        manifests = {item["name"]: item for item in self.registry.manifests()}
        result = []
        for name in self.registry.names():
            adapter = self.registry.create(name, self.config, self.credentials)
            config = getattr(self.config, name)
            result.append({
                **manifests[name],
                **adapter.status(),
                "configured": bool(config.enabled),
                "credential_configured": self._has_credential(config) if manifests[name]["requires_credential"] else True,
                "base_url": config.base_url,
                "model": config.model,
                **self._capabilities.get(name, {
                    "agentic_ready": False, "native_tool_calls": False,
                    "tool_protocol": "none", "capability_probe": "not_run",
                }),
            })
        return result

    def connect(self, name: str, secret: Optional[str] = None, model: Optional[str] = None,
                base_url: Optional[str] = None) -> Dict[str, Any]:
        name = self._name(name)
        config = getattr(self.config, name)
        candidate = replace(
            config,
            enabled=True,
            model=(model or config.model).strip(),
            base_url=(base_url or config.base_url).rstrip("/"),
        )
        temporary = deepcopy(self.config)
        setattr(temporary, name, candidate)
        adapter = self.registry.create(name, temporary, self.credentials)
        models = adapter.discover_models(secret_override=secret)
        if not models:
            raise ProviderUnavailable(f"{name} returned no WatchTower-compatible models")
        available = {item["id"] for item in models}
        selected = model or (candidate.model if candidate.model in available else models[0]["id"])
        if selected not in available:
            raise ProviderUnavailable(f"Model {selected!r} is not available or is not compatible with WatchTower tools")
        if secret:
            self.credentials.set(candidate.credential_ref, secret)
        elif self._manifest(name)["requires_credential"] and not self._has_credential(candidate):
            raise ProviderUnavailable(f"A credential is required to connect {name}")
        candidate.model = selected
        setattr(self.config, name, candidate)
        self.config.save()
        self._write_cache(name, models)
        return {
            "provider": name,
            "status": "connected",
            "model": selected,
            "models": models,
            "credential_reference": candidate.credential_ref if self._manifest(name)["requires_credential"] else None,
        }

    def test(self, name: str, refresh: bool = True) -> Dict[str, Any]:
        name = self._name(name)
        models = self.models(name, refresh=refresh)["models"]
        adapter = self.registry.create(name, self.config, self.credentials)
        capability = adapter.probe()
        self._capabilities[name] = capability
        return {
            "provider": name,
            "available": bool(models),
            "model": getattr(self.config, name).model,
            "models": models,
            "capability": capability,
            "agentic_ready": bool(capability.get("agentic_ready")),
        }

    def probe(self, name: str) -> Dict[str, Any]:
        name = self._name(name)
        adapter = self.registry.create(name, self.config, self.credentials)
        capability = adapter.probe()
        self._capabilities[name] = capability
        return {"provider": name, **capability}

    def disconnect(self, name: str) -> Dict[str, Any]:
        name = self._name(name)
        config = getattr(self.config, name)
        deleted = False
        if self._manifest(name)["requires_credential"] and config.credential_ref:
            deleted = self.credentials.delete(config.credential_ref)
        config.enabled = False
        self.config.save()
        self._delete_cache(name)
        return {"provider": name, "status": "disconnected", "credential_deleted": deleted}

    def models(self, name: str, refresh: bool = False) -> Dict[str, Any]:
        name = self._name(name)
        cached = self._read_cache(name)
        if cached and not refresh:
            return {"provider": name, **cached, "cached": True}
        adapter = self.registry.create(name, self.config, self.credentials)
        models = adapter.discover_models()
        self._write_cache(name, models)
        return {
            "provider": name,
            "models": models,
            "fetched_at": self.clock(),
            "expires_at": self.clock() + MODEL_CACHE_SECONDS,
            "cached": False,
        }

    def set_model(self, name: str, model: str) -> Dict[str, Any]:
        name = self._name(name)
        available = {item["id"] for item in self.models(name)["models"]}
        if model not in available:
            raise ProviderUnavailable(f"Model {model!r} is not available for {name}")
        config = getattr(self.config, name)
        config.model = model
        self.config.save()
        return {"provider": name, "model": model, "status": "selected"}

    def _name(self, name: str) -> str:
        selected = (name or "").casefold()
        if selected not in self.registry.names():
            raise ProviderUnavailable(f"Unknown AI provider: {name}")
        return selected

    def _manifest(self, name: str) -> Dict[str, Any]:
        return next(item for item in self.registry.manifests() if item["name"] == name)

    def _has_credential(self, config: ProviderConfig) -> bool:
        try:
            return bool(self.credentials.get(config.credential_ref))
        except Exception:
            return False

    def _read_cache(self, name: str) -> Optional[Dict[str, Any]]:
        if not hasattr(self.db, "_get_session"):
            return None
        row = self.db._get_session().query(AIProviderModelCache).filter_by(provider=name).first()
        if row is None or float(row.expires_at) <= self.clock():
            return None
        return {
            "models": json.loads(row.models_json or "[]"),
            "fetched_at": row.fetched_at,
            "expires_at": row.expires_at,
        }

    def _write_cache(self, name: str, models: list[Dict[str, Any]]) -> None:
        if not hasattr(self.db, "_get_session"):
            return
        session = self.db._get_session()
        now = self.clock()
        row = session.query(AIProviderModelCache).filter_by(provider=name).first()
        if row is None:
            row = AIProviderModelCache(provider=name, models_json="[]", fetched_at=now, expires_at=now)
            session.add(row)
        row.models_json = json.dumps(models, sort_keys=True)
        row.fetched_at = now
        row.expires_at = now + MODEL_CACHE_SECONDS
        row.error = None
        session.commit()

    def _delete_cache(self, name: str) -> None:
        if not hasattr(self.db, "_get_session"):
            return
        self.db._get_session().query(AIProviderModelCache).filter_by(provider=name).delete()
        self.db._get_session().commit()

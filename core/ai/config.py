"""Local-only AI configuration and credential storage.

Native installations use the operating-system keyring.  Containers use a
small AES-GCM vault encrypted with an installation key mounted as a Docker
secret.  The secret is never copied into application configuration, SQLite,
or the process environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import base64
import json
import os
from pathlib import Path
import threading
from typing import Dict, Optional

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.context import context


class CredentialStoreError(RuntimeError):
    pass


class _EncryptedFileCredentialBackend:
    """A deliberately small encrypted credential vault for container use.

    Docker secrets are files rather than environment variables.  The mounted
    32-byte installation key encrypts each credential independently, allowing
    providers and evidence-envelope keys to share the existing credential
    interface without introducing a database secret store.
    """

    version = 1

    def __init__(self, key_path: str | Path, vault_path: str | Path):
        self.key_path = Path(key_path)
        self.vault_path = Path(vault_path)
        self._lock = threading.RLock()

    def _key(self) -> bytes:
        try:
            raw = self.key_path.read_bytes().strip()
        except OSError as exc:
            raise CredentialStoreError(
                f"WatchTower container credential key is unavailable at {self.key_path}"
            ) from exc
        try:
            decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
        except (ValueError, TypeError) as exc:
            raise CredentialStoreError("Container credential key must be 32 raw or base64 bytes") from exc
        key = raw if len(raw) == 32 else decoded
        if len(key) != 32:
            raise CredentialStoreError("Container credential key must contain exactly 32 bytes")
        return key

    def _read(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        try:
            payload = json.loads(self.vault_path.read_text(encoding="utf-8"))
            if payload.get("version") != self.version or not isinstance(payload.get("entries"), dict):
                raise ValueError("unsupported vault format")
            return {str(name): str(value) for name, value in payload["entries"].items()}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise CredentialStoreError("WatchTower container credential vault is unreadable") from exc

    def _write(self, entries: dict[str, str]) -> None:
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.vault_path.with_suffix(self.vault_path.suffix + ".tmp")
        temporary.write_text(
            json.dumps({"version": self.version, "entries": entries}, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        temporary.replace(self.vault_path)

    @staticmethod
    def _aad(reference: str) -> bytes:
        return f"watchtower-credentials-v1\0{reference}".encode("utf-8")

    def set_password(self, _service: str, reference: str, secret: str) -> None:
        nonce = os.urandom(12)
        encrypted = AESGCM(self._key()).encrypt(nonce, secret.encode("utf-8"), self._aad(reference))
        with self._lock:
            entries = self._read()
            entries[reference] = base64.b64encode(nonce + encrypted).decode("ascii")
            self._write(entries)

    def get_password(self, _service: str, reference: str) -> str | None:
        with self._lock:
            encoded = self._read().get(reference)
        if not encoded:
            return None
        try:
            payload = base64.b64decode(encoded, validate=True)
            return AESGCM(self._key()).decrypt(payload[:12], payload[12:], self._aad(reference)).decode("utf-8")
        except (ValueError, UnicodeDecodeError, TypeError) as exc:
            raise CredentialStoreError("WatchTower container credential vault entry is invalid") from exc
        except Exception as exc:
            raise CredentialStoreError("WatchTower container credential vault cannot be decrypted") from exc

    def delete_password(self, _service: str, reference: str) -> None:
        with self._lock:
            entries = self._read()
            if reference not in entries:
                raise KeyError(reference)
            entries.pop(reference)
            self._write(entries)


class CredentialStore:
    service_name = "WatchTower"

    def __init__(self, *, backend: str | None = None, key_path: str | Path | None = None,
                 vault_path: str | Path | None = None):
        self.backend_name = (backend or os.environ.get("WATCHTOWER_CREDENTIAL_BACKEND") or "keyring").strip().lower()
        self.key_path = Path(key_path or os.environ.get("WATCHTOWER_MASTER_KEY_FILE", "/run/secrets/watchtower_master_key"))
        self.vault_path = Path(vault_path or os.environ.get(
            "WATCHTOWER_CREDENTIAL_VAULT", str(Path(context.config_dir) / "credentials.vault.json")
        ))
        self._selected_backend = None

    def _backend(self):
        if self._selected_backend is not None:
            return self._selected_backend
        if self.backend_name in {"encrypted_file", "encrypted-file", "container"}:
            self._selected_backend = _EncryptedFileCredentialBackend(self.key_path, self.vault_path)
            return self._selected_backend
        if self.backend_name != "keyring":
            raise CredentialStoreError(f"Unsupported credential backend: {self.backend_name}")
        try:
            import keyring
        except ImportError as exc:
            raise CredentialStoreError("Native credential storage requires the keyring package") from exc
        self._selected_backend = keyring
        return self._selected_backend

    def set(self, reference: str, secret: str) -> None:
        if not reference or not secret:
            raise CredentialStoreError("Credential reference and secret are required")
        self._backend().set_password(self.service_name, reference, secret)

    def get(self, reference: Optional[str]) -> Optional[str]:
        return self._backend().get_password(self.service_name, reference) if reference else None

    def delete(self, reference: str) -> bool:
        try:
            self._backend().delete_password(self.service_name, reference)
            return True
        except Exception:
            return False


@dataclass
class ProviderConfig:
    enabled: bool = False
    model: str = ""
    base_url: str = ""
    credential_ref: str = ""

    def public_dict(self) -> Dict[str, object]:
        return {"enabled": self.enabled, "model": self.model, "base_url": self.base_url, "credential_ref": self.credential_ref}


@dataclass
class AIConfig:
    ollama: ProviderConfig = field(default_factory=lambda: ProviderConfig(
        True, "llama3.2", os.environ.get("WATCHTOWER_OLLAMA_BASE_URL", "http://127.0.0.1:11434"), ""
    ))
    openai: ProviderConfig = field(default_factory=lambda: ProviderConfig(False, "gpt-5", "https://api.openai.com/v1", "watchtower-openai"))
    brave: ProviderConfig = field(default_factory=lambda: ProviderConfig(False, "", "https://api.search.brave.com", "watchtower-brave"))
    virustotal: ProviderConfig = field(default_factory=lambda: ProviderConfig(False, "", "https://www.virustotal.com/api/v3", "watchtower-virustotal"))
    abuseipdb: ProviderConfig = field(default_factory=lambda: ProviderConfig(False, "", "https://api.abuseipdb.com/api/v2", "watchtower-abuseipdb"))
    taxii: ProviderConfig = field(default_factory=ProviderConfig)
    max_tool_calls: int = 12
    max_context_chars: int = 48000
    research_cache_days: int = 30

    @staticmethod
    def default_path() -> Path:
        return Path(context.data_dir) / "config" / "ai.yaml"

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AIConfig":
        path = path or cls.default_path()
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        providers = raw.get("providers") if isinstance(raw.get("providers"), dict) else raw
        config = cls()
        for name in ("ollama", "openai", "brave", "virustotal", "abuseipdb", "taxii"):
            values = providers.get(name) or {}
            current = getattr(config, name)
            setattr(config, name, ProviderConfig(
                bool(values.get("enabled", current.enabled)),
                str(values.get("model", current.model)),
                str(values.get("base_url", current.base_url)).rstrip("/"),
                str(values.get("credential_ref", current.credential_ref)),
            ))
        for name in ("max_tool_calls", "max_context_chars", "research_cache_days"):
            if name in raw:
                setattr(config, name, max(1, int(raw[name])))
        return config

    def save(self, path: Optional[Path] = None) -> None:
        path = path or self.default_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(self.public_dict(), sort_keys=True, allow_unicode=False), encoding="utf-8")

    def public_dict(self) -> Dict[str, object]:
        return {
            "providers": {name: getattr(self, name).public_dict() for name in ("ollama", "openai", "brave", "virustotal", "abuseipdb", "taxii")},
            "max_tool_calls": self.max_tool_calls,
            "max_context_chars": self.max_context_chars,
            "research_cache_days": self.research_cache_days,
        }

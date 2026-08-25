import base64

import pytest

from core.ai.config import CredentialStore, CredentialStoreError


def test_encrypted_file_credential_store_round_trip_and_no_plaintext(tmp_path):
    key_path = tmp_path / "installation.key"
    key_path.write_text(base64.urlsafe_b64encode(bytes(range(32))).decode("ascii"), encoding="ascii")
    vault_path = tmp_path / "credentials.vault.json"
    store = CredentialStore(backend="encrypted_file", key_path=key_path, vault_path=vault_path)

    store.set("openai", "sk-test-not-in-vault")

    assert store.get("openai") == "sk-test-not-in-vault"
    assert "sk-test-not-in-vault" not in vault_path.read_text(encoding="utf-8")
    assert store.delete("openai") is True
    assert store.get("openai") is None


def test_encrypted_file_credential_store_rejects_missing_or_bad_installation_key(tmp_path):
    store = CredentialStore(backend="container", key_path=tmp_path / "missing.key", vault_path=tmp_path / "vault.json")
    with pytest.raises(CredentialStoreError, match="unavailable"):
        store.set("provider", "secret")

    key_path = tmp_path / "bad.key"
    key_path.write_text("not-a-32-byte-key", encoding="ascii")
    store = CredentialStore(backend="container", key_path=key_path, vault_path=tmp_path / "vault.json")
    with pytest.raises(CredentialStoreError, match="32"):
        store.set("provider", "secret")

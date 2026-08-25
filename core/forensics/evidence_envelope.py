"""Chunked AES-256-GCM envelopes for retained forensic evidence."""

from __future__ import annotations

import base64
import builtins
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import struct
import threading
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENCRYPTION_FORMAT = "aes-256-gcm-chunked-v1"
_MAGIC = b"WTE1"
_HEADER = struct.Struct(">4sI")
_LENGTH = struct.Struct(">I")
_MAX_CHUNK_SIZE = 16 * 1024 * 1024


class EvidenceEnvelopeError(RuntimeError):
    pass


class EvidenceKeyUnavailable(EvidenceEnvelopeError):
    pass


class EvidenceIntegrityError(EvidenceEnvelopeError):
    pass


@dataclass
class EnvelopeMetadata:
    case_id: str
    digest: str
    purpose: str
    credential_reference: str
    nonce: str
    encrypted_path: str
    format_version: str = ENCRYPTION_FORMAT

    def public_dict(self):
        return {
            "retention_mode": "encrypted",
            "encryption_format": self.format_version,
            "digest": self.digest,
        }


class EvidenceEnvelope:
    def __init__(self, credential_store, installation_id: str, *, chunk_size: int = 1024 * 1024):
        if not installation_id:
            raise ValueError("installation_id is required")
        if chunk_size < 1 or chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError("chunk_size must be between 1 byte and 16 MiB")
        self.credentials = credential_store
        self.installation_id = str(installation_id)
        self.chunk_size = int(chunk_size)
        self._key_lock = threading.RLock()

    @staticmethod
    def _nonce(base_nonce: bytes, index: int) -> bytes:
        if index < 0 or index >= 2**32:
            raise EvidenceIntegrityError("evidence envelope contains too many chunks")
        return base_nonce[:8] + index.to_bytes(4, "big")

    @staticmethod
    def _aad(
        case_id: str,
        digest: str,
        purpose: str,
        index: int,
        plaintext_length: int,
        chunk_size: int,
    ) -> bytes:
        return (
            f"{ENCRYPTION_FORMAT}\0{case_id}\0{digest}\0{purpose}\0"
            f"{index}\0{plaintext_length}\0{chunk_size}"
        ).encode("utf-8")

    def _credential_reference(self, case_id: str) -> str:
        installation = sha256(self.installation_id.encode("utf-8")).hexdigest()
        case = sha256(str(case_id).encode("utf-8")).hexdigest()
        return f"watchtower-evidence/v1/{installation}/{case}"

    def _case_key(self, case_id: str) -> tuple[str, bytes]:
        credential_reference = self._credential_reference(case_id)
        with self._key_lock:
            encoded = self.credentials.get(credential_reference)
            if encoded:
                try:
                    key = base64.b64decode(encoded, validate=True)
                except (TypeError, ValueError) as exc:
                    raise EvidenceKeyUnavailable("the case evidence encryption key is invalid") from exc
                if len(key) != 32:
                    raise EvidenceKeyUnavailable("the case evidence encryption key is invalid")
                return credential_reference, key
            key = AESGCM.generate_key(bit_length=256)
            self.credentials.set(credential_reference, base64.b64encode(key).decode("ascii"))
            return credential_reference, key

    def delete_case_key(self, case_id: str) -> bool:
        with self._key_lock:
            return bool(self.credentials.delete(self._credential_reference(case_id)))

    def encrypt(
        self,
        source_path: str | Path,
        encrypted_path: str | Path,
        *,
        case_id: str,
        digest: str,
        purpose: str,
    ) -> EnvelopeMetadata:
        source_path = Path(source_path)
        encrypted_path = Path(encrypted_path)
        expected_digest = str(digest).lower()
        credential_reference, key = self._case_key(case_id)
        aesgcm = AESGCM(key)
        base_nonce = os.urandom(12)
        encrypted_path.parent.mkdir(parents=True, exist_ok=True)
        staging_path = encrypted_path.with_name(
            f".{uuid.uuid4().hex}.tmp"
        )
        observed_digest = sha256()
        try:
            with builtins.open(source_path, "rb") as source, builtins.open(staging_path, "xb") as destination:
                destination.write(_HEADER.pack(_MAGIC, self.chunk_size))
                index = 0
                while chunk := source.read(self.chunk_size):
                    observed_digest.update(chunk)
                    ciphertext = aesgcm.encrypt(
                        self._nonce(base_nonce, index),
                        chunk,
                        self._aad(
                            case_id,
                            expected_digest,
                            purpose,
                            index,
                            len(chunk),
                            self.chunk_size,
                        ),
                    )
                    destination.write(_LENGTH.pack(len(chunk)))
                    destination.write(ciphertext)
                    index += 1
                destination.write(_LENGTH.pack(0))
            if observed_digest.hexdigest() != expected_digest:
                raise EvidenceIntegrityError("evidence digest does not match the encrypted input")
            os.replace(staging_path, encrypted_path)
        except Exception:
            try:
                staging_path.unlink()
            except FileNotFoundError:
                pass
            raise
        return EnvelopeMetadata(
            case_id=str(case_id),
            digest=expected_digest,
            purpose=str(purpose),
            credential_reference=credential_reference,
            nonce=base64.b64encode(base_nonce).decode("ascii"),
            encrypted_path=str(encrypted_path),
        )

    def decrypt(self, metadata: EnvelopeMetadata, output_path: str | Path) -> Path:
        output_path = Path(output_path)
        if metadata.format_version != ENCRYPTION_FORMAT:
            raise EvidenceIntegrityError("evidence envelope format is unsupported")
        secret = self.credentials.get(metadata.credential_reference)
        if not secret:
            raise EvidenceKeyUnavailable("the evidence encryption key is unavailable")
        try:
            key = base64.b64decode(secret, validate=True)
            base_nonce = base64.b64decode(metadata.nonce, validate=True)
        except (ValueError, TypeError) as exc:
            raise EvidenceKeyUnavailable("the evidence encryption key is invalid") from exc
        if len(key) != 32 or len(base_nonce) != 12:
            raise EvidenceKeyUnavailable("the evidence encryption key is invalid")

        aesgcm = AESGCM(key)
        observed_digest = sha256()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with builtins.open(metadata.encrypted_path, "rb") as source, builtins.open(output_path, "wb") as destination:
                header = source.read(_HEADER.size)
                if len(header) != _HEADER.size:
                    raise EvidenceIntegrityError("evidence envelope is truncated")
                magic, chunk_size = _HEADER.unpack(header)
                if magic != _MAGIC or not 1 <= chunk_size <= _MAX_CHUNK_SIZE:
                    raise EvidenceIntegrityError("evidence envelope header is invalid")
                index = 0
                while True:
                    encoded_length = source.read(_LENGTH.size)
                    if len(encoded_length) != _LENGTH.size:
                        raise EvidenceIntegrityError("evidence envelope is truncated")
                    plaintext_length = _LENGTH.unpack(encoded_length)[0]
                    if plaintext_length == 0:
                        if source.read(1):
                            raise EvidenceIntegrityError("evidence envelope has trailing data")
                        break
                    if plaintext_length > chunk_size:
                        raise EvidenceIntegrityError("evidence envelope chunk is invalid")
                    ciphertext = source.read(plaintext_length + 16)
                    if len(ciphertext) != plaintext_length + 16:
                        raise EvidenceIntegrityError("evidence envelope is truncated")
                    try:
                        plaintext = aesgcm.decrypt(
                            self._nonce(base_nonce, index),
                            ciphertext,
                            self._aad(
                                metadata.case_id,
                                metadata.digest,
                                metadata.purpose,
                                index,
                                plaintext_length,
                                chunk_size,
                            ),
                        )
                    except InvalidTag as exc:
                        raise EvidenceIntegrityError("evidence envelope authentication failed") from exc
                    destination.write(plaintext)
                    observed_digest.update(plaintext)
                    index += 1
            if observed_digest.hexdigest() != metadata.digest:
                raise EvidenceIntegrityError("decrypted evidence digest does not match metadata")
            return output_path
        except Exception:
            try:
                output_path.unlink()
            except FileNotFoundError:
                pass
            raise

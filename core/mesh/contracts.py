"""Versioned envelopes used by the mesh transport.

The v1 transport used ``google.protobuf.Struct`` for the complete envelope.
Struct represents every JSON number as a protobuf double, so hashing a Python
payload before transport could disagree with the value decoded by the
controller (``1`` became ``1.0``).  v2 hashes the exact canonical JSON bytes
that are carried in the typed protobuf envelope.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Any, Dict

from google.protobuf.struct_pb2 import Struct
from google.protobuf.json_format import MessageToDict


MESH_PROTOCOL_VERSION = "watchtower.mesh.v2"
LEGACY_MESH_PROTOCOL_VERSION = "watchtower.mesh.v1"
DIGEST_ALGORITHM = "canonical-json-sha256-v2"
MAX_ENVELOPE_BYTES = 2 * 1024 * 1024
VALID_ENVELOPE_TYPES = {
    "health", "sessions", "flows", "findings", "alerts", "endpoint_observations", "hardware_observations",
    "command_results", "case_bundle", "lifecycle",
}


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic JSON bytes without silently stringifying values."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def payload_hash(value: Any) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def legacy_payload_hash(value: Any) -> str:
    """Hash used by v1 spool records for local migration validation."""
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def encode_message(value: Dict[str, Any]) -> bytes:
    message = Struct()
    message.update(value)
    encoded = message.SerializeToString()
    if len(encoded) > MAX_ENVELOPE_BYTES:
        raise ValueError("Mesh message exceeds the 2 MiB transport limit")
    return encoded


def decode_message(value: bytes) -> Dict[str, Any]:
    if len(value) > MAX_ENVELOPE_BYTES:
        raise ValueError("Mesh message exceeds the 2 MiB transport limit")
    message = Struct()
    message.ParseFromString(value)
    return MessageToDict(message, preserving_proto_field_name=True)


@dataclass(frozen=True)
class TelemetryEnvelope:
    node_id: str
    sequence: int
    envelope_type: str
    payload: Dict[str, Any]
    created_at: float
    protocol_version: str = MESH_PROTOCOL_VERSION
    payload_digest: str = ""
    digest_algorithm: str = DIGEST_ALGORITHM

    def __post_init__(self):
        if not self.payload_digest:
            object.__setattr__(self, "payload_digest", payload_hash(self.payload))

    def validate(self) -> None:
        if self.protocol_version not in {MESH_PROTOCOL_VERSION, LEGACY_MESH_PROTOCOL_VERSION}:
            raise ValueError("Unsupported mesh protocol version")
        if not self.node_id or len(self.node_id) > 128:
            raise ValueError("Invalid mesh node identifier")
        if int(self.sequence) < 1:
            raise ValueError("Mesh sequence must be positive")
        if self.envelope_type not in VALID_ENVELOPE_TYPES:
            raise ValueError("Unsupported mesh telemetry type")
        if not isinstance(self.payload, dict):
            raise ValueError("Mesh payload must be an object")
        expected = payload_hash(self.payload)
        if self.digest_algorithm == "legacy-json-sha256":
            expected = legacy_payload_hash(self.payload)
        elif self.digest_algorithm != DIGEST_ALGORITHM:
            raise ValueError("Unsupported mesh payload digest algorithm")
        if self.payload_digest != expected:
            raise ValueError("Mesh payload hash mismatch")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "TelemetryEnvelope":
        envelope = cls(
            node_id=str(value.get("node_id") or ""), sequence=int(value.get("sequence") or 0),
            envelope_type=str(value.get("envelope_type") or ""), payload=dict(value.get("payload") or {}),
            created_at=float(value.get("created_at") or 0.0),
            protocol_version=str(value.get("protocol_version") or ""),
            payload_digest=str(value.get("payload_digest") or ""),
            digest_algorithm=str(value.get("digest_algorithm") or ("legacy-json-sha256" if str(value.get("protocol_version") or "") == LEGACY_MESH_PROTOCOL_VERSION else DIGEST_ALGORITHM)),
        )
        envelope.validate()
        return envelope

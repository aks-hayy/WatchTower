"""Canonical content identity for offline forensic analyses."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any, Mapping


PIPELINE_VERSION = "watchtower-forensics-v2.0"
RUNTIME_ONLY_CONFIGURATION_KEYS = frozenset({
    "analysis_mode",
    "execution_plan_digest",
    "execution_mode",
    "mode",
    "plan_sha256",
    "progress_callback",
    "rust_analysis_execution_mode",
    "temp_dir",
    "temp_path",
    "temporary_directory",
    "temporary_path",
})


@dataclass(frozen=True)
class AnalysisIdentity:
    case_id: str
    analysis_id: str
    pcap_sha256: str
    pipeline_version: str
    configuration_hash: str


def _normalized_scalar(value: Any) -> Any:
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, Path):
        return value.as_posix()
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("configuration numbers must be finite")
        return int(value) if value.is_integer() else value
    raise TypeError(f"unsupported configuration scalar: {type(value).__name__}")


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        normalized = {}
        for key, item in value.items():
            normalized_key = str(key)
            if normalized_key in RUNTIME_ONLY_CONFIGURATION_KEYS:
                continue
            normalized[normalized_key] = _normalize(item)
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_normalize(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
    return _normalized_scalar(value)


def canonical_configuration_json(configuration: Mapping[str, Any] | None) -> str:
    normalized = _normalize(configuration or {})
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def configuration_hash(configuration: Mapping[str, Any] | None) -> str:
    return sha256(canonical_configuration_json(configuration).encode("utf-8")).hexdigest()


def build_analysis_identity(
    pcap_sha256: str,
    configuration: Mapping[str, Any] | None,
    *,
    pipeline_version: str = PIPELINE_VERSION,
) -> AnalysisIdentity:
    digest = str(pcap_sha256).strip().lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("pcap_sha256 must be a 64-character hexadecimal digest")
    config_hash = configuration_hash(configuration)
    analysis_digest = sha256(
        f"{digest}\0{pipeline_version}\0{config_hash}".encode("utf-8")
    ).hexdigest()
    return AnalysisIdentity(
        case_id=f"case-{digest}",
        analysis_id=f"analysis-{analysis_digest}",
        pcap_sha256=digest,
        pipeline_version=pipeline_version,
        configuration_hash=config_hash,
    )

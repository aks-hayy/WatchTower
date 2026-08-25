"""Content-addressed calibration attestations and staleness checks."""

from __future__ import annotations

from hashlib import sha256
from importlib import metadata
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ATTESTATION_DIR = PROJECT_ROOT / "calibration" / "attestations"


def current_runtime_versions() -> Dict[str, str]:
    import sys

    result = {"python": f"{sys.version_info.major}.{sys.version_info.minor}"}
    for package in ("scapy", "SQLAlchemy"):
        try:
            result[package.lower()] = metadata.version(package)
        except metadata.PackageNotFoundError:
            result[package.lower()] = "missing"
    return result


def canonical_bytes(value: Dict[str, Any]) -> bytes:
    payload = dict(value)
    payload.pop("digest", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def document_digest(value: Dict[str, Any]) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def scoring_policy_digest(max_contribution: float, base_impact: Dict[str, Any],
                          half_life_seconds: Dict[str, Any]) -> str:
    return document_digest({
        "max_contribution": float(max_contribution),
        "base_impact": {str(key).upper(): float(value) for key, value in sorted(base_impact.items())},
        "half_life_seconds": {str(key).upper(): float(value) for key, value in sorted(half_life_seconds.items())},
    })


def file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_hashes(paths: Iterable[Path]) -> Dict[str, str]:
    result = {}
    root = PROJECT_ROOT.resolve()
    for path in sorted({Path(item).resolve() for item in paths}):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"calibration dependency is outside the repository: {path}") from exc
        if not path.is_file():
            raise ValueError(f"calibration dependency is missing: {relative}")
        result[relative] = file_digest(path)
    return result


def safe_repo_path(relative: str) -> Path:
    candidate = (PROJECT_ROOT / relative).resolve()
    try:
        candidate.relative_to(PROJECT_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"unsafe attestation path: {relative}") from exc
    return candidate


def verify_profile_attestation(
    digest: str, detector_id: str, detector_version: str, finding_type: str, level: str,
    policy_digest: str = "",
) -> Tuple[bool, str]:
    if not digest:
        return False, "missing calibration attestation"
    path = ATTESTATION_DIR / f"{digest}.json"
    if not path.is_file():
        return False, "calibration attestation is missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"invalid calibration attestation: {exc}"
    if value.get("digest") != digest or document_digest(value) != digest:
        return False, "calibration attestation digest mismatch"
    if value.get("schema_version") != 1:
        return False, "unsupported calibration attestation schema"
    if value.get("runtime_versions") != current_runtime_versions():
        return False, "calibration runtime versions changed"
    target = value.get("target") or {}
    expected = (detector_id, detector_version, finding_type, level, policy_digest)
    actual = (
        target.get("detector_id"), target.get("detector_version"),
        target.get("finding_type"), value.get("awarded_level"), target.get("policy_digest", ""),
    )
    if actual != expected:
        return False, "calibration attestation target mismatch"
    review = value.get("review") or {}
    if not str(review.get("reviewer") or "").strip() or not str(review.get("reason") or "").strip():
        return False, "calibration attestation is not reviewed"
    for collection in ("source_files", "corpus_files"):
        for relative, expected_hash in (value.get(collection) or {}).items():
            path = safe_repo_path(relative)
            if not path.is_file() or file_digest(path) != expected_hash:
                return False, f"stale calibration dependency: {relative}"
    return True, ""


def write_attestation(value: Dict[str, Any], directory: Path = None) -> Path:
    directory = Path(directory or ATTESTATION_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    payload = dict(value)
    payload["digest"] = document_digest(payload)
    path = directory / f"{payload['digest']}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)
    return path

"""Atomic management of the optional SigmaHQ rule corpus."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
from pathlib import Path
import shutil
import socket
import subprocess
from typing import Dict, List, Optional
from urllib.parse import urlparse
import uuid

import httpx
import yaml

from core.forensics.sigma_engine import validate_rule


DEFAULT_REPOSITORY = "https://github.com/SigmaHQ/sigma.git"
MAX_RULE_BYTES = 2 * 1024 * 1024
MAX_RULE_FILES = 100_000
ALLOWED_RULE_HOSTS = {"github.com", "raw.githubusercontent.com"}
UPSTREAM_RULE_DIRECTORIES = ("rules", "rules-emerging-threats", "rules-threat-hunting")


@dataclass
class SyncManifest:
    repository: str
    commit: str
    synchronized_at: str
    accepted: int
    rejected: int
    rejection_reasons: Dict[str, int]


class SigmaCorpusManager:
    def __init__(self, data_dir="data/sigma", repository=DEFAULT_REPOSITORY):
        self.root = Path(data_dir)
        self.repository = repository
        self.active = self.root / "active"
        self.previous = self.root / "previous"
        self.manifest_path = self.root / "manifest.json"
        self.previous_manifest = self.root / "manifest.previous.json"

    def status(self) -> Dict:
        manifest = self._read_manifest(self.manifest_path)
        return {
            "active": self.active.exists(),
            "daily_enabled": False,
            "repository": self.repository,
            "manifest": manifest,
        }

    def sync(self) -> SyncManifest:
        repository = self.repository
        self._validate_repository(repository)
        self.root.mkdir(parents=True, exist_ok=True)
        token = uuid.uuid4().hex
        checkout = self.root / f"checkout-{token}"
        staging = self.root / f"staging-{token}"
        try:
            self._run_git(["clone", "--depth", "1", "--filter=blob:none", repository, str(checkout)])
            commit = self._run_git(["-C", str(checkout), "rev-parse", "HEAD"])
            manifest = self._stage_rules(checkout, staging, repository, commit)
            self._activate(staging, manifest)
            return manifest
        finally:
            shutil.rmtree(checkout, ignore_errors=True)
            shutil.rmtree(staging, ignore_errors=True)

    @staticmethod
    def _run_git(arguments: List[str]) -> str:
        result = subprocess.run(
            ["git", "-c", "core.longpaths=true", *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Sigma repository Git operation failed: {detail or f'exit {result.returncode}'}")
        return result.stdout.strip()

    def rollback(self) -> SyncManifest:
        if not self.previous.exists() or not self.previous_manifest.exists():
            raise FileNotFoundError("No previous Sigma ruleset is available")
        token = uuid.uuid4().hex
        displaced = self.root / f"rollback-{token}"
        if self.active.exists(): self.active.replace(displaced)
        self.previous.replace(self.active)
        if displaced.exists(): displaced.replace(self.previous)
        current_manifest = self.root / f"manifest.rollback-{token}.json"
        if self.manifest_path.exists(): self.manifest_path.replace(current_manifest)
        self.previous_manifest.replace(self.manifest_path)
        if current_manifest.exists(): current_manifest.replace(self.previous_manifest)
        return SyncManifest(**self._read_manifest(self.manifest_path))

    @staticmethod
    def _validate_repository(repository: str):
        parsed = urlparse(repository)
        if parsed.scheme in {"http", "https"}:
            if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
                raise ValueError("Remote Sigma repositories must use HTTPS on github.com")
            return
        path = Path(repository).resolve()
        if not path.exists():
            raise ValueError("Local Sigma repository does not exist")

    def _stage_rules(self, checkout: Path, staging: Path, repository: str, commit: str) -> SyncManifest:
        staging.mkdir(parents=True)
        accepted, rejected = 0, 0
        reasons: Dict[str, int] = {}
        paths = sorted(
            path
            for directory in UPSTREAM_RULE_DIRECTORIES
            for path in (checkout / directory).rglob("*.y*ml")
            if (checkout / directory).exists()
        )
        if len(paths) > MAX_RULE_FILES:
            raise ValueError(f"Repository contains more than {MAX_RULE_FILES} YAML files")
        seen_ids = set()
        for path in paths:
            relative = path.relative_to(checkout)
            if path.is_symlink() or any(part in {"..", ".git"} for part in relative.parts):
                rejected += 1; reasons["unsafe path"] = reasons.get("unsafe path", 0) + 1; continue
            if path.stat().st_size > MAX_RULE_BYTES:
                rejected += 1; reasons["oversized rule"] = reasons.get("oversized rule", 0) + 1; continue
            try:
                rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                errors = validate_rule(rule, upstream=True)
                rule_id = str((rule or {}).get("id", ""))
                if not rule_id: errors.append("missing rule id")
                elif rule_id in seen_ids: errors.append("duplicate rule id")
                if errors:
                    rejected += 1
                    for reason in errors: reasons[reason] = reasons.get(reason, 0) + 1
                    continue
                seen_ids.add(rule_id)
                target = staging / f"{rule_id}.yml"
                target.write_text(yaml.safe_dump(rule, sort_keys=False, allow_unicode=False), encoding="utf-8")
                accepted += 1
            except Exception as exc:
                rejected += 1
                key = f"invalid YAML: {type(exc).__name__}"
                reasons[key] = reasons.get(key, 0) + 1
        if accepted == 0:
            summary = ", ".join(
                f"{reason} ({count})"
                for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:5]
            )
            raise ValueError(f"No compatible Sigma rules passed staging validation: {summary}")
        return SyncManifest(repository, commit, datetime.now(timezone.utc).isoformat(), accepted, rejected, reasons)

    def _activate(self, staging: Path, manifest: SyncManifest):
        manifest_staging = self.root / f"manifest-{uuid.uuid4().hex}.json"
        manifest_staging.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True), encoding="utf-8")
        if self.previous.exists(): shutil.rmtree(self.previous)
        if self.active.exists(): self.active.replace(self.previous)
        if self.manifest_path.exists(): self.manifest_path.replace(self.previous_manifest)
        try:
            staging.replace(self.active)
            manifest_staging.replace(self.manifest_path)
        except Exception:
            if not self.active.exists() and self.previous.exists(): self.previous.replace(self.active)
            if not self.manifest_path.exists() and self.previous_manifest.exists(): self.previous_manifest.replace(self.manifest_path)
            raise

    @staticmethod
    def _read_manifest(path: Path):
        if not path.exists(): return None
        return json.loads(path.read_text(encoding="utf-8"))


class SigmaRuleManager:
    """Inventory and safely import individual compatible Sigma rules."""

    def __init__(
        self,
        builtin_dir="core/forensics/plugins/sigma",
        data_dir="data/sigma",
    ):
        self.builtin = Path(builtin_dir)
        self.root = Path(data_dir)
        self.custom = self.root / "custom"
        self.managed = self.root / "active"

    def list_rules(self) -> List[Dict]:
        rules = []
        seen = set()
        for source, root in (("builtin", self.builtin), ("custom", self.custom), ("synchronized", self.managed)):
            if not root.exists():
                continue
            for path in sorted(root.rglob("*.y*ml")):
                try:
                    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
                    errors = validate_rule(rule)
                    rule_id = str((rule or {}).get("id") or "")
                    if rule_id and rule_id in seen:
                        errors.append(f"duplicate rule id: {rule_id}")
                    if rule_id:
                        seen.add(rule_id)
                    rules.append(self._describe(rule or {}, source, path, errors))
                except Exception as exc:
                    rules.append({
                        "id": "",
                        "title": path.name,
                        "source": source,
                        "path": str(path),
                        "compatible": False,
                        "errors": [f"invalid YAML: {exc}"],
                    })
        return rules

    def preview_url(self, url: str) -> Dict:
        content = self._fetch_url(url)
        digest = hashlib.sha256(content).hexdigest()
        try:
            rule = yaml.safe_load(content.decode("utf-8"))
        except Exception as exc:
            return {
                "url": url,
                "sha256": digest,
                "compatible": False,
                "errors": [f"invalid YAML: {exc}"],
                "content": content.decode("utf-8", errors="replace"),
            }
        errors = validate_rule(rule, upstream=True)
        description = self._describe(rule or {}, "remote", None, errors)
        description.update({
            "url": url,
            "sha256": digest,
            "content": yaml.safe_dump(rule, sort_keys=False, allow_unicode=False),
        })
        return description

    def install_url(self, url: str, expected_sha256: str) -> Dict:
        preview = self.preview_url(url)
        if not expected_sha256 or preview["sha256"].lower() != expected_sha256.lower():
            raise ValueError("Remote rule changed after preview; preview it again before loading")
        if not preview.get("compatible"):
            raise ValueError("Rule is incompatible: " + "; ".join(preview.get("errors") or []))
        rule_id = str(preview.get("id") or "")
        if not rule_id:
            raise ValueError("Rule id is required")
        self.custom.mkdir(parents=True, exist_ok=True)
        target = self.custom / f"{rule_id}.yml"
        staging = self.custom / f".{rule_id}.{uuid.uuid4().hex}.tmp"
        staging.write_text(preview["content"], encoding="utf-8")
        staging.replace(target)
        return {**preview, "source": "custom", "path": str(target), "installed": True}

    @staticmethod
    def _describe(rule: Dict, source: str, path: Optional[Path], errors: List[str]) -> Dict:
        return {
            "id": str(rule.get("id") or ""),
            "title": str(rule.get("title") or "Untitled Sigma rule"),
            "description": str(rule.get("description") or ""),
            "status": str(rule.get("status") or ""),
            "level": str(rule.get("level") or ""),
            "category": str((rule.get("logsource") or {}).get("category") or ""),
            "source": source,
            "path": str(path) if path else None,
            "compatible": not errors,
            "errors": list(errors),
        }

    def _fetch_url(self, url: str) -> bytes:
        current = url
        with httpx.Client(timeout=15.0, follow_redirects=False) as client:
            for _ in range(4):
                self._validate_rule_url(current)
                response = client.get(current, headers={"Accept": "application/yaml,text/yaml,text/plain"})
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("Remote rule redirect has no destination")
                    current = str(response.url.join(location))
                    continue
                response.raise_for_status()
                content = response.content
                if not content or len(content) > MAX_RULE_BYTES:
                    raise ValueError(f"Remote rule must be between 1 and {MAX_RULE_BYTES} bytes")
                return content
        raise ValueError("Remote rule exceeded the redirect limit")

    @staticmethod
    def _validate_rule_url(url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in ALLOWED_RULE_HOSTS:
            raise ValueError("Remote Sigma rules must use HTTPS on github.com or raw.githubusercontent.com")
        addresses = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ip_address(address).is_global for address in addresses):
            raise ValueError("Remote Sigma host did not resolve to a public address")

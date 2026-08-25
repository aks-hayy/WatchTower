"""Validate that a WatchTower source tree is safe and complete for publication."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Iterable


REQUIRED_FILES = {
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "USAGE.md",
    "Dockerfile",
    ".dockerignore",
    "compose.yaml",
    "AGENTS.md",
    "install.ps1",
    "pyproject.toml",
    "requirements.txt",
    "requirements/container.lock",
    "requirements/runtime.lock",
    "scripts/container.ps1",
    "scripts/container.sh",
    "scripts/setup.ps1",
    "scripts/setup.sh",
    "watchtower.ps1",
    "watchtower.sh",
    "ui/package-lock.json",
    "ui/package.json",
}

REQUIRED_DIRECTORIES = {
    ".github/workflows",
    "calibration/attestations",
    "calibration/corpus",
    "config/sysmon",
    "core",
    "deploy/container",
    "docs",
    "rust/watchtower-sensor/src",
    "tests",
    "tools",
    "ui/src",
}

FORBIDDEN_DIRECTORY_NAMES = {
    "__pycache__",
    ".mypy_cache",
    ".next",
    ".nitro",
    ".npm-cache",
    ".output",
    ".pytest_cache",
    ".ruff_cache",
    ".tanstack",
    ".venv",
    ".vinxi",
    ".vite",
    ".wrangler",
    "node_modules",
    "target",
}

FORBIDDEN_TOP_LEVEL = {
    ".deps",
    ".install-runtime",
    ".plugin-runtime",
    ".release-state",
    ".test-runtime",
    "data",
    "scratch",
    "watchtower_engine.egg-info",
}

PRIVATE_RUNTIME_PATHS = {
    "deploy/container/.env.container",
}

FORBIDDEN_SUFFIXES = {
    ".cap",
    ".db",
    ".db-shm",
    ".db-wal",
    ".enc",
    ".key",
    ".log",
    ".p12",
    ".pcap",
    ".pcapng",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}

MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
ATTESTATION_DIGEST = re.compile(r"attestation_digest:\s*([0-9a-f]{64})")


def _iter_source_files(root: Path) -> Iterable[Path]:
    for current, directories, files in os.walk(root):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        directories[:] = [
            name
            for name in directories
            if name != ".git"
            and name not in FORBIDDEN_DIRECTORY_NAMES
            and not (
                not relative_current.parts
                and (name in FORBIDDEN_TOP_LEVEL or name.startswith(".release-state-"))
            )
            and not (relative_current.parts == ("traffic_testing",) and name == "results")
            and not (relative_current.parts == ("deploy", "container") and name == "secrets")
        ]
        for name in files:
            yield current_path / name


def _find_forbidden_paths(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.iterdir():
        if path.name in FORBIDDEN_TOP_LEVEL or path.name.startswith(".release-state-"):
            found.append(path.relative_to(root))
    for current, directories, files in os.walk(root):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if relative_current.parts and (
            relative_current.parts[0] in FORBIDDEN_TOP_LEVEL
            or relative_current.parts[0].startswith(".release-state-")
        ):
            directories[:] = []
            continue
        removable = [name for name in directories if name in FORBIDDEN_DIRECTORY_NAMES]
        if relative_current.parts == ("deploy", "container") and "secrets" in directories:
            removable.append("secrets")
        if relative_current.parts == ("traffic_testing",) and "results" in directories:
            removable.append("results")
        for name in sorted(set(removable)):
            found.append((current_path / name).relative_to(root))
        directories[:] = [name for name in directories if name not in removable and name != ".git"]
        for name in files:
            relative = (current_path / name).relative_to(root)
            if _is_forbidden(relative):
                found.append(relative)
    return sorted(set(found))


def _tracked_files(root: Path) -> set[str]:
    if not (root / ".git").exists():
        return set()
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    return {
        value.decode("utf-8", errors="replace")
        for value in result.stdout.split(b"\0")
        if value
    }


def _untracked_files(root: Path) -> set[str]:
    if not (root / ".git").exists():
        return set()
    result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return set()
    return {
        value.decode("utf-8", errors="replace")
        for value in result.stdout.split(b"\0")
        if value
    }


def _is_forbidden(relative: Path) -> bool:
    normalized = relative.as_posix()
    if normalized in PRIVATE_RUNTIME_PATHS or normalized.startswith("deploy/container/secrets/"):
        return True
    if relative.parts and (
        relative.parts[0] in FORBIDDEN_TOP_LEVEL
        or relative.parts[0].startswith(".release-state-")
    ):
        return True
    if any(part in FORBIDDEN_DIRECTORY_NAMES for part in relative.parts[:-1]):
        return True
    if len(relative.parts) >= 2 and relative.parts[:2] == ("traffic_testing", "results"):
        return True
    name = relative.name.casefold()
    return any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES)


def _check_markdown_links(root: Path, errors: list[str]) -> None:
    markdown_files = [path for path in _iter_source_files(root) if path.suffix.casefold() == ".md"]
    for document in markdown_files:
        text = document.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            resolved = (document.parent / target).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                errors.append(f"documentation link escapes repository: {document.relative_to(root)} -> {target}")
                continue
            if not resolved.exists():
                errors.append(f"broken documentation link: {document.relative_to(root)} -> {target}")


def check_release_tree(
    root: Path,
    *,
    strict_workspace: bool = False,
    require_git_tree: bool = False,
) -> list[str]:
    root = root.resolve()
    errors: list[str] = []

    for relative in sorted(REQUIRED_FILES):
        if not (root / relative).is_file():
            errors.append(f"missing required file: {relative}")
    for relative in sorted(REQUIRED_DIRECTORIES):
        if not (root / relative).is_dir():
            errors.append(f"missing required directory: {relative}")

    if strict_workspace or not (root / ".git").exists():
        for relative in _find_forbidden_paths(root):
            errors.append(f"forbidden source artifact: {relative.as_posix()}")

    for relative_string in sorted(_tracked_files(root)):
        path = root / relative_string
        if path.exists() and _is_forbidden(Path(relative_string)):
            errors.append(f"forbidden tracked artifact: {relative_string}")

    if require_git_tree:
        tracked = _tracked_files(root)
        for relative in sorted(_untracked_files(root)):
            errors.append(f"untracked release source: {relative}")
        for relative in sorted(REQUIRED_FILES):
            if relative not in tracked:
                errors.append(f"required release file is not tracked: {relative}")
        for relative in sorted(REQUIRED_DIRECTORIES):
            prefix = relative.rstrip("/") + "/"
            if not any(path == relative or path.startswith(prefix) for path in tracked):
                errors.append(f"required release directory has no tracked files: {relative}")

    profiles = root / "core" / "detection" / "scoring_profiles.yaml"
    if profiles.is_file():
        for digest in sorted(set(ATTESTATION_DIGEST.findall(profiles.read_text(encoding="utf-8")))):
            if not (root / "calibration" / "attestations" / f"{digest}.json").is_file():
                errors.append(f"missing referenced calibration attestation: {digest}.json")

    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and 'requires-python = ">=3.12,<3.14"' not in pyproject.read_text(encoding="utf-8"):
        errors.append("pyproject.toml must require Python 3.12 or 3.13")

    contributing = root / "CONTRIBUTING.md"
    if contributing.is_file() and "MIT License" not in contributing.read_text(encoding="utf-8"):
        errors.append("CONTRIBUTING.md must use the repository MIT contribution license")

    if (root / "docs" / "guide").exists():
        errors.append("superseded docs/guide directory is still present")

    _check_markdown_links(root, errors)
    return sorted(set(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--strict-workspace", action="store_true")
    parser.add_argument("--require-git-tree", action="store_true")
    arguments = parser.parse_args(argv)
    errors = check_release_tree(
        arguments.root,
        strict_workspace=arguments.strict_workspace,
        require_git_tree=arguments.require_git_tree,
    )
    payload = {"valid": not errors, "errors": errors, "root": str(arguments.root.resolve())}
    if arguments.as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif errors:
        print("WatchTower release tree is not ready:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("WatchTower release tree is complete and publication-safe.")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

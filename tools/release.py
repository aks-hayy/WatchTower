"""Resumable WatchTower release and workspace maintenance entry point."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Iterable, Iterator


SCHEMA_VERSION = 1
SOURCE_ROOTS = {
    ".github",
    "calibration",
    "config",
    "core",
    "deploy",
    "docs",
    "rust",
    "requirements",
    "scripts",
    "tests",
    "tools",
    "traffic_testing",
    "ui",
}
SOURCE_FILES = {
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "THIRD_PARTY_NOTICES.md",
    "USAGE.md",
    ".dockerignore",
    "Dockerfile",
    "compose.yaml",
    "install.ps1",
    "watchtower.ps1",
    "watchtower.sh",
    "pyproject.toml",
    "requirements.txt",
}
ARCHIVE_NAMES = {".env", "data", "offline_analysis_test_files", "scratch"}
ARCHIVE_PREFIXES = (".acceptance-", ".calibration-")
DELETE_NAMES = {
    ".agents",
    ".codex",
    ".install-runtime",
    ".plugin-runtime",
    ".pytest_cache",
    ".ruff_cache",
    ".superpowers",
    ".venv",
    ".vite",
    "WT",
    "data_test",
    "watchtower_engine.egg-info",
}
NESTED_GENERATED_NAMES = {
    ".mypy_cache",
    ".next",
    ".nitro",
    ".npm-cache",
    ".output",
    ".pytest_cache",
    ".ruff_cache",
    ".tanstack",
    ".vinxi",
    ".vite",
    ".wrangler",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
}
DELETE_PREFIXES = (
    ".aggregate-",
    ".ai-",
    ".authoring-",
    ".dhcp-",
    ".focused-",
    ".integrated-",
    ".modbus-",
    ".perf-",
    ".phase",
    ".precalibration-",
    ".production-",
    ".release-phase",
    ".rust-",
    ".slice",
    ".stateful-",
    ".stream",
    ".task",
    ".terminal-",
    ".tls-",
    ".tmp-",
)
EVIDENCE_CACHE_PREFIXES = ("checkout-", "staging-")


class ReleaseToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkspaceItem:
    path: str
    action: str
    reason: str
    files: int
    bytes: int


@dataclass(frozen=True)
class GateSpec:
    name: str
    command: tuple[str, ...]
    timeout_seconds: float


DEFAULT_TEST_GATES = (
    ("release", ("tests/release",), 300.0),
    ("ai", ("tests/ai",), 300.0),
    ("api", ("tests/api",), 300.0),
    ("capture", ("tests/capture",), 600.0),
    ("detection", ("tests/detection",), 1200.0),
    (
        "forensics-core",
        (
            "tests/forensics/test_carving.py",
            "tests/forensics/test_forensic_conversations.py",
            "tests/forensics/test_forensic_evidence_retention.py",
            "tests/forensics/test_forensic_packet_index.py",
        ),
        600.0,
    ),
    (
        "forensics-workspace",
        (
            "tests/forensics/test_forensics_plugins.py",
            "tests/forensics/test_forensics_rebuild.py",
            "tests/forensics/test_offline_case_storage.py",
            "tests/forensics/test_offline_triage.py",
            "tests/forensics/test_packet_query_ast.py",
            "tests/forensics/test_pcap_case_lifecycle.py",
        ),
        600.0,
    ),
    (
        "forensics-rust",
        (
            "tests/forensics/test_rust_analysis_parity.py",
            "tests/forensics/test_rust_analysis_plan.py",
            "tests/forensics/test_rust_analysis_protocol.py",
            "tests/forensics/test_rust_fast_analysis.py",
            "tests/forensics/test_rust_packet_index.py",
        ),
        720.0,
    ),
    (
        "forensics-adapters",
        (
            "tests/forensics/test_streaming_analysis.py",
            "tests/forensics/test_tshark_adapter.py",
        ),
        300.0,
    ),
    ("identity", ("tests/identity",), 300.0),
    ("platform", ("tests/platform",), 600.0),
)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def _tree_stats(path: Path) -> tuple[int, int]:
    if path.is_file():
        return 1, path.stat().st_size
    files = 0
    total = 0
    for root, directories, names in os.walk(path, followlinks=False):
        directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
        for name in names:
            child = Path(root) / name
            if child.is_symlink():
                continue
            try:
                total += child.stat().st_size
                files += 1
            except OSError:
                continue
    return files, total


def _item(root: Path, path: Path, action: str, reason: str) -> WorkspaceItem:
    files, size = _tree_stats(path)
    return WorkspaceItem(path=path.relative_to(root).as_posix(), action=action, reason=reason, files=files, bytes=size)


def scan_workspace(root: Path | str) -> list[WorkspaceItem]:
    root = Path(root).resolve()
    if not (root / "pyproject.toml").is_file():
        raise ReleaseToolError(f"not a WatchTower repository: {root}")
    items: list[WorkspaceItem] = []
    for path in sorted(root.iterdir(), key=lambda value: value.name.lower()):
        name = path.name
        if name == ".git" or name in SOURCE_ROOTS or name in SOURCE_FILES:
            continue
        if name in ARCHIVE_NAMES or name.startswith(ARCHIVE_PREFIXES):
            items.append(_item(root, path, "archive", "local evidence or runtime state"))
        elif name in DELETE_NAMES or name.startswith(DELETE_PREFIXES):
            items.append(_item(root, path, "delete", "reproducible generated workspace data"))
        elif name.startswith(".") and path.is_dir():
            items.append(_item(root, path, "delete", "unrecognized generated hidden directory"))
        else:
            items.append(_item(root, path, "review", "unclassified path requires operator review"))

    for source_name in sorted(SOURCE_ROOTS):
        source_root = root / source_name
        if not source_root.is_dir():
            continue
        for current, directories, _files in os.walk(source_root, topdown=True, followlinks=False):
            current_path = Path(current)
            removable = [name for name in directories if name in NESTED_GENERATED_NAMES]
            directories[:] = [name for name in directories if name not in removable]
            for name in removable:
                generated = current_path / name
                items.append(_item(root, generated, "delete", "reproducible nested build or cache directory"))
    return sorted(items, key=lambda item: item.path)


def _hash_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_files(path: Path) -> Iterator[Path]:
    if path.is_file():
        yield path
        return
    for root, directories, names in os.walk(path, followlinks=False):
        directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
        for name in sorted(names):
            child = Path(root) / name
            if child.is_file() and not child.is_symlink():
                yield child


def _is_regenerable_evidence_cache(path: Path, root: Path) -> bool:
    """Return true only for managed Sigma synchronization worktrees."""
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except (OSError, ValueError):
        return False
    return (
        len(parts) >= 3
        and parts[0] == "data"
        and parts[1] == "sigma"
        and parts[2].startswith(EVIDENCE_CACHE_PREFIXES)
    )


def _copy_hashed(source: Path, destination: Path) -> dict:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_hash = _hash_file(source)
    if destination.is_file() and destination.stat().st_size == source.stat().st_size:
        destination_hash = _hash_file(destination)
        if source_hash == destination_hash:
            return {"bytes": source.stat().st_size, "sha256": source_hash}
    if destination.exists():
        destination.chmod(destination.stat().st_mode | stat.S_IWRITE)
    shutil.copy2(source, destination)
    destination_hash = _hash_file(destination)
    if source_hash != destination_hash:
        raise ReleaseToolError(f"archive verification failed for {source}")
    return {"bytes": source.stat().st_size, "sha256": source_hash}


def _source_snapshot_paths(root: Path) -> Iterable[Path]:
    for name in sorted(SOURCE_FILES):
        path = root / name
        if path.is_file():
            yield path
    for name in sorted(SOURCE_ROOTS):
        path = root / name
        if not path.exists():
            continue
        for child in _iter_files(path):
            if any(part in NESTED_GENERATED_NAMES for part in child.relative_to(root).parts):
                continue
            yield child


def archive_workspace(
    root: Path | str,
    destination: Path | str,
    items: Iterable[WorkspaceItem] | None = None,
) -> Path:
    root = Path(root).resolve()
    destination = Path(destination).resolve()
    if _is_within(destination, root):
        raise ReleaseToolError("archive destination must be outside the repository")
    if destination.exists() and any(destination.iterdir()):
        allowed_partial = {"source-snapshot", "local-evidence", "manifest.json.tmp"}
        existing = {path.name for path in destination.iterdir()}
        if (destination / "manifest.json").exists() or not existing <= allowed_partial:
            raise ReleaseToolError("archive destination must be absent, empty, or an incomplete WatchTower archive")
    destination.mkdir(parents=True, exist_ok=True)
    selected = list(items if items is not None else scan_workspace(root))
    records: list[dict] = []
    skipped: list[dict] = []
    excluded_generated: set[str] = set()

    def archive_file(source: Path, category: str, base: Path, allow_vanished: bool = False) -> None:
        relative = source.relative_to(base)
        target = destination / category / relative
        try:
            metadata = _copy_hashed(source, target)
        except FileNotFoundError:
            if not allow_vanished:
                raise
            skipped.append({
                "source": source.relative_to(root).as_posix(),
                "category": category,
                "reason": "runtime file vanished before it could be archived",
            })
            return
        records.append({
            "source": source.relative_to(root).as_posix(),
            "archive": target.relative_to(destination).as_posix(),
            "category": category,
            **metadata,
        })

    for source in _source_snapshot_paths(root):
        archive_file(source, "source-snapshot", root)
    for item in selected:
        if item.action != "archive":
            continue
        source = root / item.path
        if not source.exists():
            continue
        base = source.parent if source.is_file() else source
        if source.is_file():
            archive_file(source, "local-evidence", base, allow_vanished=True)
        else:
            for child in _iter_files(source):
                if _is_regenerable_evidence_cache(child, root):
                    relative = child.relative_to(root)
                    excluded_generated.add(Path(*relative.parts[:3]).as_posix())
                    continue
                relative_root = destination / "local-evidence" / source.relative_to(root)
                target = relative_root / child.relative_to(source)
                try:
                    metadata = _copy_hashed(child, target)
                except FileNotFoundError:
                    skipped.append({
                        "source": child.relative_to(root).as_posix(),
                        "category": "local-evidence",
                        "reason": "runtime file vanished before it could be archived",
                    })
                    continue
                records.append({
                    "source": child.relative_to(root).as_posix(),
                    "archive": target.relative_to(destination).as_posix(),
                    "category": "local-evidence",
                    **metadata,
                })

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repository": str(root),
        "archive_root": str(destination),
        "complete": True,
        "workspace_items": [asdict(item) for item in selected],
        "files": sorted(records, key=lambda record: (record["category"], record["source"])),
        "excluded_generated": sorted(excluded_generated),
        "skipped_files": sorted(skipped, key=lambda record: record["source"]),
    }
    manifest_path = destination / "manifest.json"
    pending = destination / "manifest.json.tmp"
    pending.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    pending.replace(manifest_path)
    return manifest_path


def _remove_readonly(function, path: str, _error) -> None:
    """Retry cleanup after making a generated Windows path writable."""
    target = Path(path)
    target.chmod(stat.S_IWRITE)
    function(path)


def _filesystem_path(path: Path) -> str:
    """Use extended Windows paths so deeply nested managed caches are removable."""
    value = str(path)
    if os.name == "nt" and not value.startswith("\\\\?\\"):
        return "\\\\?\\" + value
    return value


def _remove_tree(path: Path) -> None:
    filesystem_path = _filesystem_path(path)
    try:
        shutil.rmtree(filesystem_path, onerror=_remove_readonly)
    except OSError as exc:
        if getattr(exc, "winerror", None) != 145:
            raise
        # A first pass can expose children hidden by legacy MAX_PATH handling.
        shutil.rmtree(filesystem_path, onerror=_remove_readonly)


def apply_cleanup(root: Path | str, manifest_path: Path | str, dry_run: bool = False) -> list[str]:
    root = Path(root).resolve()
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if int(manifest.get("schema_version") or 0) != SCHEMA_VERSION or not manifest.get("complete"):
        raise ReleaseToolError("cleanup requires a complete supported archive manifest")
    if manifest.get("skipped_files"):
        raise ReleaseToolError("cleanup refuses an archive with skipped evidence files")
    archive_root = Path(str(manifest.get("archive_root") or "")).resolve()
    if _is_within(archive_root, root) or not (archive_root / "manifest.json").is_file():
        raise ReleaseToolError("cleanup archive is unavailable or inside the repository")
    removed: list[str] = []
    for raw in manifest.get("workspace_items") or []:
        if raw.get("action") not in {"archive", "delete"}:
            continue
        relative = Path(str(raw.get("path") or ""))
        target = (root / relative).resolve()
        if not _is_within(target, root) or target == root or target == root / ".git":
            raise ReleaseToolError(f"unsafe cleanup path: {relative}")
        if not target.exists():
            continue
        removed.append(relative.as_posix())
        if dry_run:
            continue
        if target.is_dir():
            _remove_tree(target)
        else:
            target.chmod(stat.S_IWRITE)
            os.unlink(_filesystem_path(target))
    return removed


def _release_input_digest(root: Path) -> str:
    digest = sha256()
    for path in sorted(_source_snapshot_paths(root), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_hash_file(path)))
    return digest.hexdigest()


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_gate_suite(
    root: Path | str,
    state_dir: Path | str,
    gates: Iterable[GateSpec],
    *,
    resume: bool = True,
) -> dict:
    root = Path(root).resolve()
    state_dir = Path(state_dir).resolve()
    if not (root / "pyproject.toml").is_file():
        raise ReleaseToolError(f"not a WatchTower repository: {root}")
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "summary.json"
    previous = {}
    if resume and state_path.is_file():
        previous = json.loads(state_path.read_text(encoding="utf-8"))
    input_digest = _release_input_digest(root)
    results: dict[str, dict] = {}

    def persist() -> None:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "input_digest": input_digest,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "gates": results,
        }
        pending = state_path.with_suffix(".json.tmp")
        pending.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        pending.replace(state_path)

    for gate in gates:
        command = list(gate.command)
        prior = (previous.get("gates") or {}).get(gate.name) or {}
        if (
            resume
            and previous.get("input_digest") == input_digest
            and prior.get("status") == "passed"
            and prior.get("command") == command
        ):
            results[gate.name] = {**prior, "reused": True}
            persist()
            continue
        log_path = state_dir / f"{gate.name}.log"
        started = time.monotonic()
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        with log_path.open("wb") as output:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=os.environ.copy(),
                stdout=output,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
            try:
                exit_code = process.wait(timeout=gate.timeout_seconds)
                status = "passed" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                _terminate_process_tree(process)
                exit_code = None
                status = "timeout"
        results[gate.name] = {
            "command": command,
            "duration_seconds": round(time.monotonic() - started, 3),
            "exit_code": exit_code,
            "log": str(log_path),
            "reused": False,
            "status": status,
            "timeout_seconds": gate.timeout_seconds,
        }
        persist()
        if status != "passed":
            break
    return json.loads(state_path.read_text(encoding="utf-8"))


def _default_test_gates(selected: set[str] | None = None) -> tuple[GateSpec, ...]:
    gates = tuple(
        GateSpec(name, (sys.executable, "-m", "pytest", *paths, "-q"), timeout)
        for name, paths, timeout in DEFAULT_TEST_GATES
    )
    if selected is None:
        return gates
    unknown = selected - {gate.name for gate in gates}
    if unknown:
        raise ReleaseToolError(f"unknown release gate(s): {', '.join(sorted(unknown))}")
    return tuple(gate for gate in gates if gate.name in selected)


def _default_archive(root: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return root.parent / f"WatchTower-workspace-archive-{timestamp}"


def _write_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    workspace = subparsers.add_parser("workspace")
    workspace_sub = workspace.add_subparsers(dest="workspace_command", required=True)
    scan = workspace_sub.add_parser("scan")
    scan.add_argument("--root", type=Path, default=Path.cwd())
    archive = workspace_sub.add_parser("archive")
    archive.add_argument("--root", type=Path, default=Path.cwd())
    archive.add_argument("--destination", type=Path)
    apply = workspace_sub.add_parser("apply")
    apply.add_argument("--root", type=Path, default=Path.cwd())
    apply.add_argument("--manifest", type=Path, required=True)
    apply.add_argument("--dry-run", action="store_true")
    gate = subparsers.add_parser("gate")
    gate_sub = gate.add_subparsers(dest="gate_command", required=True)
    gate_run = gate_sub.add_parser("run")
    gate_run.add_argument("--root", type=Path, default=Path.cwd())
    gate_run.add_argument("--state-dir", type=Path, default=Path(".release-state"))
    gate_run.add_argument("--gate", action="append", dest="gates")
    gate_run.add_argument("--no-resume", action="store_true")
    arguments = parser.parse_args(argv)

    try:
        if arguments.command == "gate":
            selected = set(arguments.gates) if arguments.gates else None
            summary = run_gate_suite(
                arguments.root,
                arguments.state_dir,
                _default_test_gates(selected),
                resume=not arguments.no_resume,
            )
            _write_json(summary)
            return 0 if all(item["status"] == "passed" for item in summary["gates"].values()) else 1
        if arguments.workspace_command == "scan":
            items = scan_workspace(arguments.root)
            _write_json({"schema_version": SCHEMA_VERSION, "items": [asdict(item) for item in items]})
        elif arguments.workspace_command == "archive":
            root = arguments.root.resolve()
            destination = arguments.destination or _default_archive(root)
            path = archive_workspace(root, destination)
            _write_json({"manifest": str(path)})
        else:
            removed = apply_cleanup(arguments.root, arguments.manifest, arguments.dry_run)
            _write_json({"dry_run": arguments.dry_run, "paths": removed})
    except (OSError, ValueError, ReleaseToolError) as exc:
        print(f"release tool error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from pathlib import Path
import json
import os
import stat
import sys

import pytest

from tools import release
from tools.release import GateSpec, ReleaseToolError, apply_cleanup, archive_workspace, run_gate_suite, scan_workspace


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='watchtower'\n", encoding="utf-8")
    (root / "core").mkdir()
    (root / "core" / "new_untracked_source.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "data").mkdir()
    (root / "data" / "watchtower.db").write_bytes(b"evidence")
    (root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (root / ".task-generated").mkdir()
    (root / ".task-generated" / "watchtower.db").write_bytes(b"generated")
    (root / "ui").mkdir()
    (root / "ui" / "app.tsx").write_text("export default 1\n", encoding="utf-8")
    (root / "ui" / "node_modules").mkdir()
    (root / "ui" / "node_modules" / "package.js").write_text("generated", encoding="utf-8")
    return root


def test_scan_preserves_source_and_classifies_local_evidence_and_generated_data(tmp_path):
    root = _repository(tmp_path)

    by_path = {item.path: item for item in scan_workspace(root)}

    assert "core" not in by_path
    assert "ui" not in by_path
    assert by_path["data"].action == "archive"
    assert by_path[".env"].action == "archive"
    assert by_path[".task-generated"].action == "delete"
    assert by_path["ui/node_modules"].action == "delete"


def test_archive_must_be_outside_repository(tmp_path):
    root = _repository(tmp_path)

    with pytest.raises(ReleaseToolError, match="outside"):
        archive_workspace(root, root / "archive")


def test_verified_archive_and_cleanup_preserve_source(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"

    manifest_path = archive_workspace(root, destination)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    removed = apply_cleanup(root, manifest_path)

    assert manifest["complete"] is True
    assert (destination / "source-snapshot" / "core" / "new_untracked_source.py").is_file()
    assert (destination / "local-evidence" / "data" / "watchtower.db").read_bytes() == b"evidence"
    assert "data" in removed
    assert ".task-generated" in removed
    assert (root / "core" / "new_untracked_source.py").is_file()
    assert (root / "ui" / "app.tsx").is_file()
    assert not (root / "data").exists()
    assert not (root / "ui" / "node_modules").exists()


def test_cleanup_rejects_manifest_path_traversal(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    manifest_path = archive_workspace(root, destination)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["workspace_items"].append({"path": "../outside", "action": "delete"})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseToolError, match="unsafe cleanup"):
        apply_cleanup(root, manifest_path)


def test_archive_records_runtime_file_that_vanishes_during_copy(tmp_path, monkeypatch):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    volatile = root / "data" / "watchtower.db-shm"
    volatile.write_bytes(b"volatile")
    from tools import release

    original = release._copy_hashed

    def copy_with_vanishing(source, target):
        if source == volatile:
            source.unlink()
        return original(source, target)

    monkeypatch.setattr(release, "_copy_hashed", copy_with_vanishing)

    manifest_path = archive_workspace(root, destination)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["complete"] is True
    assert manifest["skipped_files"] == [{
        "source": "data/watchtower.db-shm",
        "category": "local-evidence",
        "reason": "runtime file vanished before it could be archived",
    }]


def test_incomplete_archive_can_resume_with_read_only_files(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    destination_file = destination / "source-snapshot" / "core" / "new_untracked_source.py"
    destination_file.parent.mkdir(parents=True)
    destination_file.write_text("VALUE = 1\n", encoding="utf-8")
    destination_file.chmod(stat.S_IREAD)

    manifest_path = archive_workspace(root, destination)

    assert json.loads(manifest_path.read_text(encoding="utf-8"))["complete"] is True
    assert destination_file.read_text(encoding="utf-8") == "VALUE = 1\n"


def test_cleanup_removes_read_only_generated_tree(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    generated = root / "ui" / "node_modules" / "package" / "index.js"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text("generated\n", encoding="utf-8")
    generated.chmod(stat.S_IREAD)

    manifest_path = archive_workspace(root, destination)
    removed = apply_cleanup(root, manifest_path)

    assert "ui/node_modules" in removed
    assert not (root / "ui" / "node_modules").exists()


def test_sigma_checkout_is_explicitly_excluded_as_regenerable_cache(tmp_path):
    root = _repository(tmp_path)
    active = root / "data" / "sigma" / "active" / "rule.yml"
    checkout = root / "data" / "sigma" / "checkout-123" / "rule.yml"
    active.parent.mkdir(parents=True)
    checkout.parent.mkdir(parents=True)
    active.write_text("active\n", encoding="utf-8")
    checkout.write_text("cache\n", encoding="utf-8")

    manifest_path = archive_workspace(root, tmp_path / "archive")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["skipped_files"] == []
    assert manifest["excluded_generated"] == ["data/sigma/checkout-123"]
    assert (tmp_path / "archive" / "local-evidence" / "data" / "sigma" / "active" / "rule.yml").is_file()
    assert not (tmp_path / "archive" / "local-evidence" / "data" / "sigma" / "checkout-123").exists()


def test_cleanup_refuses_archive_with_skipped_evidence(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    manifest_path = archive_workspace(root, destination)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["skipped_files"] = [{"source": "data/watchtower.db", "reason": "vanished"}]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ReleaseToolError, match="skipped evidence"):
        apply_cleanup(root, manifest_path)


def test_cleanup_removes_deep_generated_tree(tmp_path):
    root = _repository(tmp_path)
    destination = tmp_path / "archive"
    generated = root / "ui" / "node_modules"
    for index in range(18):
        generated /= f"dependency-with-a-long-name-{index:02d}"
    leaf = generated / "index.js"
    if os.name == "nt":
        generated_path = "\\\\?\\" + str(generated)
        leaf_path = "\\\\?\\" + str(leaf)
        os.makedirs(generated_path)
        with open(leaf_path, "w", encoding="utf-8") as handle:
            handle.write("generated\n")
        os.chmod(leaf_path, stat.S_IREAD)
    else:
        generated.mkdir(parents=True)
        leaf.write_text("generated\n", encoding="utf-8")
        leaf.chmod(stat.S_IREAD)

    manifest_path = archive_workspace(root, destination)
    apply_cleanup(root, manifest_path)

    assert not (root / "ui" / "node_modules").exists()


def test_gate_suite_records_and_resumes_unchanged_pass(tmp_path):
    root = _repository(tmp_path)
    state_dir = tmp_path / "release-state"
    gate = GateSpec("smoke", (sys.executable, "-c", "print('green')"), 10)

    first = run_gate_suite(root, state_dir, [gate])
    second = run_gate_suite(root, state_dir, [gate])

    assert first["gates"]["smoke"]["status"] == "passed"
    assert first["gates"]["smoke"]["reused"] is False
    assert second["gates"]["smoke"]["reused"] is True
    assert "green" in (state_dir / "smoke.log").read_text(encoding="utf-8")


def test_gate_suite_stops_after_timeout(tmp_path):
    root = _repository(tmp_path)
    state_dir = tmp_path / "release-state"
    timeout = GateSpec("timeout", (sys.executable, "-c", "import time; time.sleep(5)"), 0.05)
    unreachable = GateSpec("unreachable", (sys.executable, "-c", "raise SystemExit(9)"), 10)

    result = run_gate_suite(root, state_dir, [timeout, unreachable], resume=False)

    assert result["gates"]["timeout"]["status"] == "timeout"
    assert "unreachable" not in result["gates"]


def test_default_gates_cover_each_forensics_module_once():
    root = Path(__file__).resolve().parents[2]
    configured = [
        Path(argument).name
        for gate in release._default_test_gates()
        if gate.name.startswith("forensics-")
        for argument in gate.command
        if argument.startswith("tests/forensics/")
    ]
    expected = sorted(path.name for path in (root / "tests" / "forensics").glob("test_*.py"))

    assert sorted(configured) == expected
    assert len(configured) == len(set(configured))

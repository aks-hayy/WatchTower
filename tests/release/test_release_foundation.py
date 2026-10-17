from pathlib import Path, PurePosixPath, PureWindowsPath
import json
import importlib.util
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from core import __version__
from core.backend_policy import BackendPolicyError, CaptureBackendPolicy
from core.runtime_paths import RuntimePaths


def test_version_source_reports_watchtower_2_0_rc1():
    assert __version__ == "2.0.0rc1"


def test_container_package_build_backend_is_pinned_and_uses_the_installed_environment():
    repository_root = Path(__file__).resolve().parents[2]
    container_lock = (repository_root / "requirements" / "container.lock").read_text(
        encoding="utf-8"
    )
    dockerfile = (repository_root / "Dockerfile").read_text(encoding="utf-8")

    assert not re.search(r"^setuptools==", container_lock, re.MULTILINE)
    assert 'python -m pip install "setuptools==84.0.0"' in dockerfile
    assert "python -m pip install --no-build-isolation --no-deps ." in dockerfile


def test_nitro_security_beta_is_locked_as_a_build_only_dependency():
    repository_root = Path(__file__).resolve().parents[2]
    package = json.loads(
        (repository_root / "ui" / "package.json").read_text(encoding="utf-8")
    )
    lock = json.loads(
        (repository_root / "ui" / "package-lock.json").read_text(encoding="utf-8")
    )

    assert "nitro" not in package["dependencies"]
    assert package["devDependencies"]["nitro"] == "3.0.260903-beta"
    assert lock["packages"]["node_modules/nitro"]["version"] == "3.0.260903-beta"


def test_nitro_build_uses_a_vite_version_inside_its_supported_range():
    repository_root = Path(__file__).resolve().parents[2]
    package = json.loads(
        (repository_root / "ui" / "package.json").read_text(encoding="utf-8")
    )
    lock = json.loads(
        (repository_root / "ui" / "package-lock.json").read_text(encoding="utf-8")
    )
    vite_range = package["devDependencies"]["vite"]
    locked_vite = lock["packages"]["node_modules/vite"]["version"]
    major, minor, patch = (int(part) for part in locked_vite.split(".")[:3])

    assert vite_range.startswith("^8.")
    assert (major, minor, patch) >= (8, 2, 2)


def test_windows_paths_use_localappdata_state_root(tmp_path):
    localappdata = PureWindowsPath("C:/") / "Users" / "WatchTowerTest" / "AppData" / "Local"
    paths = RuntimePaths.from_environment(
        environment={"LOCALAPPDATA": str(localappdata)},
        platform_name="Windows",
        repository_root=tmp_path,
    )

    assert paths.data == localappdata / "WatchTower"
    assert paths.config == paths.data / "config"
    assert paths.cache == paths.data / "cache"
    assert paths.logs == paths.data / "logs"
    assert paths.spool == paths.data / "spool"
    assert paths.cases == paths.data / "cases"
    assert paths.exports == paths.data / "exports"
    assert paths.temp == paths.cache / "temp"


def test_linux_paths_use_xdg_roots(tmp_path):
    paths = RuntimePaths.from_environment(
        environment={
            "XDG_STATE_HOME": "/var/state",
            "XDG_CONFIG_HOME": "/var/config",
            "XDG_CACHE_HOME": "/var/cache",
        },
        platform_name="Linux",
        repository_root=tmp_path,
    )

    assert paths.data == PurePosixPath("/var/state/watchtower")
    assert paths.config == PurePosixPath("/var/config/watchtower")
    assert paths.cache == PurePosixPath("/var/cache/watchtower")


def test_empty_linux_xdg_values_use_default_roots(tmp_path):
    paths = RuntimePaths.from_environment(
        environment={
            "HOME": "/home/analyst",
            "XDG_STATE_HOME": "",
            "XDG_CONFIG_HOME": "",
            "XDG_CACHE_HOME": "",
        },
        platform_name="Linux",
        repository_root=tmp_path,
    )

    assert paths.data == PurePosixPath("/home/analyst/.local/state/watchtower")
    assert paths.config == PurePosixPath("/home/analyst/.config/watchtower")
    assert paths.cache == PurePosixPath("/home/analyst/.cache/watchtower")


def test_portable_home_overrides_every_root(tmp_path):
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": "/portable/watchtower"},
        platform_name="Linux",
        repository_root=tmp_path,
    )

    assert paths.data == PurePosixPath("/portable/watchtower/data")
    assert paths.config == PurePosixPath("/portable/watchtower/config")
    assert paths.cache == PurePosixPath("/portable/watchtower/cache")
    assert paths.logs == PurePosixPath("/portable/watchtower/logs")
    assert paths.spool == PurePosixPath("/portable/watchtower/spool")
    assert paths.cases == PurePosixPath("/portable/watchtower/cases")
    assert paths.exports == PurePosixPath("/portable/watchtower/exports")
    assert paths.temp == PurePosixPath("/portable/watchtower/temp")


def test_runtime_home_override_is_absolute_on_the_host():
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": ".watchtower-test-runtime"},
        platform_name=platform.system(),
    )

    assert Path(paths.data).is_absolute()


def test_repository_data_is_reported_as_legacy_without_mutation(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_data.mkdir()
    marker = legacy_data / "watchtower.db"
    marker.write_text("legacy", encoding="utf-8")

    paths = RuntimePaths.from_environment(
        environment={}, platform_name="Linux", repository_root=tmp_path
    )

    assert paths.legacy_data_source == legacy_data
    assert marker.read_text(encoding="utf-8") == "legacy"


def test_explicit_legacy_adoption_copies_data_and_retains_backup(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_marker = legacy_data / "nested" / "watchtower.db"
    legacy_marker.parent.mkdir(parents=True)
    legacy_marker.write_text("legacy", encoding="utf-8")
    backup = tmp_path / "legacy-backup"
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": str(tmp_path / "runtime")},
        repository_root=tmp_path,
    )

    result = paths.adopt_legacy_data(backup_location=backup)

    assert result == backup
    assert (Path(paths.data) / "nested" / "watchtower.db").read_text(encoding="utf-8") == "legacy"
    assert (backup / "nested" / "watchtower.db").read_text(encoding="utf-8") == "legacy"
    assert legacy_marker.read_text(encoding="utf-8") == "legacy"


def test_legacy_adoption_refuses_backup_inside_legacy_source(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_data.mkdir()
    (legacy_data / "watchtower.db").write_text("legacy", encoding="utf-8")
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": str(tmp_path / "runtime")},
        repository_root=tmp_path,
    )

    with pytest.raises(ValueError, match="must not be inside the legacy source"):
        paths.adopt_legacy_data(backup_location=legacy_data / "backup")

    assert (legacy_data / "watchtower.db").read_text(encoding="utf-8") == "legacy"


def test_legacy_adoption_refuses_to_overwrite_active_data(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_data.mkdir()
    (legacy_data / "watchtower.db").write_text("legacy", encoding="utf-8")
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": str(tmp_path / "runtime")},
        repository_root=tmp_path,
    )
    active_marker = Path(paths.data) / "current.db"
    active_marker.parent.mkdir(parents=True)
    active_marker.write_text("active", encoding="utf-8")

    with pytest.raises(FileExistsError, match="active data root is not empty"):
        paths.adopt_legacy_data(backup_location=tmp_path / "legacy-backup")

    assert active_marker.read_text(encoding="utf-8") == "active"
    assert (legacy_data / "watchtower.db").read_text(encoding="utf-8") == "legacy"


def test_legacy_adoption_verifies_sqlite_backup_and_writes_hash_manifest(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_data.mkdir()
    source_db = legacy_data / "watchtower.db"
    with sqlite3.connect(source_db) as connection:
        connection.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)")
        connection.execute("INSERT INTO evidence (value) VALUES ('preserved')")

    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": str(tmp_path / "runtime")},
        repository_root=tmp_path,
    )
    backup = paths.adopt_legacy_data(backup_location=tmp_path / "legacy-backup")
    manifest = json.loads((Path(paths.data) / "migration.manifest.json").read_text(encoding="utf-8"))

    assert manifest["source_quick_check"] == "ok"
    assert manifest["backup_quick_check"] == "ok"
    assert manifest["active_quick_check"] == "ok"
    assert len(manifest["source_sha256"]) == 64
    assert manifest["backup_sha256"] == manifest["active_sha256"]
    with sqlite3.connect(Path(paths.data) / "watchtower.db") as connection:
        assert connection.execute("SELECT value FROM evidence").fetchone()[0] == "preserved"
    assert (backup / "watchtower.db").is_file()


def test_legacy_adoption_refuses_corrupt_primary_sqlite_database(tmp_path):
    legacy_data = tmp_path / "data"
    legacy_data.mkdir()
    (legacy_data / "watchtower.db").write_bytes(b"not-a-sqlite-database")
    paths = RuntimePaths.from_environment(
        environment={"WATCHTOWER_HOME": str(tmp_path / "runtime")},
        repository_root=tmp_path,
    )

    with pytest.raises(ValueError, match="integrity verification failed"):
        paths.adopt_legacy_data(backup_location=tmp_path / "legacy-backup")

    assert not Path(paths.data).exists()
    assert (legacy_data / "watchtower.db").read_bytes() == b"not-a-sqlite-database"


def test_network_capture_and_offline_replay_default_to_rust():
    policy = CaptureBackendPolicy()

    assert policy.capture_backend() == "rust"
    assert policy.replay_backend() == "rust"


def test_python_is_an_explicit_secondary_backend():
    policy = CaptureBackendPolicy()

    assert policy.capture_backend(requested_backend="python") == "python"
    assert policy.replay_backend(requested_backend="python") == "python"


def test_unsupported_backend_request_is_rejected_without_fallback():
    policy = CaptureBackendPolicy()

    with pytest.raises(BackendPolicyError, match="Unsupported backend request: go"):
        policy.capture_backend(requested_backend="go")


def test_bluetooth_hci_is_python_only_without_rust_source_support():
    policy = CaptureBackendPolicy()

    assert policy.capture_backend(source_type="bluetooth") == "python"
    with pytest.raises(BackendPolicyError, match="does not support backend: rust"):
        policy.capture_backend(source_type="bluetooth", requested_backend="rust")


def test_bluetooth_hci_uses_rust_when_its_source_declares_rust_support():
    policy = CaptureBackendPolicy()

    assert policy.capture_backend(
        source_type="bluetooth", source_backends={"python", "rust"}
    ) == "rust"


def test_setup_scripts_build_current_ui_rust_and_offer_optional_integrations():
    root = Path(__file__).resolve().parents[2]
    windows = (root / "scripts" / "setup.ps1").read_text(encoding="utf-8")
    unix = (root / "scripts" / "setup.sh").read_text(encoding="utf-8")

    assert "flow-insights" not in windows + unix
    assert "ui" in windows and "ui" in unix
    assert "build_rust_sensor.ps1" in windows
    assert "cargo build --locked --release" in unix
    assert "WithSysmon" in windows
    assert "WithNeo4j" in windows
    assert "--with-neo4j" in unix
    assert 'Invoke-Tower @("doctor", "--install-check")' in windows
    assert '"$TOWER" doctor' in unix
    assert "InstallPrerequisites" in windows
    assert "--install-prerequisites" in unix
    assert "npm run lint" in windows and "npm run lint" in unix
    assert "npm run typecheck" in windows and "npm run typecheck" in unix


def test_native_installers_use_locked_build_backend_without_isolated_downloads():
    root = Path(__file__).resolve().parents[2]
    windows = (root / "scripts" / "setup.ps1").read_text(encoding="utf-8")
    unix = (root / "scripts" / "setup.sh").read_text(encoding="utf-8")
    runtime_lock = (root / "requirements" / "runtime.lock").read_text(
        encoding="utf-8"
    )

    assert re.search(r"^setuptools==84\.0\.0$", runtime_lock, re.MULTILINE)
    assert "pip install --upgrade pip" not in windows + unix
    assert (
        'Invoke-Checked { & $Python -m pip install -c $RuntimeConstraints setuptools }'
        in windows
    )
    assert (
        'Invoke-Checked { & $Python -m pip install --no-build-isolation -c $RuntimeConstraints -e $InstallTarget }'
        in windows
    )
    assert '"$PYTHON" -m pip install -c requirements/runtime.lock setuptools' in unix
    assert (
        unix.count(
            '"$PYTHON" -m pip install --no-build-isolation -c requirements/runtime.lock -e'
        )
        == 2
    )


def test_windows_top_level_installer_offers_native_path_without_docker():
    root = Path(__file__).resolve().parents[2]
    installer = (root / "install.ps1").read_text(encoding="utf-8")
    hybrid_installer = (root / "scripts" / "install-hybrid.ps1").read_text(encoding="utf-8")

    assert 'ValidateSet("auto", "hybrid", "native")' in installer
    assert '[string]$Mode = "auto"' in installer
    assert '$ResolvedMode = "native"' in installer
    assert '$ResolvedMode = "hybrid"' in installer
    assert 'if ($ResolvedMode -eq "native")' in installer
    assert 'scripts\\setup.ps1' in installer
    assert 'scripts\\install-hybrid.ps1' in installer
    assert 'install.ps1 -Mode native' in hybrid_installer


@pytest.mark.parametrize(
    ("arguments", "docker_mock", "docker_host", "expected_path"),
    [
        ("", "", None, "NATIVE"),
        (
            "",
            "function docker { if ($args[0] -eq 'context') { '[{\"Endpoints\":{\"docker\":{\"Host\":\"npipe:////./pipe/docker_engine\"}}}]' }; $global:LASTEXITCODE=0 }",
            None,
            "HYBRID",
        ),
        (
            "",
            "function docker { if ($args[0] -eq 'context') { '[{\"Endpoints\":{\"docker\":{\"Host\":\"npipe:////./pipe/docker_engine\"}}}]' }; if ($args[0] -eq 'compose') { $global:LASTEXITCODE=1; return }; $global:LASTEXITCODE=0 }",
            None,
            "NATIVE",
        ),
        (
            "",
            "function docker { if ($args[0] -eq 'context') { '[{\"Endpoints\":{\"docker\":{\"Host\":\"npipe:////./pipe/docker_engine\"}}}]' }; if ($args[0] -eq 'info') { $global:LASTEXITCODE=1; return }; $global:LASTEXITCODE=0 }",
            None,
            "NATIVE",
        ),
        (
            "",
            "function docker { if ($args[0] -eq 'context') { '[{\"Endpoints\":{\"docker\":{\"Host\":\"tcp://203.0.113.4:2376\"}}}]' }; $global:LASTEXITCODE=0 }",
            None,
            "NATIVE",
        ),
        (
            "",
            "function docker { if ($args[0] -eq 'context') { '[{\"Endpoints\":{\"docker\":{\"Host\":\"npipe:////./pipe/docker_engine\"}}}]' }; $global:LASTEXITCODE=0 }",
            "tcp://203.0.113.4:2376",
            "NATIVE",
        ),
        ("-Mode native", "", None, "NATIVE"),
        ("-Mode hybrid", "", None, "HYBRID"),
    ],
)
def test_top_level_installer_selects_an_explicit_or_ready_default_path(
    tmp_path, arguments, docker_mock, docker_host, expected_path,
):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated installer-routing test")

    repository = tmp_path / "isolated-install"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    root = Path(__file__).resolve().parents[2]
    shutil.copyfile(root / "install.ps1", repository / "install.ps1")
    (scripts / "setup.ps1").write_text(
        "param([switch]$InstallPrerequisites,[switch]$WithSysmon,[switch]$WithNeo4j,"
        "[switch]$DisableAuth,[string]$SysmonExecutable='')\nWrite-Output 'INSTALL_PATH=NATIVE'\n$global:LASTEXITCODE=0\n",
        encoding="utf-8",
    )
    (scripts / "install-hybrid.ps1").write_text(
        "param([switch]$InstallPrerequisites,[switch]$WithSysmon,[switch]$WithNeo4j,"
        "[switch]$DisableAuth,[string]$SysmonExecutable='')\nWrite-Output 'INSTALL_PATH=HYBRID'\n$global:LASTEXITCODE=0\n",
        encoding="utf-8",
    )
    command = f"{docker_mock}; & '{repository / 'install.ps1'}' {arguments}"
    environment = os.environ.copy()
    environment["PATH"] = str(Path(pwsh).parent) + os.pathsep + os.environ.get("SystemRoot", "C:\\Windows") + "\\System32"
    environment["ProgramFiles"] = str(tmp_path / "ProgramFiles")
    environment["ProgramFiles(x86)"] = str(tmp_path / "ProgramFiles-x86")
    environment["LOCALAPPDATA"] = str(tmp_path / "LocalAppData")
    environment.pop("DOCKER_HOST", None)
    environment.pop("DOCKER_CONTEXT", None)
    if docker_host:
        environment["DOCKER_HOST"] = docker_host
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert f"INSTALL_PATH={expected_path}" in output, output
    if not arguments and not docker_mock:
        assert "native single-host edition" in output
        assert "rerun with -Mode hybrid" in output
    if not arguments and expected_path == "HYBRID":
        assert "Local Docker Desktop engine is ready" in output
    if not arguments and docker_mock and expected_path == "NATIVE":
        assert "native single-host edition" in output
        if "203.0.113.4" in docker_mock:
            assert "remote Docker contexts are not selected automatically" in output


def test_readme_makes_docker_requirement_and_native_alternative_explicit():
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")

    assert ".\\install.ps1" in readme
    assert "automatically selects" in readme
    assert "requires Docker Desktop" in readme
    assert ".\\install.ps1 -Mode native" in readme


def test_windows_uninstaller_fails_when_generated_file_removal_fails(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    repository = tmp_path / "isolated-repository"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parents[2] / "scripts" / "uninstall-hybrid.ps1"
    copied_uninstaller = scripts / "uninstall-hybrid.ps1"
    shutil.copyfile(source, copied_uninstaller)
    generated = repository / ".venv"
    generated.mkdir()
    (generated / "marker.txt").write_text("generated", encoding="utf-8")

    command = (
        "function Remove-Item { throw 'injected cleanup failure' }; "
        f"& '{copied_uninstaller}' -Force"
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "uninstall incomplete" in (result.stdout + result.stderr).lower()
    assert (generated / "marker.txt").is_file()


def test_windows_uninstaller_fails_when_owned_watchtower_process_remains(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    repository = tmp_path / "isolated-process-repository"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parents[2] / "scripts" / "uninstall-hybrid.ps1"
    copied_uninstaller = scripts / "uninstall-hybrid.ps1"
    shutil.copyfile(source, copied_uninstaller)
    generated = repository / ".venv"
    generated.mkdir()
    marker = generated / "marker.txt"
    marker.write_text("retain until process stops", encoding="utf-8")
    root_literal = str(repository).replace("'", "''")
    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); "
        f"[pscustomobject]@{{ Name='python.exe'; CommandLine='{root_literal}\\core\\daemon\\server.py'; ProcessId=424242 }} }}; "
        "function Stop-Process { [CmdletBinding()] param([int]$Id, [switch]$Force) }; "
        f"& '{copied_uninstaller}' -Force"
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "uninstall incomplete" in (result.stdout + result.stderr).lower()
    assert "watchtower process" in (result.stdout + result.stderr).lower()
    assert marker.read_text(encoding="utf-8") == "retain until process stops"


def test_windows_uninstaller_explains_access_denied_and_preserves_generated_files(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    repository = tmp_path / "isolated-access-denied-repository"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    copied_uninstaller = scripts / "uninstall-hybrid.ps1"
    shutil.copyfile(
        Path(__file__).resolve().parents[2] / "scripts" / "uninstall-hybrid.ps1",
        copied_uninstaller,
    )
    generated = repository / ".venv"
    generated.mkdir()
    marker = generated / "marker.txt"
    marker.write_text("preserve on inspection failure", encoding="utf-8")
    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); "
        "throw [System.UnauthorizedAccessException]::new('Access is denied') }; "
        f"& '{copied_uninstaller}' -Force"
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    output = (result.stdout + result.stderr).lower()
    assert result.returncode != 0
    assert "rerun powershell as administrator" in output
    assert marker.read_text(encoding="utf-8") == "preserve on inspection failure"


@pytest.mark.parametrize("purge, removes_volumes", [(False, False), (True, True)])
@pytest.mark.parametrize("neo4j_enabled", [False, True])
def test_windows_container_uninstall_preserves_state_unless_purging(
    tmp_path, purge, removes_volumes, neo4j_enabled
):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    root = tmp_path / "container-repository"
    scripts = root / "scripts"
    container_dir = root / "deploy" / "container"
    secrets = container_dir / "secrets"
    scripts.mkdir(parents=True)
    secrets.mkdir(parents=True)
    source_root = Path(__file__).resolve().parents[2]
    for relative in (
        "scripts/uninstall-hybrid.ps1",
        "scripts/container.ps1",
        "compose.yaml",
        "deploy/compose.neo4j.yaml",
        "deploy/compose.mesh.yaml",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)

    env_file = container_dir / ".env.container"
    env_file.write_text(
        "WATCHTOWER_MASTER_KEY_FILE=deploy/container/secrets/watchtower_master_key\n"
        "WATCHTOWER_DEPLOYMENT_ROLE=offline\n"
        "WATCHTOWER_MESH_BIND_ADDRESS=100.64.0.5\n"
        + (
            "WATCHTOWER_NEO4J_PASSWORD_FILE=deploy/container/secrets/watchtower_neo4j_password\n"
            if neo4j_enabled
            else ""
        ),
        encoding="utf-8",
    )
    master_key = secrets / "watchtower_master_key"
    neo4j_password = secrets / "watchtower_neo4j_password"
    master_key.write_text("fixture-key", encoding="utf-8")
    if neo4j_enabled:
        neo4j_password.write_text("fixture-neo4j-password", encoding="utf-8")
    runtime_root = tmp_path / "isolated-localappdata" / "WatchTower"
    runtime_root.mkdir(parents=True)
    runtime_marker = runtime_root / "watchtower.db"
    runtime_marker.write_text("fixture-state", encoding="utf-8")

    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); @() }; "
        "function docker { $global:LASTEXITCODE=0; Write-Output ('DOCKER_CALL: ' + ($args -join ' ')) }; "
        f"& '{scripts / 'uninstall-hybrid.ps1'}' -Force {'-Purge' if purge else ''}"
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(runtime_root.parent)
    environment.pop("WATCHTOWER_HOME", None)
    environment.pop("WATCHTOWER_DATA_DIR", None)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    down_calls = [line for line in output.splitlines() if "DOCKER_CALL:" in line and " down " in line]
    assert down_calls
    assert ("--volumes" in down_calls[-1]) is removes_volumes
    assert ("deploy/compose.neo4j.yaml" in down_calls[-1]) is neo4j_enabled
    assert "deploy/compose.mesh.yaml" in down_calls[-1]
    assert "ai-local" in down_calls[-1]
    assert "linux-sensor" in down_calls[-1]
    if purge:
        assert not env_file.exists()
        assert not secrets.exists()
        assert not runtime_marker.exists()
    else:
        assert env_file.read_text(encoding="utf-8").find("WATCHTOWER_DEPLOYMENT_ROLE=offline") >= 0
        assert master_key.read_text(encoding="utf-8") == "fixture-key"
        assert neo4j_password.exists() is neo4j_enabled
        if neo4j_enabled:
            assert neo4j_password.read_text(encoding="utf-8") == "fixture-neo4j-password"
        assert runtime_marker.read_text(encoding="utf-8") == "fixture-state"


def test_windows_native_uninstall_does_not_require_docker(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    root = tmp_path / "native-repository"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source_root = Path(__file__).resolve().parents[2]
    for relative in ("scripts/uninstall-hybrid.ps1", "scripts/container.ps1"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)

    generated = root / ".venv"
    generated.mkdir()
    marker = generated / "marker.txt"
    marker.write_text("generated native app files", encoding="utf-8")
    runtime_root = tmp_path / "isolated-localappdata" / "WatchTower"
    runtime_root.mkdir(parents=True)
    runtime_marker = runtime_root / "watchtower.db"
    runtime_marker.write_text("preserved native data", encoding="utf-8")

    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); @() }; "
        f"& '{scripts / 'uninstall-hybrid.ps1'}' -Force"
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(runtime_root.parent)
    environment.pop("WATCHTOWER_HOME", None)
    environment.pop("WATCHTOWER_DATA_DIR", None)
    environment["ProgramFiles"] = str(tmp_path / "empty-program-files")
    environment["ProgramFiles(x86)"] = str(tmp_path / "empty-program-files-x86")
    environment["PATH"] = str(tmp_path / "empty-path")
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists()
    assert runtime_marker.read_text(encoding="utf-8") == "preserved native data"
    assert not (root / "deploy" / "container" / ".env.container").exists()


@pytest.mark.parametrize(
    ("override_variable", "database_relative_path"),
    [("WATCHTOWER_HOME", Path("data") / "watchtower.db"), ("WATCHTOWER_DATA_DIR", Path("watchtower.db"))],
)
def test_windows_uninstaller_purges_the_configured_runtime_home(
    tmp_path, override_variable, database_relative_path
):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    root = tmp_path / "portable-repository"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source_root = Path(__file__).resolve().parents[2]
    for relative in ("scripts/uninstall-hybrid.ps1", "scripts/container.ps1"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)
    generated = root / ".venv"
    generated.mkdir()
    (generated / "marker.txt").write_text("generated app files", encoding="utf-8")

    custom_home = tmp_path / "portable-runtime" / "watchtower-home"
    for directory in ("data", "config", "cache", "logs"):
        (custom_home / directory).mkdir(parents=True, exist_ok=True)
    custom_marker = custom_home / database_relative_path
    custom_marker.write_text("portable user data", encoding="utf-8")
    default_home = tmp_path / "isolated-localappdata" / "WatchTower"
    default_home.mkdir(parents=True)
    default_marker = default_home / "watchtower.db"
    default_marker.write_text("unrelated default-root data", encoding="utf-8")

    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); @() }; "
        f"& '{scripts / 'uninstall-hybrid.ps1'}' -Force -Purge"
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(default_home.parent)
    environment.pop("WATCHTOWER_HOME", None)
    environment.pop("WATCHTOWER_DATA_DIR", None)
    environment[override_variable] = str(custom_home)
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert not custom_home.exists()
    assert default_marker.read_text(encoding="utf-8") == "unrelated default-root data"
    assert str(custom_home) in output


def test_windows_uninstaller_refuses_to_purge_a_filesystem_root(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    root = tmp_path / "root-guard-repository"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source_root = Path(__file__).resolve().parents[2]
    for relative in ("scripts/uninstall-hybrid.ps1", "scripts/container.ps1"):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)
    default_home = tmp_path / "isolated-localappdata" / "WatchTower"
    default_home.mkdir(parents=True)
    (default_home / "watchtower.db").write_text("test-only marker", encoding="utf-8")

    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); @() }; "
        "function Remove-Item { [CmdletBinding()] param([string]$LiteralPath, [switch]$Recurse, [switch]$Force); "
        "Write-Output ('REMOVE_ATTEMPT: ' + $LiteralPath) }; "
        f"& '{scripts / 'uninstall-hybrid.ps1'}' -Force -Purge"
    )
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(default_home.parent)
    environment["WATCHTOWER_HOME"] = Path.cwd().anchor
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "refusing to purge" in output.lower()
    assert "REMOVE_ATTEMPT:" not in output
    assert (default_home / "watchtower.db").read_text(encoding="utf-8") == "test-only marker"


@pytest.mark.parametrize(
    "process_name,command_line_suffix",
    [
        ("python.exe", r".venv\Scripts\python.exe -m uvicorn core.api.server:app"),
        ("node.exe", r"ui\.output\server\index.mjs"),
        ("tower.exe", r'.venv\Scripts\tower.exe" ui'),
    ],
)
def test_windows_uninstaller_detects_native_ui_and_api_processes(
    tmp_path, process_name, command_line_suffix
):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell 7 is required for the isolated uninstaller integration test")

    root = tmp_path / "native-process-repository"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    copied_uninstaller = scripts / "uninstall-hybrid.ps1"
    shutil.copyfile(
        Path(__file__).resolve().parents[2] / "scripts" / "uninstall-hybrid.ps1",
        copied_uninstaller,
    )
    generated = root / ".venv"
    generated.mkdir()
    marker = generated / "marker.txt"
    marker.write_text("keep while process is running", encoding="utf-8")
    root_literal = str(root).replace("'", "''")
    command_line = f'{root_literal}\\{command_line_suffix}'.replace("'", "''")
    process_literal = process_name.replace("'", "''")
    command = (
        "function Get-CimInstance { [CmdletBinding()] param([string]$ClassName, [string]$Filter); "
        f"if ($Filter.Contains(\"Name='{process_literal}'\")) "
        f"{{ [pscustomobject]@{{ Name='{process_literal}'; CommandLine='{command_line}'; ProcessId=424242 }} }} }}; "
        "function Stop-Process { [CmdletBinding()] param([int]$Id, [switch]$Force) }; "
        f"& '{copied_uninstaller}' -Force"
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "uninstall incomplete" in (result.stdout + result.stderr).lower()
    assert "watchtower process pid 424242" in (result.stdout + result.stderr).lower()
    assert marker.read_text(encoding="utf-8") == "keep while process is running"


def test_windows_setup_requires_npcap_for_python_live_capture_even_when_rust_is_skipped():
    root = Path(__file__).resolve().parents[2]
    setup = (root / "scripts" / "setup.ps1").read_text(encoding="utf-8")

    assert re.search(r"(?m)^\s*Ensure-NpcapRuntime\s*$", setup)
    rust_only_block = re.search(
        r"(?ms)if \(-not \$SkipRust\) \{(?P<body>.*?)^\s*\}", setup
    )
    assert rust_only_block
    assert "Ensure-NpcapRuntime" not in rust_only_block.group("body")
    assert "$NpcapSdk = Ensure-NpcapSdk" in setup


def test_windows_setup_process_guard_matches_only_this_repository_runtime(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for the setup process-guard regression")

    root = Path(__file__).resolve().parents[2]
    guard = root / "scripts" / "watchtower_process_guard.ps1"
    command = f"""
. '{guard}'
$processes = @(
  [pscustomobject]@{{ ProcessId = 101; Name = 'node.exe'; CommandLine = 'node C:\\Apps\\WT\\ui\\.output\\server\\index.mjs' }},
  [pscustomobject]@{{ ProcessId = 102; Name = 'python.exe'; CommandLine = 'C:\\Apps\\WT\\.venv\\Scripts\\python.exe -m uvicorn core.api.server:app' }},
  [pscustomobject]@{{ ProcessId = 103; Name = 'watchtower-sensor.exe'; CommandLine = 'C:\\Apps\\WT\\rust\\watchtower-sensor\\target\\release\\watchtower-sensor.exe capture' }},
  [pscustomobject]@{{ ProcessId = 104; Name = 'node.exe'; CommandLine = 'node C:\\Apps\\WT-copy\\ui\\.output\\server\\index.mjs' }},
  [pscustomobject]@{{ ProcessId = 105; Name = 'python.exe'; CommandLine = 'C:\\Apps\\WT\\.venv\\Scripts\\python.exe tools\\generate_report.py' }},
  [pscustomobject]@{{ ProcessId = 106; Name = 'tower.exe'; CommandLine = 'C:\\Apps\\WT\\.venv\\Scripts\\tower.exe ui --port 43961' }}
)
(Find-WatchTowerRuntimeProcesses -RepositoryRoot 'C:\\Apps\\WT' -Processes $processes | ForEach-Object ProcessId) -join ','
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "101,102,103,106"

    block_result = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-Command",
            command.replace(
                "(Find-WatchTowerRuntimeProcesses -RepositoryRoot 'C:\\Apps\\WT' -Processes $processes | ForEach-Object ProcessId) -join ','",
                "try { Assert-WatchTowerStoppedForSetup -RepositoryRoot 'C:\\Apps\\WT' -Processes $processes; 'NOT_BLOCKED' } catch { $_.Exception.Message }",
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert block_result.returncode == 0, block_result.stdout + block_result.stderr
    assert "PID(s): 101, 102, 103, 106" in block_result.stdout
    assert "Setup made no changes" in block_result.stdout


def test_windows_setup_process_guard_fails_closed_when_process_inspection_is_denied():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for the setup process-guard regression")

    root = Path(__file__).resolve().parents[2]
    guard = root / "scripts" / "watchtower_process_guard.ps1"
    command = f"""
function Get-CimInstance {{ throw 'process access denied' }}
. '{guard}'
Assert-WatchTowerStoppedForSetup -RepositoryRoot 'C:\\Apps\\WT'
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "could not safely inspect running processes" in (
        result.stdout + result.stderr
    ).lower()


def test_windows_setup_process_guard_fails_closed_for_hidden_checkout_command_line():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for the setup process-guard regression")

    root = Path(__file__).resolve().parents[2]
    guard = root / "scripts" / "watchtower_process_guard.ps1"
    command = f"""
. '{guard}'
$processes = @([pscustomobject]@{{ ProcessId = 106; Name = 'python.exe'; ExecutablePath = 'C:\\Apps\\WT\\.venv\\Scripts\\python.exe'; CommandLine = $null }})
Assert-WatchTowerStoppedForSetup -RepositoryRoot 'C:\\Apps\\WT' -Processes $processes
"""
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "could not safely identify" in (result.stdout + result.stderr).lower()


def test_windows_setup_invokes_process_guard_before_mutating_steps():
    root = Path(__file__).resolve().parents[2]
    setup = (root / "scripts" / "setup.ps1").read_text(encoding="utf-8")
    main = setup[setup.rindex("\ntry {"):]
    guard_call = main.index("Assert-WatchTowerStoppedForSetup -RepositoryRoot $Root")
    for mutation in (
        "Set-Location $Root",
        "Invoke-WebRequest",
        "npm ci",
        "npm run build",
        "pip install",
    ):
        position = main.find(mutation)
        if position >= 0:
            assert guard_call < position, f"process guard must precede {mutation}"


def _bash_executable():
    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]
    return next((candidate for candidate in candidates if candidate and Path(candidate).is_file()), None)


def _bash_path(path):
    value = Path(path).resolve().as_posix()
    if re.match(r"^[A-Za-z]:/", value):
        return f"/{value[0].lower()}{value[2:]}"
    return value


def test_posix_setup_process_guard_blocks_only_runtime_processes_from_same_checkout():
    bash = _bash_executable()
    if not bash:
        pytest.skip("Bash is required for the POSIX setup process-guard regression")

    root = Path(__file__).resolve().parents[2]
    guard = root / "scripts" / "watchtower_process_guard.sh"
    script = f"""
ps() {{
  printf '%s\\n' \
    '101 node /workspace/WT/ui/.output/server/index.mjs' \
    '102 python /workspace/WT/.venv/bin/python -m uvicorn core.api.server:app' \
    '103 tower /workspace/WT/.venv/bin/tower ui --port 43000' \
    '104 watchtower-sensor /workspace/WT/rust/watchtower-sensor/target/release/watchtower-sensor capture' \
    '105 node /workspace/WT-copy/ui/.output/server/index.mjs' \
    '106 python /workspace/WT/tools/generate_report.py'
}}
. '{_bash_path(guard)}'
watchtower_assert_stopped '/workspace/WT'
"""
    result = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert "PID(s): 101, 102, 103, 104" in result.stderr
    assert "Setup made no changes" in result.stderr


def test_posix_setup_process_guard_fails_closed_when_process_inspection_fails():
    bash = _bash_executable()
    if not bash:
        pytest.skip("Bash is required for the POSIX setup process-guard regression")

    root = Path(__file__).resolve().parents[2]
    guard = root / "scripts" / "watchtower_process_guard.sh"
    script = f"""
ps() {{ return 13; }}
. '{_bash_path(guard)}'
watchtower_assert_stopped '/workspace/WT'
"""
    result = subprocess.run([bash, "-c", script], capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert "could not safely inspect running processes" in result.stderr.lower()


def test_posix_setup_blocks_in_place_changes_when_checkout_runtime_is_active(tmp_path):
    bash = _bash_executable()
    if not bash:
        pytest.skip("Bash is required for the POSIX setup process-guard regression")

    source_root = Path(__file__).resolve().parents[2]
    checkout = tmp_path / "checkout"
    scripts = checkout / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(source_root / "scripts" / "setup.sh", scripts / "setup.sh")
    helper = source_root / "scripts" / "watchtower_process_guard.sh"
    if helper.is_file():
        shutil.copy2(helper, scripts / helper.name)
    script_path = _bash_path(scripts / "setup.sh")
    script = f"""
dirname() {{ printf '%s\\n' "${{1%/*}}"; }}
checkout_root="$(cd '{_bash_path(checkout)}' && pwd -P)"
ps() {{ printf '101 node %s\\n' "$checkout_root/ui/.output/server/index.mjs"; }}
source '{script_path}' --skip-ui --skip-rust --disable-auth --non-interactive --skip-diagnostics
"""
    result = subprocess.run([bash, "-c", script], cwd=checkout, capture_output=True, text=True, check=False)

    assert result.returncode != 0
    assert "PID(s): 101" in result.stderr
    assert "Setup made no changes" in result.stderr
    assert not (checkout / ".venv").exists()
    assert not (checkout / "ui" / ".output").exists()


def test_repository_release_tree_is_complete_and_publication_safe():
    from tools.check_release_tree import check_release_tree

    root = Path(__file__).resolve().parents[2]
    assert check_release_tree(root) == []


def test_windows_rust_builder_resolves_npcap_sdk_before_developer_shell():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "build_rust_sensor.ps1").read_text(encoding="utf-8")

    assert "Resolve-Path -LiteralPath $NpcapSdk" in script


@pytest.mark.parametrize(
    ("sdk_location", "environment_override"),
    [
        (Path(".deps") / "npcap-sdk-1.16", False),
        (Path(".deps") / "NpcapSDK", False),
        (Path("custom-sdk"), True),
    ],
)
def test_acceptance_preflight_resolves_npcap_sdk_paths(
    tmp_path, sdk_location, environment_override
):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for acceptance-runner integration tests")

    root = tmp_path / "project"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_full.ps1"
    shutil.copy2(source, scripts / source.name)
    shutil.copy2(source.with_name("acceptance_network_scope.ps1"), scripts / "acceptance_network_scope.ps1")
    sdk = root / sdk_location
    (sdk / "Include").mkdir(parents=True)
    (sdk / "Lib" / "x64").mkdir(parents=True)
    (sdk / "Include" / "pcap.h").write_text("fixture header", encoding="utf-8")
    (sdk / "Lib" / "x64" / "wpcap.lib").write_bytes(b"fixture import library")
    environment = os.environ.copy()
    environment.pop("NPCAP_SDK", None)
    if environment_override:
        environment["NPCAP_SDK"] = str(sdk.resolve())
    output = tmp_path / "acceptance-output"

    result = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(scripts / source.name),
            "-Stage",
            "preflight",
            "-OutputRoot",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        timeout=60,
    )
    report = json.loads((output / "acceptance.json").read_text(encoding="utf-8-sig"))

    assert report["tooling"]["npcap_sdk"] is True, (
        result.stdout + result.stderr + json.dumps(report["tooling"])
    )
    assert Path(report["tooling"]["npcap_sdk_path"]) == sdk.resolve()
    assert report["checks"]["npcap_sdk"]["status"] == "passed"
    acceptance = source.read_text(encoding="utf-8")
    assert '"-NpcapSdk"' in acceptance
    assert "$Results.tooling.npcap_sdk_path" in acceptance


def test_acceptance_preflight_resolves_per_user_docker_desktop_install(tmp_path):
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for acceptance-runner integration tests")

    root = tmp_path / "project"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_full.ps1"
    shutil.copy2(source, scripts / source.name)
    shutil.copy2(
        source.with_name("acceptance_network_scope.ps1"),
        scripts / "acceptance_network_scope.ps1",
    )
    local_app_data = tmp_path / "local-app-data"
    docker = local_app_data / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
    docker.parent.mkdir(parents=True)
    docker.write_bytes(b"fixture executable path; preflight must not execute it")
    output = tmp_path / "acceptance-output"
    environment = os.environ.copy()
    environment["LOCALAPPDATA"] = str(local_app_data)
    environment["PATH"] = str(Path(pwsh).parent) + os.pathsep + os.environ.get("SystemRoot", "C:\\Windows") + "\\System32"

    result = subprocess.run(
        [
            pwsh,
            "-NoProfile",
            "-File",
            str(scripts / source.name),
            "-Stage",
            "preflight",
            "-OutputRoot",
            str(output),
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        timeout=60,
    )
    report = json.loads((output / "acceptance.json").read_text(encoding="utf-8-sig"))

    assert report["tooling"]["docker"] == str(docker)


def test_acceptance_sigma_stage_runs_bundled_rule_on_isolated_synthetic_flow(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required for acceptance-runner integration tests")

    repository_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "acceptance-sigma"
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repository_root / "scripts" / "acceptance_full.ps1"),
            "-Stage",
            "sigma",
            "-OutputRoot",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((output / "acceptance.json").read_text(encoding="utf-8-sig"))
    assert report["scope"]["sigma_end_to_end"] is True
    assert report["sigma"]["status"] == "passed"
    assert report["sigma"]["match_count"] == 1
    assert report["sigma"]["rule_id"] == "c92ab6e7-9d55-4f33-80f1-4ce91010f998"
    assert report["sigma"]["persisted_alert_count"] == 1


def test_live_acceptance_scope_requires_matching_up_adapter_and_authorized_ipv4(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required for acceptance-runner scope tests")

    helper = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_network_scope.ps1"
    helper_literal = str(helper).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f". '{helper_literal}'; "
        "$adapter=[pscustomobject]@{Name='Wi-Fi';InterfaceIndex=12;Status='Up';NetworkInterfaceType='Wireless80211'}; "
        "$authorized=[pscustomobject]@{InterfaceIndex=12;IPAddress='192.168.1.227'}; "
        "$other=[pscustomobject]@{InterfaceIndex=12;IPAddress='192.168.0.127'}; "
        "$down=[pscustomobject]@{Name='Wi-Fi';InterfaceIndex=12;Status='Disconnected'}; "
        "$virtual=[pscustomobject]@{Name='Wi-Fi';InterfaceIndex=12;Status='Up';NetworkInterfaceType='Tunnel'}; "
        "[ordered]@{allowed=(Get-AcceptanceCaptureScope $adapter @($authorized) 'Wi-Fi' '192.168.1.227');"
        "wrong_address=(Get-AcceptanceCaptureScope $adapter @($other) 'Wi-Fi' '192.168.1.227');"
        "disconnected=(Get-AcceptanceCaptureScope $down @($authorized) 'Wi-Fi' '192.168.1.227');"
        "virtual=(Get-AcceptanceCaptureScope $virtual @($authorized) 'Wi-Fi' '192.168.1.227');"
        "missing=(Get-AcceptanceCaptureScope $null @() 'Wi-Fi' '192.168.1.227')} | ConvertTo-Json -Compress -Depth 5"
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["allowed"]["status"] == "passed"
    assert outcome["allowed"]["interface"] == "Wi-Fi"
    assert outcome["allowed"]["ipv4"] == "192.168.1.227"
    assert outcome["wrong_address"]["status"] == "blocked"
    assert "192.168.0.127" in outcome["wrong_address"]["detail"]
    assert outcome["disconnected"]["status"] == "blocked"
    assert outcome["virtual"]["status"] == "blocked"
    assert outcome["missing"]["status"] == "blocked"


def test_live_capture_gate_requires_both_verified_scope_and_explicit_opt_in():
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required for acceptance-runner scope tests")

    helper = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_network_scope.ps1"
    helper_literal = str(helper).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f". '{helper_literal}'; "
        "[ordered]@{missing_opt_in=(Get-AcceptanceLiveCaptureGate $true $false);"
        "missing_scope=(Get-AcceptanceLiveCaptureGate $false $true);"
        "ready=(Get-AcceptanceLiveCaptureGate $true $true)} | ConvertTo-Json -Compress -Depth 5"
    )
    result = subprocess.run(
        [shell, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["missing_opt_in"]["status"] == "blocked"
    assert "No capture was started" in outcome["missing_opt_in"]["detail"]
    assert outcome["missing_scope"]["status"] == "blocked"
    assert outcome["ready"]["status"] == "passed"


def test_live_acceptance_runner_does_not_start_capture_without_explicit_scope(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell:
        pytest.skip("PowerShell is required for acceptance-runner integration tests")

    repository_root = Path(__file__).resolve().parents[2]
    output = tmp_path / "acceptance-live-no-scope"
    result = subprocess.run(
        [
            shell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repository_root / "scripts" / "acceptance_full.ps1"),
            "-Stage",
            "live",
            "-OutputRoot",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    report = json.loads((output / "acceptance.json").read_text(encoding="utf-8-sig"))

    assert result.returncode == 1
    assert report["stages"]["live"]["status"] == "blocked"
    scope = report["checks"]["live_capture_scope"]
    assert scope["status"] == "blocked"
    assert "AuthorizedCaptureInterface" in scope["detail"]
    assert "No capture was started" in scope["detail"]
    assert not any(step["name"] == "live_capture_start" for step in report["steps"])


@pytest.mark.parametrize(
    ("approved", "duration_seconds", "expected_error"),
    [
        (False, 1800, "explicit capture approval"),
        (True, 60, "exactly 1800 seconds"),
    ],
)
def test_live_capture_runner_rejects_unapproved_or_short_runs_without_starting_daemon(
    tmp_path, approved, duration_seconds, expected_error
):
    repository_root = Path(__file__).resolve().parents[2]
    isolated_home = tmp_path / "isolated-home"
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(isolated_home)
    environment.pop("WATCHTOWER_ACCEPTANCE_LIVE_APPROVED", None)
    if approved:
        environment["WATCHTOWER_ACCEPTANCE_LIVE_APPROVED"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "acceptance_live.py"),
            "--interface",
            "Wi-Fi",
            "--ipv4",
            "192.168.1.227",
            "--duration-seconds",
            str(duration_seconds),
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
        timeout=30,
    )

    assert result.returncode != 0
    assert result.stdout.strip(), result.stderr
    outcome = json.loads(result.stdout.strip().splitlines()[-1])
    assert outcome["status"] == "blocked"
    assert expected_error in outcome["error"]
    assert not (isolated_home / "data" / "watchtower.db").exists()


def test_live_capture_runner_rejects_a_non_acceptance_runtime_home(tmp_path, monkeypatch):
    repository_root = Path(__file__).resolve().parents[2]
    runner_path = repository_root / "scripts" / "acceptance_live.py"
    spec = importlib.util.spec_from_file_location("acceptance_live_under_test", runner_path)
    runner = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(runner)

    monkeypatch.setenv("WATCHTOWER_ACCEPTANCE_LIVE_APPROVED", "1")
    monkeypatch.setenv("WATCHTOWER_HOME", str(tmp_path / "user-watchtower-home"))
    monkeypatch.setenv("WATCHTOWER_DAEMON_PORT", "54321")

    with pytest.raises(runner.CaptureBlocked, match="unique temporary acceptance directory"):
        runner._validate_request("Wi-Fi", "192.168.1.227", 1800)

    isolated_home = tmp_path / "wt-accept-regression" / "watchtower-home"
    monkeypatch.setenv("WATCHTOWER_HOME", str(isolated_home))
    assert runner._validate_request("Wi-Fi", "192.168.1.227", 1800) == isolated_home.resolve()


def test_offline_acceptance_analyzes_fixture_through_rust_cli_and_checks_persisted_findings(tmp_path):
    repository_root = Path(__file__).resolve().parents[2]
    fixture = tmp_path / "acceptance-1MiB.pcap"
    generation = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "generate_acceptance_pcaps.py"),
            "--output",
            str(fixture),
            "--size",
            "1MiB",
        ],
        cwd=repository_root,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert generation.returncode == 0, generation.stdout + generation.stderr

    home = tmp_path / "watchtower-home"
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(home)
    from core.auth import OperatorAuthService
    from core.storage.database import WatchtowerDB

    db = WatchtowerDB(data_dir=str(home / "data"))
    try:
        OperatorAuthService(db).disable_first_run()
    finally:
        db.close()

    result = subprocess.run(
        [
            sys.executable,
            str(repository_root / "scripts" / "acceptance_offline.py"),
            "--pcap",
            str(fixture),
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = json.loads(result.stdout)
    assert outcome["status"] == "passed"
    assert outcome["backend"] == "rust"
    assert outcome["report_id"] > 0
    assert outcome["report_status"] == "COMPLETE"
    assert outcome["bytes_processed"] == fixture.stat().st_size
    assert outcome["flow_count"] > 0
    assert outcome["entity_count"] > 0
    assert outcome["alert_count"] > 0
    assert outcome["expected_finding_types"] == outcome["present_finding_types"]


def test_offline_verifier_does_not_accept_a_historical_report_for_the_same_source():
    repository_root = Path(__file__).resolve().parents[2]
    helper_path = repository_root / "scripts" / "acceptance_offline.py"
    spec = importlib.util.spec_from_file_location("acceptance_offline", helper_path)
    helper = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(helper)

    historical = {"id": 14, "source": "pcap:fixture.pcap", "status": "COMPLETE"}
    assert helper._select_new_report([historical], "pcap:fixture.pcap", {14}) is None
    assert helper._select_new_report([historical], "pcap:other.pcap", {14}) is None


def test_container_acceptance_keeps_valid_json_separate_from_command_exit():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        pytest.skip("PowerShell Core is required for acceptance-runner integration tests")

    helper = Path(__file__).resolve().parents[2] / "scripts" / "acceptance_json.ps1"
    helper_literal = str(helper).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop'; "
        f". '{helper_literal}'; "
        "$validFailure = Get-CommandJsonResult -Output @('{\"status\":\"fail\"}') -ExitCode 1; "
        "$invalidSuccess = Get-CommandJsonResult -Output @('not json') -ExitCode 0; "
        "[ordered]@{valid=$validFailure.IsValid;valid_exit=$validFailure.ExitCode;"
        "reported_status=$validFailure.Report.status;invalid=$invalidSuccess.IsValid;"
        "invalid_exit=$invalidSuccess.ExitCode} | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    outcome = json.loads(result.stdout)
    assert outcome == {
        "valid": True,
        "valid_exit": 1,
        "reported_status": "fail",
        "invalid": False,
        "invalid_exit": 0,
    }
    acceptance = (helper.parent / "acceptance_docker.ps1").read_text(encoding="utf-8")
    assert 'acceptance_json.ps1' in acceptance
    assert 'Set-Check "doctor_json" $doctorResult.IsValid' in acceptance
    assert 'Set-Check "doctor_exit" ($doctorResult.ExitCode -eq 0)' in acceptance
    assert "function Remove-GeneratedSecrets" in acceptance
    assert "Remove-Item -LiteralPath $EnvFile -Force" in acceptance
    assert "Remove-Item -LiteralPath $SecretDir -Recurse -Force" in acceptance


def test_watchtower_sysmon_policy_collects_process_and_network_events_without_payloads():
    root = Path(__file__).resolve().parents[2]
    path = root / "config" / "sysmon" / "watchtower-sysmon.xml"
    document = ET.parse(path)
    event_filtering = document.getroot().find("EventFiltering")

    assert event_filtering is not None
    assert event_filtering.find("ProcessCreate") is not None
    assert event_filtering.find("NetworkConnect") is not None
    serialized = path.read_text(encoding="utf-8").lower()
    assert "clipboard" not in serialized
    assert "filecreate" not in serialized


def test_optional_neo4j_deployment_is_loopback_only_and_has_no_committed_password():
    root = Path(__file__).resolve().parents[2]
    compose = (root / "deploy" / "neo4j.compose.yml").read_text(encoding="utf-8")

    assert "127.0.0.1:7474:7474" in compose
    assert "127.0.0.1:7687:7687" in compose
    assert "${WATCHTOWER_NEO4J_PASSWORD:?" in compose
    assert "neo4j/password" not in compose.lower()


def test_acceptance_pcap_generator_streams_hashed_attack_corpus(tmp_path):
    from scripts.generate_acceptance_pcaps import generate_acceptance_pcap

    output = tmp_path / "acceptance.pcap"
    manifest = generate_acceptance_pcap(output, target_bytes=1024 * 1024, profile="detection")

    assert output.stat().st_size >= 1024 * 1024
    assert manifest["sha256"] == __import__("hashlib").sha256(output.read_bytes()).hexdigest()
    assert manifest["packet_count"] > 10_000
    assert manifest["capture_started_at"] < manifest["capture_ended_at"]
    assert set(manifest["expected_finding_types"]) >= {
        "credential.cleartext.ftp",
        "recon.port_scan",
        "recon.host_scan",
        "recon.syn_flood",
        "dns.tunnel.suspected",
        "icmp.tunnel.suspected",
        "behavior.beacon.suspected",
    }
    persisted = json.loads(output.with_suffix(".manifest.json").read_text(encoding="utf-8"))
    assert persisted == manifest

from pathlib import Path, PurePosixPath, PureWindowsPath
import json
import platform
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from core import __version__
from core.backend_policy import BackendPolicyError, CaptureBackendPolicy
from core.runtime_paths import RuntimePaths


def test_version_source_reports_watchtower_2_0_rc1():
    assert __version__ == "2.0.0rc1"


def test_windows_paths_use_localappdata_state_root(tmp_path):
    paths = RuntimePaths.from_environment(
        environment={"LOCALAPPDATA": r"C:\\Users\\Analyst\\AppData\\Local"},
        platform_name="Windows",
        repository_root=tmp_path,
    )

    assert paths.data == PureWindowsPath(r"C:\Users\Analyst\AppData\Local\WatchTower")
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
    assert "& $Tower doctor" in windows
    assert '"$TOWER" doctor' in unix
    assert "InstallPrerequisites" in windows
    assert "--install-prerequisites" in unix
    assert "npm run lint" in windows and "npm run lint" in unix
    assert "npm run typecheck" in windows and "npm run typecheck" in unix


def test_repository_release_tree_is_complete_and_publication_safe():
    from tools.check_release_tree import check_release_tree

    root = Path(__file__).resolve().parents[2]
    assert check_release_tree(root) == []


def test_windows_rust_builder_resolves_npcap_sdk_before_developer_shell():
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "build_rust_sensor.ps1").read_text(encoding="utf-8")

    assert "Resolve-Path -LiteralPath $NpcapSdk" in script


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

"""Platform-aware runtime locations for WatchTower state and artifacts."""

from __future__ import annotations

from hashlib import sha256
import json
import os
import platform
import shutil
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


@dataclass(frozen=True)
class RuntimePaths:
    """Runtime directories without implicitly migrating repository-local data."""

    data: Path | PurePosixPath | PureWindowsPath
    config: Path | PurePosixPath | PureWindowsPath
    cache: Path | PurePosixPath | PureWindowsPath
    logs: Path | PurePosixPath | PureWindowsPath
    spool: Path | PurePosixPath | PureWindowsPath
    cases: Path | PurePosixPath | PureWindowsPath
    exports: Path | PurePosixPath | PureWindowsPath
    temp: Path | PurePosixPath | PureWindowsPath
    legacy_data_source: Path | None = None

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
        platform_name: str | None = None,
        repository_root: str | Path | None = None,
    ) -> RuntimePaths:
        environment = os.environ if environment is None else environment
        platform_name = platform_name or platform.system()
        is_windows = platform_name.casefold().startswith("win")
        path_type = cls._path_type(is_windows)

        portable_home = environment.get("WATCHTOWER_HOME")
        data_override = environment.get("WATCHTOWER_DATA_DIR")
        if portable_home:
            root = path_type(portable_home)
            if isinstance(root, Path):
                root = root.expanduser().resolve()
            data = root / "data"
            config = root / "config"
            cache = root / "cache"
            logs = root / "logs"
            spool = root / "spool"
            cases = root / "cases"
            exports = root / "exports"
            temp = root / "temp"
        elif data_override:
            data = path_type(data_override)
            if isinstance(data, Path):
                data = data.expanduser().resolve()
            config = data / "config"
            cache = data / "cache"
            logs = data / "logs"
            spool = data / "spool"
            cases = data / "cases"
            exports = data / "exports"
            temp = cache / "temp"
        elif is_windows:
            local_app_data = environment.get("LOCALAPPDATA")
            if not local_app_data:
                local_app_data = str(Path.home() / "AppData" / "Local")
            data = path_type(local_app_data) / "WatchTower"
            config = data / "config"
            cache = data / "cache"
            logs = data / "logs"
            spool = data / "spool"
            cases = data / "cases"
            exports = data / "exports"
            temp = cache / "temp"
        else:
            home = path_type(environment.get("HOME") or Path.home())
            state_home = environment.get("XDG_STATE_HOME") or str(home / ".local" / "state")
            config_home = environment.get("XDG_CONFIG_HOME") or str(home / ".config")
            cache_home = environment.get("XDG_CACHE_HOME") or str(home / ".cache")
            data = path_type(state_home) / "watchtower"
            config = path_type(config_home) / "watchtower"
            cache = path_type(cache_home) / "watchtower"
            logs = data / "logs"
            spool = data / "spool"
            cases = data / "cases"
            exports = data / "exports"
            temp = cache / "temp"

        legacy_root = Path(repository_root) if repository_root is not None else Path.cwd()
        legacy_data = legacy_root / "data"
        return cls(
            data=data,
            config=config,
            cache=cache,
            logs=logs,
            spool=spool,
            cases=cases,
            exports=exports,
            temp=temp,
            legacy_data_source=legacy_data if legacy_data.is_dir() else None,
        )

    @staticmethod
    def _path_type(is_windows: bool):
        if is_windows and os.name != "nt":
            return PureWindowsPath
        if not is_windows and os.name == "nt":
            return PurePosixPath
        return Path

    def ensure(self) -> None:
        """Create active runtime directories without changing legacy data."""
        for directory in (
            self.data,
            self.config,
            self.cache,
            self.logs,
            self.spool,
            self.cases,
            self.exports,
            self.temp,
        ):
            Path(directory).mkdir(parents=True, exist_ok=True)

    def adopt_legacy_data(self, backup_location: str | Path | None = None) -> Path:
        """Explicitly copy legacy data into an empty active root with a retained backup."""
        if self.legacy_data_source is None or not self.legacy_data_source.is_dir():
            raise FileNotFoundError("No legacy data source is available to adopt")

        source = self.legacy_data_source.resolve()
        active_data = Path(self.data).resolve()
        backup = (
            Path(backup_location).resolve()
            if backup_location is not None
            else active_data.parent / f"{active_data.name}.legacy-backup"
        )
        self._validate_adoption_paths(source, active_data, backup)

        if active_data.exists() and (not active_data.is_dir() or any(active_data.iterdir())):
            raise FileExistsError("Cannot adopt legacy data: active data root is not empty")
        if backup.exists():
            raise FileExistsError("Cannot adopt legacy data: backup location already exists")

        source_database = source / "watchtower.db"
        source_hash = source_backup_hash = active_hash = None
        source_check = backup_check = active_check = None
        if source_database.is_file():
            source_check = self._verify_sqlite(source_database)
            source_hash = self._file_hash(source_database)

        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, backup)
        if source_database.is_file():
            # A SQLite backup creates a consistent copy even when an operator
            # starts the migration while the legacy controller is shutting down.
            with sqlite3.connect(str(source_database)) as source_connection:
                with sqlite3.connect(str(backup / "watchtower.db")) as backup_connection:
                    source_connection.backup(backup_connection)
            backup_check = self._verify_sqlite(backup / "watchtower.db")
            source_backup_hash = self._file_hash(backup / "watchtower.db")
        if active_data.exists():
            shutil.copytree(backup, active_data, dirs_exist_ok=True)
        else:
            shutil.copytree(backup, active_data)
        if source_database.is_file():
            active_check = self._verify_sqlite(active_data / "watchtower.db")
            active_hash = self._file_hash(active_data / "watchtower.db")
            manifest = {
                "migration_version": 1,
                "created_at": time.time(),
                "source_quick_check": source_check,
                "backup_quick_check": backup_check,
                "active_quick_check": active_check,
                "source_sha256": source_hash,
                "backup_sha256": source_backup_hash,
                "active_sha256": active_hash,
            }
            (active_data / "migration.manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
            )
        return backup

    @staticmethod
    def _verify_sqlite(path: Path) -> str:
        try:
            with sqlite3.connect(str(path)) as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            raise ValueError(f"SQLite integrity verification failed: {exc}") from exc
        if result != "ok":
            raise ValueError(f"SQLite integrity verification failed: {result}")
        return result

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _validate_adoption_paths(source: Path, active_data: Path, backup: Path) -> None:
        if RuntimePaths._overlaps(source, active_data):
            raise ValueError("Active data root must not overlap the legacy source")
        if RuntimePaths._overlaps(source, backup):
            raise ValueError("Backup location must not be inside the legacy source")
        if RuntimePaths._overlaps(active_data, backup):
            raise ValueError("Backup location must not overlap the active data root")

    @staticmethod
    def _overlaps(first: Path, second: Path) -> bool:
        try:
            first.relative_to(second)
            return True
        except ValueError:
            pass
        try:
            second.relative_to(first)
            return True
        except ValueError:
            return False

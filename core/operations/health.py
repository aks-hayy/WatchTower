"""Read-only operational diagnostics for Watchtower."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List
import shutil

from sqlalchemy import inspect, text

from core.packet_engine.config import PacketEngineConfig


@dataclass
class HealthCheck:
    name: str
    status: str
    detail: str


class HealthService:
    REQUIRED_TABLES = {"entities", "flows", "alerts", "asset_profiles", "evidence_links"}

    def __init__(self, db, config: PacketEngineConfig = None):
        self.db = db
        self.config = config or PacketEngineConfig(data_dir=str(db.data_dir.resolve()))

    def run(self) -> Dict:
        checks: List[HealthCheck] = []
        errors = self.config.validate(raise_on_error=False)
        checks.append(HealthCheck(
            "configuration", "pass" if not errors else "fail",
            "valid" if not errors else "; ".join(errors),
        ))

        try:
            with self.db.engine.connect() as connection:
                result = connection.execute(text("PRAGMA quick_check")).scalar()
            checks.append(HealthCheck("database_integrity", "pass" if result == "ok" else "fail", str(result)))
        except Exception as exc:
            checks.append(HealthCheck("database_integrity", "fail", str(exc)))

        tables = set(inspect(self.db.engine).get_table_names())
        missing = sorted(self.REQUIRED_TABLES - tables)
        checks.append(HealthCheck(
            "database_schema", "pass" if not missing else "fail",
            "all required tables present" if not missing else "missing: " + ", ".join(missing),
        ))

        data_dir = Path(self.db.data_dir)
        writable = data_dir.exists() and data_dir.is_dir()
        checks.append(HealthCheck("data_directory", "pass" if writable else "fail", str(data_dir.resolve())))
        usage = shutil.disk_usage(data_dir)
        free_mb = usage.free / (1024 * 1024)
        checks.append(HealthCheck("disk_space", "pass" if free_mb >= 512 else "warn", f"{free_mb:.0f} MB free"))

        serialized = [asdict(check) for check in checks]
        overall = "fail" if any(check.status == "fail" for check in checks) else (
            "warn" if any(check.status == "warn" for check in checks) else "pass"
        )
        return {"status": overall, "checks": serialized}


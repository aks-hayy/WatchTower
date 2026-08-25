"""Headless sensor runtime used by the Linux capture profile."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import signal
import sys
import time

from core.ai.config import CredentialStore
from core.daemon.client import DaemonClient
from core.daemon.manager import DaemonManager
from core.mesh.agent import MeshAgent
from core.storage.database import WatchtowerDB


SERVICE_ID = "watchtower-sensor"
SERVICE_ROLE = "sensor"
SERVICE_SCOPES = ("daemon.lifecycle", "capture.lifecycle", "mesh.sync")
SERVICE_CREDENTIAL = "watchtower-service-sensor"


class SensorService:
    def __init__(self, db: WatchtowerDB, interface: str, interval: int, limit: int, backend: str = "rust"):
        self.db = db
        self.interface = str(interface).strip()
        self.backend = str(backend).strip().lower()
        self.interval = max(2, min(int(interval), 3600))
        self.limit = max(1, min(int(limit), 1000))
        self.agent = MeshAgent(db)
        self.stop_requested = False
        self.daemon_started = False
        self.capture_started = False
        self.health_path = Path(db.data_dir) / "sensor-health.json"

    def ensure_identity(self) -> dict:
        store = CredentialStore()
        token = store.get(SERVICE_CREDENTIAL)
        if not token:
            token = secrets.token_urlsafe(32)
            store.set(SERVICE_CREDENTIAL, token)
        return self.db.ensure_service_principal(
            SERVICE_ID,
            SERVICE_ROLE,
            sha256(token.encode("utf-8")).hexdigest(),
            list(SERVICE_SCOPES),
        )

    def validate(self) -> None:
        if self.backend != "rust":
            raise RuntimeError("The headless sensor service requires the Rust backend")
        if not self.interface:
            raise RuntimeError("WATCHTOWER_SENSOR_INTERFACE must name a Linux capture interface")
        binary = Path(os.environ.get("WATCHTOWER_RUST_SENSOR", ""))
        if not binary.is_file():
            raise RuntimeError(f"Rust sensor binary not found: {binary}")
        if not os.access(binary, os.X_OK):
            raise RuntimeError(f"Rust sensor binary is not executable: {binary}")
        try:
            self.health_path.parent.mkdir(parents=True, exist_ok=True)
            probe = self.health_path.with_suffix(".probe")
            probe.write_text("ok", encoding="ascii")
            probe.unlink(missing_ok=True)
        except OSError as exc:
            raise RuntimeError(f"Sensor state directory is not writable: {self.health_path.parent}") from exc
        agent_required = os.environ.get("WATCHTOWER_SENSOR_AGENT", "0").strip() == "1"
        if agent_required and not self.agent.status().get("enrolled"):
            raise RuntimeError("Sensor mesh agent is not enrolled; join the controller before enabling WATCHTOWER_SENSOR_AGENT=1")

    def start(self) -> dict:
        self.validate()
        identity = self.ensure_identity()
        status = DaemonClient().get_status()
        if not status.get("running"):
            if not DaemonManager.start_daemon(silent=True):
                raise RuntimeError("WatchTower daemon did not become ready for the headless sensor")
            self.daemon_started = True
        result = DaemonClient().start_engine(self.interface, backend=self.backend, source_type="network")
        if result.get("status") == "error":
            raise RuntimeError(str(result.get("message") or "Rust capture could not start"))
        self.capture_started = True
        self._health("ready", capture_state="running", mesh_state="enrolled" if self.agent.status().get("enrolled") else "local")
        return {"service": identity, "capture": result}

    def stop(self) -> None:
        if self.capture_started:
            try:
                DaemonClient().stop_engine(self.interface)
            finally:
                self.capture_started = False
        if self.daemon_started:
            DaemonClient().shutdown()
            self.daemon_started = False
        self._health("stopped", capture_state="stopped")

    def _health(self, bootstrap_state: str, **values) -> None:
        payload = {
            "service": SERVICE_ID, "bootstrap_state": bootstrap_state,
            "interface": self.interface, "updated_at": time.time(),
            "spool_pressure": self.agent.status().get("spool_bytes", 0),
            **values,
        }
        try:
            temporary = self.health_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            temporary.replace(self.health_path)
        except OSError:
            pass

    def run(self) -> int:
        while not self.stop_requested:
            if not self.capture_started:
                try:
                    self.start()
                except Exception as exc:
                    self._health("blocked", capture_state="stopped", fatal_startup_reason=str(exc)[:500])
                    print(f"WatchTower sensor waiting for configuration: {exc}", file=sys.stderr)
                    for _ in range(20):
                        if self.stop_requested:
                            break
                        time.sleep(0.5)
                    continue
            if os.environ.get("WATCHTOWER_SENSOR_AGENT", "0").strip() == "1":
                try:
                    sync = self.agent.sync_once(self.limit)
                    self._health("ready", capture_state="running", mesh_state="connected",
                                 last_synchronization=time.time(), pending_envelopes=sync.get("pending_envelopes", 0))
                except Exception as exc:
                    self._health("ready", capture_state="running", mesh_state="degraded", last_sync_error=str(exc)[:500])
            for _ in range(self.interval * 2):
                if self.stop_requested:
                    break
                time.sleep(0.5)
        self.stop()
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the WatchTower headless Linux sensor")
    parser.add_argument("--interface", default=os.environ.get("WATCHTOWER_SENSOR_INTERFACE", ""))
    parser.add_argument("--backend", choices=("rust",), default="rust")
    parser.add_argument("--interval", type=int, default=int(os.environ.get("WATCHTOWER_SENSOR_SYNC_INTERVAL", "10")))
    parser.add_argument("--limit", type=int, default=int(os.environ.get("WATCHTOWER_SENSOR_SYNC_LIMIT", "250")))
    args = parser.parse_args()
    db = WatchtowerDB()
    service = SensorService(db, args.interface, args.interval, args.limit, args.backend)
    signal.signal(signal.SIGTERM, lambda *_args: setattr(service, "stop_requested", True))
    signal.signal(signal.SIGINT, lambda *_args: setattr(service, "stop_requested", True))
    try:
        return service.run()
    except Exception as exc:
        print(f"WatchTower sensor startup failed: {exc}", file=sys.stderr)
        return 78
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

"""Background lifecycle manager for mesh controller and sensor agent processes."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict

import psutil


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
    temporary.replace(path)


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        return {}


def _alive(pid: int) -> bool:
    try:
        process = psutil.Process(int(pid))
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except (psutil.Error, ValueError, TypeError):
        return False


class MeshRuntimeManager:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.controller_dir = self.data_dir / "mesh" / "controller"
        self.agent_dir = self.data_dir / "mesh" / "agent"

    def controller_status(self) -> Dict[str, Any]:
        return self._status(self.controller_dir)

    def agent_status(self) -> Dict[str, Any]:
        return self._status(self.agent_dir)

    def start_controller(self) -> Dict[str, Any]:
        from core.storage.database import WatchtowerDB
        from core.mesh.service import MeshControllerService

        db = WatchtowerDB(str(self.data_dir))
        try:
            service = MeshControllerService(db)
            config = service._config()
            if not service.authority.ready or not config.get("advertised_address"):
                raise RuntimeError("Run 'tower mesh controller setup' before starting the controller")
        finally:
            db.close()
        return self._start("controller-serve", self.controller_dir)

    def start_agent(self, interval: int = 10, limit: int = 250) -> Dict[str, Any]:
        from core.storage.database import WatchtowerDB
        from core.mesh.agent import MeshAgent

        db = WatchtowerDB(str(self.data_dir))
        try:
            if not MeshAgent(db).status().get("enrolled"):
                raise RuntimeError("Run 'tower mesh agent join' before starting the agent")
        finally:
            db.close()
        return self._start(
            "agent-run", self.agent_dir,
            ["--interval", str(max(1, int(interval))), "--limit", str(max(1, min(int(limit), 1000)))],
        )

    def stop_controller(self, timeout: float = 15.0) -> Dict[str, Any]:
        return self._stop(self.controller_dir, timeout, "ingestion drained")

    def stop_agent(self, timeout: float = 15.0) -> Dict[str, Any]:
        return self._stop(self.agent_dir, timeout, "telemetry flush completed")

    def restart_controller(self) -> Dict[str, Any]:
        self.stop_controller()
        return self.start_controller()

    def restart_agent(self, interval: int = 10, limit: int = 250) -> Dict[str, Any]:
        self.stop_agent()
        return self.start_agent(interval, limit)

    def _start(self, command: str, directory: Path, extra: list[str] | None = None) -> Dict[str, Any]:
        current = self._status(directory)
        if current.get("running"):
            return current
        stop_path = directory / "stop.request"
        stop_path.unlink(missing_ok=True)
        log_path = directory / "runtime.log"
        try:
            log_handle = log_path.open("ab")
        except PermissionError:
            # A previous elevated install may have left its runtime log with
            # an owner-only ACL. Keep durable runtime state in place, but use
            # a user-writable log so the current operator can still start the
            # sensor runtime without manual ACL repair.
            log_path = Path(tempfile.gettempdir()) / f"watchtower-{directory.name}-runtime.log"
            log_handle = log_path.open("ab")
        arguments = [
            sys.executable, "-m", "core.mesh.runtime", command,
            "--data-dir", str(self.data_dir), *(extra or []),
        ]
        creation_flags = 0
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        with log_handle:
            process = subprocess.Popen(
                arguments,
                cwd=str(Path(__file__).resolve().parents[2]),
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                close_fds=os.name != "nt",
                creationflags=creation_flags,
            )
        _write_json(directory / "runtime.json", {
            "state": "starting", "pid": process.pid, "started_at": time.time(),
            "log_path": str(log_path),
        })
        deadline = time.time() + 8.0
        while time.time() < deadline:
            status = self._status(directory)
            if status.get("state") == "running":
                return status
            if not _alive(process.pid):
                break
            time.sleep(0.1)
        status = self._status(directory)
        if not status.get("running"):
            raise RuntimeError(
                f"Mesh process failed to start. Review {log_path}"
                + (f": {status.get('error')}" if status.get("error") else "")
            )
        return status

    def _stop(self, directory: Path, timeout: float, reason: str) -> Dict[str, Any]:
        status = self._status(directory)
        if not status.get("running"):
            status["state"] = "stopped"
            status["running"] = False
            return status
        (directory / "stop.request").write_text(str(time.time()), encoding="ascii")
        deadline = time.time() + max(2.0, float(timeout))
        while time.time() < deadline:
            status = self._status(directory)
            if not status.get("running"):
                status["drain_result"] = reason
                return status
            time.sleep(0.2)
        raise RuntimeError(
            f"Mesh process did not complete its drain within {timeout:.0f}s; it remains running"
        )

    @staticmethod
    def _status(directory: Path) -> Dict[str, Any]:
        state = _read_json(directory / "runtime.json")
        pid = int(state.get("pid") or 0)
        running = bool(pid and _alive(pid))
        if not running and state.get("state") in {"running", "starting", "draining"}:
            state["state"] = "failed" if state.get("error") else "stopped"
        return {**state, "running": running}


def _controller_serve(data_dir: str) -> int:
    from core.storage.database import WatchtowerDB
    from core.mesh.service import MeshControllerService
    from core.mesh.transport import MeshGrpcServer

    db = WatchtowerDB(data_dir)
    service = MeshControllerService(db)
    config = service._config()
    directory = Path(data_dir) / "mesh" / "controller"
    state_path = directory / "runtime.json"
    stop_path = directory / "stop.request"
    server = MeshGrpcServer(
        service,
        str(config.get("bind_host") or "127.0.0.1"),
        int(config.get("enrollment_port") or 9443),
        int(config.get("ingest_port") or 9444),
    )
    try:
        addresses = server.start()
        _write_json(state_path, {
            "state": "running", "pid": os.getpid(), "started_at": time.time(),
            "addresses": addresses, "mode": config.get("mode"),
        })
        while not stop_path.exists():
            time.sleep(0.2)
        _write_json(state_path, {
            "state": "draining", "pid": os.getpid(), "started_at": _read_json(state_path).get("started_at"),
            "drain_started_at": time.time(), "addresses": addresses,
        })
        server.stop()
        _write_json(state_path, {
            "state": "stopped", "pid": os.getpid(), "stopped_at": time.time(),
            "completion_reason": "operator_stop_after_ingestion_drain",
        })
        return 0
    except Exception as exc:
        _write_json(state_path, {
            "state": "failed", "pid": os.getpid(), "failed_at": time.time(), "error": str(exc)[:1000],
        })
        return 1
    finally:
        stop_path.unlink(missing_ok=True)
        db.close()


def _agent_run(data_dir: str, interval: int, limit: int) -> int:
    from core.storage.database import WatchtowerDB
    from core.mesh.agent import MeshAgent

    db = WatchtowerDB(data_dir)
    agent = MeshAgent(db)
    directory = Path(data_dir) / "mesh" / "agent"
    state_path = directory / "runtime.json"
    stop_path = directory / "stop.request"
    started_at = time.time()
    try:
        _write_json(state_path, {
            "state": "running", "pid": os.getpid(), "started_at": started_at,
            "interval_seconds": interval,
        })
        while not stop_path.exists():
            result = agent.sync_once(limit)
            _write_json(state_path, {
                "state": "running", "pid": os.getpid(), "started_at": started_at,
                "last_sync_at": time.time(), "last_result": result, "interval_seconds": interval,
            })
            deadline = time.time() + interval
            while time.time() < deadline and not stop_path.exists():
                time.sleep(0.2)
        _write_json(state_path, {
            "state": "draining", "pid": os.getpid(), "started_at": started_at,
            "drain_started_at": time.time(),
        })
        final = agent.flush_once()
        _write_json(state_path, {
            "state": "stopped", "pid": os.getpid(), "stopped_at": time.time(),
            "completion_reason": "operator_stop_after_telemetry_flush", "last_result": final,
        })
        return 0
    except Exception as exc:
        _write_json(state_path, {
            "state": "failed", "pid": os.getpid(), "failed_at": time.time(), "error": str(exc)[:1000],
        })
        return 1
    finally:
        stop_path.unlink(missing_ok=True)
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["controller-serve", "agent-run"])
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--interval", type=int, default=10)
    parser.add_argument("--limit", type=int, default=250)
    arguments = parser.parse_args()
    if arguments.command == "controller-serve":
        return _controller_serve(arguments.data_dir)
    return _agent_run(arguments.data_dir, max(1, arguments.interval), max(1, min(arguments.limit, 1000)))


if __name__ == "__main__":
    raise SystemExit(main())

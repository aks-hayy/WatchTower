import os
import sys
import time
import subprocess
import uuid
import json
from pathlib import Path
import psutil
from core.context import context
from core.daemon.client import DaemonClient

class DaemonManager:
    """
    Handles the lifecycle of the Watchtower Daemon service, including
    startup, shutdown, and health monitoring.
    """
    
    @staticmethod
    def ensure_running(silent=False):
        """
        Ensures the daemon is active. If not, attempts to start it
        (prompting for elevation if necessary).
        """
        client = DaemonClient()
        status = client.get_status()
        
        if status.get("running"):
            if not silent: print("[Watchtower] Daemon is active.")
            return True

        # Not running, need to start it
        # The hybrid sensor daemon is a local service coordinator. It does not
        # need an elevated operator shell just to bind its loopback control
        # socket; capture privileges are enforced by the selected backend.
        if not context.is_admin and os.environ.get("WATCHTOWER_SENSOR_SERVICE") != "1":
            if silent: return False
            print("[Watchtower] Daemon is not running and requires Administrator privileges to start.")
            print("[Watchtower] Please grant permission in the UAC prompt...")
            
            # Start the daemon script elevated
            daemon_script = os.path.join(context.root_dir, "core", "daemon", "server.py")
            context.run_elevated(sys.executable, f'"{daemon_script}"', context.root_dir)
            
            # Wait for daemon to respond to status check
            for _ in range(20): # 10 seconds timeout
                time.sleep(0.5)
                if client.get_status().get("running"):
                    if not silent: print("[Watchtower] Daemon started and connected.")
                    return True
            
            print("[ERROR] Daemon failed to start or respond.")
            return False
            
        return DaemonManager.start_daemon(silent=silent)

    @staticmethod
    def start_daemon(silent=False):
        """Launches the daemon process."""
        daemon_script = os.path.join(context.root_dir, "core", "daemon", "server.py")
        
        if not os.path.exists(daemon_script):
            print(f"[ERROR] Daemon server script not found: {daemon_script}")
            return False

        if not silent: print(f"[Watchtower] Starting Daemon service...")
        
        try:
            # Generate key BEFORE starting to ensure it's ready for early connections
            DaemonManager.get_or_create_key()
            
            if sys.platform == 'win32':
                # CREATE_NEW_CONSOLE can inherit a broken interactive console
                # across UAC/PowerShell boundaries and leave the caller stuck
                # inside CreateProcess. The daemon is a background service;
                # detach its stdio and give it its own process group instead.
                creation_flags = (
                    getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                    | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                )
                subprocess.Popen(
                    [sys.executable, daemon_script],
                    creationflags=creation_flags,
                    cwd=context.root_dir,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(
                    [sys.executable, daemon_script],
                    start_new_session=True,
                    cwd=context.root_dir
                )
            
            # Wait for daemon to respond to status check
            client = DaemonClient()
            for _ in range(15): # 7.5 seconds timeout
                time.sleep(0.5)
                if client.get_status().get("running"):
                    if not silent: print("[Watchtower] Daemon started successfully.")
                    return True
            
            print("[ERROR] Daemon failed to respond after startup.")
            return False
            
        except Exception as e:
            print(f"[ERROR] Failed to launch daemon: {e}")
            return False

    @staticmethod
    def get_or_create_key():
        """Ensures a fresh daemon key is present."""
        os.makedirs(context.data_dir, exist_ok=True)
        try:
            with open(context.daemon_key_file, "x", encoding="ascii") as handle:
                handle.write(uuid.uuid4().hex)
        except FileExistsError:
            # Multiple launcher/worker paths can initialize the daemon at the
            # same time on Windows. Exclusive creation prevents one process
            # from replacing a key another already-bound listener is using.
            pass
        with open(context.daemon_key_file, "r", encoding="ascii") as handle:
            return handle.read().strip()

    @staticmethod
    def stop_daemon():
        """Sends a shutdown command to the daemon."""
        client = DaemonClient()
        return client.shutdown()

    @staticmethod
    def restart_daemon(silent=False):
        client = DaemonClient()
        status = client.get_status()
        if status.get("running"):
            result = client.shutdown()
            if result.get("status") == "error":
                return {"status": "error", "message": result.get("message") or "Daemon shutdown failed"}
            for _ in range(20):
                time.sleep(0.25)
                if not client.get_status().get("running"):
                    break
            else:
                return {"status": "error", "message": "Daemon did not stop within five seconds"}
        started = DaemonManager.ensure_running(silent=silent)
        return {"status": "restarted" if started else "error", "running": bool(started)}

    @staticmethod
    def repair_state(force=False):
        """Repair stale daemon state, optionally stopping one verified daemon PID."""
        path = Path(context.data_dir) / "daemon.instance.json"
        status = DaemonClient().get_status()
        if status.get("running"):
            return {
                "status": "healthy",
                "daemon_instance_id": status.get("daemon_instance_id"),
                "pid": status.get("pid"),
            }

        listener_pids = {
            int(connection.pid)
            for connection in psutil.net_connections(kind="tcp")
            if connection.pid
            and connection.status == psutil.CONN_LISTEN
            and connection.laddr
            and int(connection.laddr.port) == int(context.daemon_port)
        }

        def terminate_listener(process, pid, executable):
            process.terminate()
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            return {
                "status": "repaired",
                "message": "Terminated the verified stale WatchTower daemon listener",
                "pid": pid,
                "executable": executable,
            }

        if not path.exists():
            if force:
                for listener_pid in sorted(listener_pids):
                    try:
                        process = psutil.Process(listener_pid)
                        executable = str(Path(process.exe()).resolve())
                        working_directory = str(Path(process.cwd()).resolve())
                        verified_owner = (
                            Path(executable).name.casefold() in {"python.exe", "pythonw.exe"}
                            and working_directory.casefold() == str(Path(context.root_dir).resolve()).casefold()
                        )
                        if not verified_owner:
                            continue
                        return terminate_listener(process, listener_pid, executable)
                    except (psutil.Error, OSError, ValueError):
                        continue
            return {"status": "clean", "message": "No stale daemon state was present"}
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        pid = int(state.get("pid") or 0)
        if pid and psutil.pid_exists(pid):
            try:
                process = psutil.Process(pid)
                if pid not in listener_pids:
                    path.unlink(missing_ok=True)
                    return {
                        "status": "repaired",
                        "message": "Removed stale daemon identity; recorded process was not listening on the daemon port",
                        "pid": pid,
                    }
                executable = str(Path(process.exe()).resolve())
                expected_executable = str(Path(state.get("executable") or "").resolve())
                working_directory = str(Path(process.cwd()).resolve())
                expected_directory = str(Path(context.root_dir).resolve())
                same_recorded_interpreter = (
                    Path(executable).name.casefold() == Path(expected_executable).name.casefold()
                    and Path(executable).name.casefold() in {"python.exe", "pythonw.exe"}
                )
                verified_owner = (
                    bool(expected_executable)
                    and (
                        executable.casefold() == expected_executable.casefold()
                        or same_recorded_interpreter
                    )
                    and working_directory.casefold() == expected_directory.casefold()
                )
                if force and verified_owner:
                    result = terminate_listener(process, pid, executable)
                    path.unlink(missing_ok=True)
                    result["message"] = "Terminated the verified stale WatchTower daemon and removed its identity record"
                    return result
                return {
                    "status": "blocked",
                    "message": (
                        "The recorded process is still alive but is not answering WatchTower commands"
                        if verified_owner else
                        "The recorded PID is alive but could not be verified as the recorded WatchTower daemon"
                    ),
                    "pid": pid,
                    "executable": executable,
                }
            except (psutil.Error, OSError):
                return {
                    "status": "blocked",
                    "message": "The recorded PID is still allocated and cannot be verified safely",
                    "pid": pid,
                }
        path.unlink(missing_ok=True)
        return {
            "status": "repaired",
            "message": "Removed a stale daemon identity record; no process was terminated",
            "stale_instance": state.get("daemon_instance_id"),
        }

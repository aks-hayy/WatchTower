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
        if not context.is_admin:
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
                subprocess.Popen(
                    [sys.executable, daemon_script],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=context.root_dir
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
        if not os.path.exists(context.daemon_key_file):
            os.makedirs(context.data_dir, exist_ok=True)
            new_key = uuid.uuid4().hex
            with open(context.daemon_key_file, "w") as f:
                f.write(new_key)
            return new_key
        
        with open(context.daemon_key_file, "r") as f:
            return f.read().strip()

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
    def repair_state():
        """Remove only a verified stale daemon identity record."""
        path = Path(context.data_dir) / "daemon.instance.json"
        status = DaemonClient().get_status()
        if status.get("running"):
            return {
                "status": "healthy",
                "daemon_instance_id": status.get("daemon_instance_id"),
                "pid": status.get("pid"),
            }
        if not path.exists():
            return {"status": "clean", "message": "No stale daemon state was present"}
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state = {}
        pid = int(state.get("pid") or 0)
        if pid and psutil.pid_exists(pid):
            try:
                process = psutil.Process(pid)
                return {
                    "status": "blocked",
                    "message": "The recorded process is still alive but is not answering WatchTower commands",
                    "pid": pid,
                    "executable": process.exe(),
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

import os
import json
import socket
from core.context import context


class DaemonClient:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = context.daemon_port
        self.key_file = context.daemon_key_file
        self._timeout = 10.0  # Increased from 3s — daemon may be doing heavy I/O

    def _get_key(self):
        if not os.path.exists(self.key_file):
            return None
        try:
            with open(self.key_file, "r") as f:
                return f.read().strip()
        except Exception:
            return None

    def _recv_line(self, sock):
        """Read a complete newline-terminated JSON line from socket.
        Handles responses larger than a single recv() buffer.
        """
        buf = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
            if len(buf) > 131072:  # 128KB safety limit
                break
        return buf.decode("utf-8", errors="replace").strip()

    def _send_command(self, command_dict):
        auth_key = self._get_key()
        if not auth_key:
            return {"status": "error", "message": "Daemon key missing. Is the daemon running?"}

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self._timeout)
                s.connect((self.host, self.port))

                # Step 1: Authenticate
                s.sendall((json.dumps({"auth": auth_key}) + "\n").encode("utf-8"))
                auth_resp_raw = self._recv_line(s)
                if not auth_resp_raw:
                    return {"status": "error", "message": "No auth response from daemon"}

                auth_resp = json.loads(auth_resp_raw)
                if auth_resp.get("status") != "authenticated":
                    return {"status": "error", "message": "Daemon authentication failed"}

                # Step 2: Send command
                s.sendall((json.dumps(command_dict) + "\n").encode("utf-8"))
                resp_raw = self._recv_line(s)
                if not resp_raw:
                    return {"status": "error", "message": "Empty command response from daemon"}
                return json.loads(resp_raw)

        except ConnectionRefusedError:
            return {"status": "error", "message": f"Daemon not running (port {self.port})"}
        except socket.timeout:
            return {"status": "error", "message": f"Daemon timed out after {self._timeout}s"}
        except json.JSONDecodeError as e:
            return {"status": "error", "message": f"Invalid JSON response: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def heartbeat(self, duration=60):
        return self._send_command({"action": "heartbeat", "duration": duration})

    def set_background(self, enabled=True):
        return self._send_command({"action": "background", "enabled": enabled})

    def shutdown(self):
        return self._send_command({"action": "shutdown"})

    def start_engine(self, interface):
        return self._send_command({"action": "start", "interface": interface})

    def stop_engine(self, interface):
        return self._send_command({"action": "stop", "interface": interface})

    def get_status(self):
        resp = self._send_command({"action": "status"})
        if resp.get("status") == "error":
            return {"running": False}
        return resp

    def dump_pcap(self, interface, filename):
        return self._send_command({"action": "dump", "interface": interface, "filename": filename})

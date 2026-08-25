"""Local WatchTower API and analyst UI process launcher."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import webbrowser

from core.context import context


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.25)
        return probe.connect_ex(("127.0.0.1", int(port))) == 0


def _tail(path: Path, lines: int = 20) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def _http_ready(url: str, contains: str = "") -> bool:
    try:
        with urlopen(url, timeout=0.75) as response:
            body = response.read(262144).decode("utf-8", errors="replace")
            return 200 <= response.status < 400 and (not contains or contains.casefold() in body.casefold())
    except (HTTPError, URLError, OSError, TimeoutError):
        return False


def _wait_for_http(url: str, process, log_path: Path, contains: str = "", timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _http_ready(url, contains):
            return
        if process is not None and process.poll() is not None:
            details = _tail(log_path)
            raise RuntimeError(f"Service exited before becoming healthy at {url}" + (f"\n{details}" if details else ""))
        time.sleep(0.15)
    details = _tail(log_path)
    raise RuntimeError(f"Service did not become healthy at {url} within {timeout:.0f}s" + (f"\n{details}" if details else ""))


def launch_ui(console, port: int = 4173, api_port: int = 8000, open_browser: bool = True) -> None:
    ui_dir = Path(context.root_dir) / "ui"
    vite = ui_dir / "node_modules" / ".bin" / ("vite.cmd" if sys.platform == "win32" else "vite")
    production_server = ui_dir / ".output" / "server" / "index.mjs"
    if not (ui_dir / "package.json").exists():
        raise RuntimeError(f"UI package not found at {ui_dir}")
    if not production_server.exists() and not vite.exists():
        raise RuntimeError(f"UI dependencies are not installed. Run npm install in {ui_dir}")

    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    owned = []
    log_handles = []
    api_process = None
    ui_process = None
    logs_dir = Path(context.logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    api_log = logs_dir / f"ui-api-{stamp}.log"
    ui_log = logs_dir / f"ui-server-{stamp}.log"
    try:
        if not _port_open(api_port):
            api_handle = api_log.open("a", encoding="utf-8")
            log_handles.append(api_handle)
            api_process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "core.api.server:app", "--host", "127.0.0.1", "--port", str(api_port)],
                cwd=context.root_dir,
                stdout=api_handle,
                stderr=subprocess.STDOUT,
                creationflags=creation_flags,
            )
            owned.append(api_process)
            _wait_for_http(f"http://127.0.0.1:{api_port}/api/v1/health", api_process, api_log, '"status"')
        else:
            try:
                _wait_for_http(
                    f"http://127.0.0.1:{api_port}/api/v1/health", None, api_log, '"status"', timeout=5.0,
                )
            except RuntimeError as exc:
                raise RuntimeError(f"Port {api_port} is occupied by a service that is not the WatchTower API") from exc

        if not _port_open(port):
            environment = os.environ.copy()
            api_url = f"http://127.0.0.1:{api_port}/api/v1"
            environment["WATCHTOWER_API_URL"] = api_url
            environment["WATCHTOWER_API_ORIGIN"] = f"http://127.0.0.1:{api_port}"
            environment["VITE_WATCHTOWER_API_URL"] = "/api/v1"
            environment.update({"PORT": str(port), "HOST": "127.0.0.1", "NITRO_PORT": str(port), "NITRO_HOST": "127.0.0.1"})
            if production_server.exists():
                node = shutil.which("node")
                if not node:
                    raise RuntimeError("Node.js is required to run the WatchTower production UI")
                command = [node, str(production_server)]
            else:
                command = [str(vite), "--host", "127.0.0.1", "--port", str(port)]
            if sys.platform == "win32" and not production_server.exists():
                command = [os.environ.get("COMSPEC", "cmd.exe"), "/c", *command]
            ui_handle = ui_log.open("a", encoding="utf-8")
            log_handles.append(ui_handle)
            ui_process = subprocess.Popen(
                command,
                cwd=str(ui_dir),
                env=environment,
                stdout=ui_handle,
                stderr=subprocess.STDOUT,
                creationflags=creation_flags,
            )
            owned.append(ui_process)
            _wait_for_http(
                f"http://127.0.0.1:{port}/api/v1/health",
                ui_process,
                ui_log,
                '"status"',
            )
        else:
            try:
                _wait_for_http(
                    f"http://127.0.0.1:{port}/api/v1/health",
                    None,
                    ui_log,
                    '"status"',
                    timeout=5.0,
                )
            except RuntimeError as exc:
                raise RuntimeError(f"Port {port} is occupied by a service that is not the WatchTower UI") from exc

        url = f"http://127.0.0.1:{port}"
        console.print(f"[bold cyan]WatchTower UI[/bold cyan]  {url}")
        mode = "production" if production_server.exists() else "development"
        console.print(f"[dim]Local API: http://127.0.0.1:{api_port}/api/v1  |  {mode} bundle  |  Ctrl+C to stop services started here[/dim]")
        if open_browser:
            webbrowser.open(url)
        if not owned:
            return
        while all(process.poll() is None for process in owned):
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopping local UI services...[/dim]")
    finally:
        for process in reversed(owned):
            if process.poll() is None:
                process.terminate()
        for process in reversed(owned):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for handle in log_handles:
            handle.close()

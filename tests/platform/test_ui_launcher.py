import pytest
import psutil
import subprocess
import sys
import threading
import time

from core.ui_launcher import _managed_ui_ready, _stop_process_tree, launch_ui


class _Response:
    def __init__(self, body=b"", status=200):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, *_args):
        return self._body


def test_managed_ui_readiness_requires_every_current_page_asset(monkeypatch):
    requested = []

    def open_url(url, timeout):
        if url.endswith("/ai"):
            return _Response(
                b'<link rel="stylesheet" href="/assets/missing.js">'
                b'<script type="module" src="/assets/entry.js"></script>'
            )

    def http_ready(url, contains=""):
        requested.append(url)
        return url.endswith("/health") or url.endswith("/entry.js")

    monkeypatch.setattr("core.ui_launcher._http_ready", http_ready)
    monkeypatch.setattr("core.ui_launcher.urlopen", open_url)

    assert not _managed_ui_ready(43100)
    assert "http://127.0.0.1:43100/assets/missing.js" in requested


def test_managed_ui_readiness_accepts_healthy_page_and_assets(monkeypatch):
    def open_url(url, timeout):
        if url.endswith("/ai"):
            return _Response(
                b'<link rel="stylesheet" href="/assets/ui.css">'
                b'<link rel="modulepreload" href="/assets/entry.js">'
            )
        return _Response(b'{"status":"ok"}')

    monkeypatch.setattr("core.ui_launcher._http_ready", lambda url, contains="": True)
    monkeypatch.setattr("core.ui_launcher.urlopen", open_url)

    assert _managed_ui_ready(43100)


def test_launcher_reports_stale_occupied_ui_without_stopping_it(monkeypatch):
    monkeypatch.setattr("core.ui_launcher._port_open", lambda port: True)
    monkeypatch.setattr("core.ui_launcher._managed_ui_ready", lambda port: False)
    monkeypatch.setattr("core.ui_launcher._http_ready", lambda url, contains="": True)

    with pytest.raises(RuntimeError, match="bundle is incomplete or stale"):
        launch_ui(console=None, port=43100, api_port=43101, open_browser=False)


def test_launcher_shutdown_stops_the_real_interpreter_and_its_children():
    child_code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); time.sleep(60)"
    process = subprocess.Popen(
        [sys.executable, "-c", child_code],
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    process_tree_pids = {process.pid}
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                root = psutil.Process(process.pid)
                descendants = root.children(recursive=True)
                process_tree_pids.update(child.pid for child in descendants)
                if descendants:
                    break
            except psutil.NoSuchProcess:
                break
            time.sleep(0.05)
        assert len(process_tree_pids) > 1, "fixture did not create a child process"

        _stop_process_tree(process)

        assert all(not psutil.pid_exists(pid) for pid in process_tree_pids)
    finally:
        if psutil.pid_exists(process.pid):
            _stop_process_tree(process)


def test_launcher_keyboard_interrupt_cleans_up_virtualenv_interpreter_descendant(monkeypatch, tmp_path):
    ui_dir = tmp_path / "ui"
    (ui_dir / "node_modules" / ".bin").mkdir(parents=True)
    (ui_dir / "package.json").write_text("{}", encoding="utf-8")
    (ui_dir / "node_modules" / ".bin" / "vite.cmd").write_text("", encoding="utf-8")
    logs_dir = tmp_path / "logs"
    launched = []
    process_tree_pids = set()
    real_popen = subprocess.Popen
    child_code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); time.sleep(60)"

    def launch_fixture(*_args, **kwargs):
        process = real_popen(
            [sys.executable, "-c", child_code],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
        )
        launched.append(process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                descendants = psutil.Process(process.pid).children(recursive=True)
                process_tree_pids.update(descendant.pid for descendant in descendants)
                if descendants:
                    break
            except psutil.NoSuchProcess:
                break
            threading.Event().wait(0.05)
        process_tree_pids.add(process.pid)
        return process

    class Console:
        @staticmethod
        def print(*_args, **_kwargs):
            pass

    monkeypatch.setattr("core.ui_launcher.context.root_dir", str(tmp_path))
    monkeypatch.setattr("core.ui_launcher.context.logs_dir", str(logs_dir))
    monkeypatch.setattr("core.ui_launcher._port_open", lambda _port: False)
    monkeypatch.setattr("core.ui_launcher._wait_for_http", lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()))
    monkeypatch.setattr("core.ui_launcher.subprocess.Popen", launch_fixture)

    launch_ui(Console(), port=43110, api_port=43111, open_browser=False)

    assert launched
    assert len(process_tree_pids) > 1
    assert all(not psutil.pid_exists(pid) for pid in process_tree_pids)

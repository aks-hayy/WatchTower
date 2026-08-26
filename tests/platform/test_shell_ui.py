from unittest.mock import Mock

from core.cli.shell import WatchtowerShell


def test_interactive_ui_uses_shared_launcher(monkeypatch):
    launcher = Mock()
    monkeypatch.setattr("core.ui_launcher.launch_ui", launcher)

    WatchtowerShell.do_ui(
        object(),
        "--port 4300 --api-port 8300 --no-open",
    )

    launcher.assert_called_once()
    assert launcher.call_args.kwargs == {
        "port": 4300,
        "api_port": 8300,
        "open_browser": False,
    }


def test_interactive_ui_rejects_invalid_port(monkeypatch):
    launcher = Mock()
    monkeypatch.setattr("core.ui_launcher.launch_ui", launcher)

    WatchtowerShell.do_ui(object(), "--port 70000")

    launcher.assert_not_called()


def test_interactive_ui_contains_launcher_failure(monkeypatch):
    launcher = Mock(side_effect=RuntimeError("API did not start"))
    output = Mock()
    monkeypatch.setattr("core.ui_launcher.launch_ui", launcher)
    monkeypatch.setattr("core.cli.shell.console", output)

    WatchtowerShell.do_ui(object(), "--no-open")

    launcher.assert_called_once()
    output.print.assert_called_once()
    assert "API did not start" in output.print.call_args.args[0]

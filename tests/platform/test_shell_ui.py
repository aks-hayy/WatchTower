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

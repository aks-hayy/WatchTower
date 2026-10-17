import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from core.cli.ux import capture_completion_message, capture_source_inventory, capture_succeeded, command_family, quick_status
from core.capture_sources.base import CaptureDevice


class CliUxTests(unittest.TestCase):
    def run_main_with_calibration_result(self, arguments, result):
        from importlib import import_module
        from io import StringIO
        from unittest.mock import patch
        from rich.console import Console

        cli = import_module("core.packet_engine.main")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        with tempfile.TemporaryDirectory(prefix="watchtower-cli-calibration-") as runtime:
            with patch.dict(os.environ, {"WATCHTOWER_HOME": runtime}), \
                 patch.object(cli.sys, "argv", ["tower", *arguments]), \
                 patch.object(cli, "console", console), \
                 patch("core.calibration.service.CalibrationService.verify", return_value=result):
                try:
                    cli.main()
                    exit_code = 0
                except SystemExit as exc:
                    exit_code = int(exc.code or 0)
        return exit_code, output.getvalue()

    @staticmethod
    def run_cli(*arguments, input_text=None, timeout=30):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="watchtower-cli-help-") as runtime:
            environment = os.environ.copy()
            environment["WATCHTOWER_HOME"] = runtime
            return subprocess.run(
                [sys.executable, "-m", "core.packet_engine.main", *arguments],
                cwd=root,
                env=environment,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )

    def test_root_help_prioritizes_task_commands_without_legacy_alias_noise(self):
        result = self.run_cli("--help")

        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        self.assertIn("Common tasks", output)
        self.assertIn("monitor", output)
        self.assertIn("investigate", output)
        self.assertIn("chat", output)
        self.assertNotIn("flows", output)
        self.assertNotIn("plugins", output)
        self.assertNotIn("mesh", output)

    def test_help_all_shows_hidden_commands_and_legacy_routes_still_parse(self):
        all_help = self.run_cli("help", "--all")
        legacy_help = self.run_cli("flows", "--help")

        self.assertEqual(all_help.returncode, 0, all_help.stderr)
        self.assertIn("tower flows", all_help.stdout)
        self.assertIn("tower plugins", all_help.stdout)
        self.assertEqual(legacy_help.returncode, 0, legacy_help.stderr)
        self.assertIn("usage: tower flows", legacy_help.stdout)
        self.assertIn("--source SOURCE", legacy_help.stdout)

    def test_pin_setup_fails_fast_with_recovery_guidance_without_a_terminal(self):
        with tempfile.TemporaryDirectory(prefix="watchtower-cli-auth-nontty-") as runtime:
            root = Path(__file__).resolve().parents[2]
            environment = os.environ.copy()
            environment["WATCHTOWER_HOME"] = runtime
            result = subprocess.run(
                [sys.executable, "-m", "core.packet_engine.main", "auth", "setup"],
                cwd=root,
                env=environment,
                input="",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )

        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("interactive terminal", output.lower())
        self.assertIn("tower ui", output)
        self.assertNotIn("Traceback", output)

    def test_ui_launch_failure_does_not_contradict_specific_recovery(self):
        from importlib import import_module
        from unittest.mock import Mock, patch

        cli = import_module("core.packet_engine.main")
        output = Mock()
        detail = (
            "UI bundle is incomplete or stale. Restart the service that owns this port, "
            "or choose another UI port; it was not stopped."
        )
        with patch.object(cli.sys, "argv", ["tower", "open", "--no-open"]), \
             patch.object(cli, "console", output), \
             patch("core.ui_launcher.launch_ui", side_effect=RuntimeError(detail)):
            with self.assertRaises(SystemExit) as raised:
                cli.main()

        rendered = "\n".join(str(call.args[0]) for call in output.print.call_args_list)
        self.assertEqual(raised.exception.code, 1)
        self.assertIn(detail, rendered)
        self.assertIn("Follow the recovery steps above", rendered)
        self.assertNotIn("retry 'tower open'", rendered)

    def test_quick_status_is_concise_and_points_to_next_action(self):
        output = quick_status(
            {"running": False, "message": "Daemon not running"},
            configured=False,
        )

        self.assertIn("WatchTower is not configured", output)
        self.assertIn("tower setup", output)
        self.assertNotIn("WATCHTOWER", output)

    def test_controller_status_reports_api_health_instead_of_a_missing_native_daemon(self):
        from unittest.mock import patch

        with patch.dict(os.environ, {"WATCHTOWER_DEPLOYMENT_ROLE": "controller"}):
            result = self.run_cli("status")

        self.assertIn("controller_api", result.stdout)
        self.assertIn("not_applicable", result.stdout.lower())
        self.assertNotIn("WatchTower service is not running", result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_calibration_verify_defaults_to_concise_human_summary(self):
        result = {
            "valid": False,
            "errors": ["watchtower.sample/example.finding: stale calibration dependency: core/calibration/service.py"],
            "targets": [{
                "detector_id": "watchtower.sample",
                "finding_type": "example.finding",
                "level": "FIELD_CALIBRATED",
                "valid": False,
                "reason": "stale calibration dependency: core/calibration/service.py",
            }],
        }

        exit_code, output = self.run_main_with_calibration_result(
            ["plugins", "calibration", "verify"], result,
        )

        self.assertEqual(exit_code, 2)
        self.assertIn("Calibration verification: FAIL", output)
        self.assertIn("1 target checked; 1 invalid", output)
        self.assertIn("stale calibration dependency: core/calibration/service.py", output)
        self.assertIn("Next step:", output)
        self.assertNotIn('"targets"', output)

    def test_calibration_verify_json_format_preserves_structured_contract(self):
        result = {
            "valid": True,
            "errors": [],
            "targets": [{
                "detector_id": "watchtower.sample",
                "finding_type": "example.finding",
                "level": "UNCALIBRATED",
                "valid": True,
                "reason": "",
            }],
        }

        exit_code, output = self.run_main_with_calibration_result(
            ["plugins", "calibration", "verify", "--format", "json"], result,
        )

        self.assertEqual(exit_code, 0, output)
        payload = __import__("json").loads(output)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["targets"][0]["finding_type"], "example.finding")

    def test_interactive_shell_calibration_verify_uses_human_summary(self):
        from importlib import import_module
        from io import StringIO
        from unittest.mock import patch
        from rich.console import Console

        shell = import_module("core.cli.shell")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        result = {
            "valid": False,
            "errors": ["watchtower.sample/example.finding: stale calibration dependency: core/calibration/service.py"],
            "targets": [{
                "detector_id": "watchtower.sample",
                "finding_type": "example.finding",
                "level": "FIELD_CALIBRATED",
                "valid": False,
                "reason": "stale calibration dependency: core/calibration/service.py",
            }],
        }
        with tempfile.TemporaryDirectory(prefix="watchtower-shell-calibration-") as runtime:
            with patch.dict(os.environ, {"WATCHTOWER_HOME": runtime}), \
                 patch.object(shell, "console", console), \
                 patch("core.calibration.service.CalibrationService.verify", return_value=result):
                shell.WatchtowerShell.do_plugins(object(), "calibration verify")

        rendered = output.getvalue()
        self.assertIn("Calibration verification: FAIL", rendered)
        self.assertIn("Next step:", rendered)
        self.assertNotIn('"targets"', rendered)

    def test_plugins_test_separates_verified_trust_evidence_from_policy_level(self):
        from importlib import import_module
        from io import StringIO
        from types import SimpleNamespace
        from unittest.mock import patch
        from rich.console import Console

        from core.calibration.attestations import document_digest

        shell = import_module("core.cli.shell")
        presentation = import_module("core.operations.calibration_presentation")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None, width=140)
        detector = SimpleNamespace(
            name="Example Detector",
            enabled=True,
            manifest=SimpleNamespace(contract_version=2),
        )
        plugin_info = {
            "calibration_level": "FIELD_CALIBRATED",
            "calibration": [{
                "finding_type": "example.signal",
                "calibration_level": "FIELD_CALIBRATED",
                "attestation_digest": "",
                "stale_reason": "",
                "effective_cap": 10.0,
            }],
        }
        loader = SimpleNamespace(
            get_parsers=lambda: [],
            get_detectors=lambda: [detector],
            list_plugins=lambda: {
                "BaseDetector:Example Detector": plugin_info,
            },
        )
        payload = {
            "awarded_level": "FIELD_CALIBRATED",
            "bootstrap_exception": {"exception_id": "builtins-v2.0"},
            "field_evidence": {"relevant_host_days": 0},
        }
        digest = document_digest(payload)
        payload["digest"] = digest

        with tempfile.TemporaryDirectory(prefix="watchtower-cli-trust-") as runtime:
            Path(runtime, f"{digest}.json").write_text(__import__("json").dumps(payload), encoding="utf-8")
            plugin_info["calibration"][0]["attestation_digest"] = digest
            with patch.object(shell, "console", console), \
                 patch("core.forensics.plugin_loader.PluginLoader", return_value=loader), \
                 patch("core.forensics.sigma_engine.SigmaEngine", return_value=SimpleNamespace(rules=[])), \
                 patch.object(presentation, "ATTESTATION_DIR", Path(runtime)):
                shell.WatchtowerShell.do_plugins(object(), "test")

        rendered = output.getvalue()
        self.assertIn("Trust evidence", rendered)
        self.assertIn("Policy level", rendered)
        self.assertIn("BOOTSTRAP QUALIFIED", rendered)
        self.assertIn("Field Calibrated", rendered)

    def test_tower_plugins_test_uses_verified_trust_evidence(self):
        from importlib import import_module
        from io import StringIO
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        from rich.console import Console

        from core.calibration.attestations import document_digest

        cli = import_module("core.packet_engine.main")
        presentation = import_module("core.operations.calibration_presentation")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        plugin_info = {
            "type": "detector",
            "name": "Example Detector",
            "valid": True,
            "errors": 0,
            "contract_version": 2,
            "calibration_level": "FIELD_CALIBRATED",
            "calibration": [{
                "calibration_level": "FIELD_CALIBRATED",
                "attestation_digest": "",
                "stale_reason": "",
            }],
        }
        loader = SimpleNamespace(list_plugins=lambda: {"BaseDetector:Example Detector": plugin_info})
        payload = {
            "awarded_level": "FIELD_CALIBRATED",
            "bootstrap_exception": {"exception_id": "builtins-v2.0"},
            "field_evidence": {"relevant_host_days": 0},
        }
        digest = document_digest(payload)
        payload["digest"] = digest

        with tempfile.TemporaryDirectory(prefix="watchtower-tower-plugin-trust-") as runtime:
            Path(runtime, f"{digest}.json").write_text(__import__("json").dumps(payload), encoding="utf-8")
            plugin_info["calibration"][0]["attestation_digest"] = digest
            with patch.object(cli.sys, "argv", ["tower", "plugins", "test"]), \
                 patch.object(cli, "console", console), \
                 patch("core.forensics.plugin_loader.PluginLoader", return_value=loader), \
                 patch.object(presentation, "ATTESTATION_DIR", Path(runtime)):
                cli.main()

        rendered = output.getvalue()
        self.assertIn("BOOTSTRAP QUALIFIED", rendered)
        self.assertIn("FIELD_CALIBRATED", rendered)

    def test_legacy_commands_resolve_to_task_families(self):
        self.assertEqual(command_family("ui"), "open")
        self.assertEqual(command_family("mesh"), "sensors")
        self.assertEqual(command_family("dive"), "investigate")
        self.assertEqual(command_family("plugins"), "extensions")

    def test_background_capture_does_not_claim_success_after_failures(self):
        output = capture_completion_message(
            background=True,
            started=0,
            failures=["Wi-Fi adapter: permission denied"],
        )

        self.assertIn("did not start", output)
        self.assertIn("tower doctor", output)
        self.assertNotIn("now running", output)

    def test_capture_failure_is_nonzero_for_automation(self):
        self.assertFalse(capture_succeeded(started=0, failures=["adapter rejected start"]))
        self.assertFalse(capture_succeeded(started=1, failures=["second adapter failed"]))
        self.assertTrue(capture_succeeded(started=1, failures=[]))

    def test_cli_capture_stops_when_daemon_cannot_start(self):
        from importlib import import_module
        from io import StringIO
        from unittest.mock import patch
        from rich.console import Console

        capture = import_module("core.cli.modules.capture")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        with patch(
            "core.daemon.manager.DaemonManager.ensure_running", return_value=False
        ) as ensure_running, patch(
            "core.daemon.client.DaemonClient"
        ) as client_type, patch.object(
            capture, "console", console
        ):
            result = capture.CaptureModule({"interface": "Wi-Fi"}).run()

        self.assertFalse(result)
        ensure_running.assert_called_once_with(silent=False)
        client_type.assert_not_called()
        self.assertIn("daemon could not be started", output.getvalue().lower())
        self.assertIn("retry", output.getvalue().lower())

    def test_cli_background_setup_stops_when_daemon_cannot_start(self):
        from importlib import import_module
        from io import StringIO
        from unittest.mock import patch
        from rich.console import Console

        capture = import_module("core.cli.modules.capture")
        output = StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        with patch(
            "core.daemon.manager.DaemonManager.ensure_running", return_value=False
        ) as ensure_running, patch(
            "core.daemon.client.DaemonClient"
        ) as client_type, patch.object(
            capture.CaptureModule, "_select_interfaces", return_value=[]
        ) as select_interfaces, patch.object(capture, "console", console):
            capture.CaptureModule({}).background()

        ensure_running.assert_called_once_with(silent=False)
        client_type.assert_not_called()
        select_interfaces.assert_not_called()
        self.assertIn("daemon could not be started", output.getvalue().lower())

    def test_capture_source_json_preserves_availability_and_recovery_reason(self):
        payload = capture_source_inventory([
            CaptureDevice("network", "wifi-1", "Wi-Fi", addresses=["192.0.2.10"], backends=["python"], available=True),
            CaptureDevice(
                "network", "wifi-2", "Ethernet", available=False,
                unavailable_reason="Npcap runtime is missing",
            ),
            {"source_type": "network", "name": "sensor-wifi", "backends": ["rust"]},
        ])

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["available_count"], 2)
        self.assertEqual(payload["unavailable_count"], 1)
        self.assertEqual(payload["devices"][0]["device_id"], "wifi-1")
        self.assertEqual(payload["devices"][1]["unavailable_reason"], "Npcap runtime is missing")
        self.assertEqual(payload["devices"][2]["device_id"], "sensor-wifi")


if __name__ == "__main__":
    unittest.main()

import unittest

from core.ux.contracts import (
    CaptureState,
    DeploymentRole,
    ExperienceMode,
    OperationResult,
    ServiceState,
    build_operation_failure,
    describe_status,
)


class UxContractTests(unittest.TestCase):
    def test_stopped_sensor_has_a_concrete_live_capture_action(self):
        status = describe_status(
            service=ServiceState.STOPPED,
            capture=CaptureState.UNAVAILABLE,
            deployment=DeploymentRole.NATIVE,
        )

        self.assertEqual(status["service_label"], "Stopped")
        self.assertEqual(status["capture_label"], "Capture unavailable")
        self.assertIn("tower start", status["next_action"])

    def test_status_description_explains_a_degraded_capture_without_raw_errors(self):
        status = describe_status(
            service=ServiceState.RUNNING,
            capture=CaptureState.FAILED,
            deployment=DeploymentRole.NATIVE,
            issue="Npcap could not open the selected adapter",
        )

        self.assertEqual(status["service_label"], "Running")
        self.assertEqual(status["capture_label"], "Capture needs attention")
        self.assertEqual(status["next_action"], "Check the selected adapter and retry capture.")
        self.assertNotIn("Npcap", status["next_action"])

    def test_operation_failure_has_a_machine_code_and_recovery_action(self):
        result = build_operation_failure(
            operation_id="op-123",
            code="capture_source_unavailable",
            title="Capture could not start",
            detail="The selected adapter is unavailable.",
            recovery_action="Choose another adapter and retry.",
        )

        self.assertIsInstance(result, OperationResult)
        self.assertEqual(result.state, "failed")
        self.assertEqual(result.error["code"], "capture_source_unavailable")
        self.assertEqual(result.next_actions, ["Choose another adapter and retry."])

    def test_modes_and_roles_are_serializable_for_ui_and_cli(self):
        self.assertEqual(ExperienceMode.STANDARD.value, "standard")
        self.assertEqual(DeploymentRole.CONTROLLER.value, "controller")


if __name__ == "__main__":
    unittest.main()

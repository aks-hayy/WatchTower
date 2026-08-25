from argparse import Namespace
import json
from pathlib import Path
import sys

from scripts import run_calibration_ci as calibration_ci


def test_select_targets_can_limit_work_to_untrusted_findings():
    status = {
        "targets": [
            {
                "detector_id": "watchtower.good",
                "finding_type": "finding.good",
                "calibration_level": "FIELD_CALIBRATED",
                "stale_reason": "",
            },
            {
                "detector_id": "watchtower.stale",
                "finding_type": "finding.stale",
                "calibration_level": "FIELD_CALIBRATED",
                "stale_reason": "source changed",
            },
            {
                "detector_id": "watchtower.new",
                "finding_type": "finding.new",
                "calibration_level": "UNCALIBRATED",
                "stale_reason": "",
            },
        ]
    }

    targets = calibration_ci.select_targets(status, only_untrusted=True)

    assert [target.key for target in targets] == [
        "watchtower.new::finding.new",
        "watchtower.stale::finding.stale",
    ]


def test_bounded_runner_records_output_and_timeout(tmp_path):
    completed_log = tmp_path / "completed.log"
    completed = calibration_ci.run_bounded(
        [sys.executable, "-c", "print('complete')"],
        completed_log,
        10,
        dict(calibration_ci.os.environ),
    )
    timeout_log = tmp_path / "timeout.log"
    timed_out = calibration_ci.run_bounded(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_log,
        0.05,
        dict(calibration_ci.os.environ),
    )

    assert completed[0:2] == ("passed", 0)
    assert "complete" in completed_log.read_text(encoding="utf-8")
    assert timed_out[0] == "timeout"


def test_reuse_requires_both_result_and_report(tmp_path):
    result = tmp_path / "result.json"
    report = tmp_path / "report.json"
    entry = {"status": "passed", "result_path": str(result), "report_path": str(report)}

    assert calibration_ci._reusable(entry) is False
    result.write_text(json.dumps({"passed": True}), encoding="utf-8")
    assert calibration_ci._reusable(entry) is False
    report.write_text(json.dumps({"passed": True}), encoding="utf-8")
    assert calibration_ci._reusable(entry) is True

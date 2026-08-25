"""Run detector calibration targets in isolated, resumable subprocesses."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_DIR = PROJECT_ROOT / ".release-state" / "calibration"
STATE_SCHEMA_VERSION = 1


@dataclass(frozen=True, order=True)
class CalibrationTarget:
    detector_id: str
    finding_type: str

    @property
    def key(self) -> str:
        return f"{self.detector_id}::{self.finding_type}"

    @property
    def slug(self) -> str:
        return "__".join((self.detector_id, self.finding_type)).replace("/", "_").replace("\\", "_")


def select_targets(
    status: dict[str, Any],
    *,
    only_untrusted: bool,
    detector_ids: Iterable[str] = (),
    finding_types: Iterable[str] = (),
) -> list[CalibrationTarget]:
    detector_filter = set(detector_ids)
    finding_filter = set(finding_types)
    selected: list[CalibrationTarget] = []
    for item in status.get("targets") or []:
        detector_id = str(item.get("detector_id") or "")
        finding_type = str(item.get("finding_type") or "")
        if not detector_id or not finding_type:
            continue
        if detector_filter and detector_id not in detector_filter:
            continue
        if finding_filter and finding_type not in finding_filter:
            continue
        trusted = item.get("calibration_level") == "FIELD_CALIBRATED" and not item.get("stale_reason")
        if only_untrusted and trusted:
            continue
        selected.append(CalibrationTarget(detector_id, finding_type))
    return sorted(set(selected))


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema_version": STATE_SCHEMA_VERSION, "targets": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": STATE_SCHEMA_VERSION, "targets": {}}
    if value.get("schema_version") != STATE_SCHEMA_VERSION or not isinstance(value.get("targets"), dict):
        return {"schema_version": STATE_SCHEMA_VERSION, "targets": {}}
    return value


def _reusable(entry: dict[str, Any]) -> bool:
    result_path = Path(str(entry.get("result_path") or ""))
    report_path = Path(str(entry.get("report_path") or ""))
    return entry.get("status") == "passed" and result_path.is_file() and report_path.is_file()


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_bounded(command: list[str], log_path: Path, timeout_seconds: float, env: dict[str, str]) -> tuple[str, int, float]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
        try:
            exit_code = process.wait(timeout=timeout_seconds)
            status = "passed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired:
            _terminate_process_tree(process)
            exit_code = -1
            status = "timeout"
    return status, exit_code, round(time.monotonic() - started, 3)


def _worker(detector_id: str, finding_type: str, backend: str, data_dir: Path, result_path: Path) -> int:
    from core.calibration.service import CalibrationService

    result = CalibrationService(data_dir=data_dir).run(
        detector_id,
        finding_type=finding_type,
        backend=backend,
    )
    _atomic_json(result_path, result)
    return 0 if result.get("passed") else 2


def run_suite(args: argparse.Namespace) -> dict[str, Any]:
    from core.calibration.service import CalibrationService

    state_dir = Path(args.state_dir).resolve()
    state_path = state_dir / "state.json"
    state = _load_state(state_path) if args.resume else {"schema_version": STATE_SCHEMA_VERSION, "targets": {}}
    service = CalibrationService()
    targets = select_targets(
        service.status(),
        only_untrusted=args.only_untrusted,
        detector_ids=args.detector,
        finding_types=args.finding_type,
    )
    summary: dict[str, Any] = {
        "schema_version": STATE_SCHEMA_VERSION,
        "started_at": time.time(),
        "backend": args.backend,
        "selected": len(targets),
        "targets": state.get("targets") or {},
    }
    state_dir.mkdir(parents=True, exist_ok=True)

    for index, target in enumerate(targets, 1):
        previous = summary["targets"].get(target.key) or {}
        if args.resume and _reusable(previous):
            entry = dict(previous)
            entry["reused"] = True
        else:
            runtime_dir = state_dir / "runtime" / target.slug
            result_path = state_dir / "results" / f"{target.slug}.json"
            log_path = state_dir / "logs" / f"{target.slug}.log"
            env = os.environ.copy()
            env["WATCHTOWER_HOME"] = str(runtime_dir)
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                target.detector_id,
                target.finding_type,
                "--backend",
                args.backend,
                "--data-dir",
                str(runtime_dir / "data"),
                "--result-file",
                str(result_path),
            ]
            print(f"[{index}/{len(targets)}] calibrating {target.key}", flush=True)
            status, exit_code, elapsed = run_bounded(command, log_path, args.timeout, env)
            result: dict[str, Any] = {}
            if result_path.is_file():
                try:
                    result = json.loads(result_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    status = "failed"
            reports = result.get("reports") or []
            report_path = str(reports[0].get("report_path") or "") if reports else ""
            entry = {
                "detector_id": target.detector_id,
                "finding_type": target.finding_type,
                "status": status if result.get("passed") else "failed" if status == "passed" else status,
                "exit_code": exit_code,
                "elapsed_seconds": elapsed,
                "result_path": str(result_path),
                "report_path": report_path,
                "log_path": str(log_path),
                "reused": False,
            }

        if args.promote and entry.get("status") == "passed" and not entry.get("promoted"):
            try:
                promotion = service.promote(entry["report_path"], args.reviewer, args.reason)
                entry["promoted"] = True
                entry["attestation_digest"] = promotion["digest"]
            except Exception as exc:  # Promotion errors belong in the machine-readable release record.
                entry["promoted"] = False
                entry["promotion_error"] = f"{type(exc).__name__}: {exc}"
                entry["status"] = "failed"

        summary["targets"][target.key] = entry
        summary["updated_at"] = time.time()
        _atomic_json(state_path, summary)

    selected_entries = [summary["targets"].get(target.key) or {} for target in targets]
    summary["passed"] = all(
        entry.get("status") == "passed" and (not args.promote or entry.get("promoted") is True)
        for entry in selected_entries
    )
    summary["completed_at"] = time.time()
    _atomic_json(state_path, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("all", "python", "rust"), default="all")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--timeout", type=float, default=900.0, help="Hard timeout per finding type in seconds")
    parser.add_argument("--only-untrusted", action="store_true")
    parser.add_argument("--detector", action="append", default=[])
    parser.add_argument("--finding-type", action="append", default=[])
    parser.add_argument("--no-resume", dest="resume", action="store_false")
    parser.set_defaults(resume=True)
    parser.add_argument("--promote", action="store_true")
    parser.add_argument("--reviewer", default="")
    parser.add_argument("--reason", default="")
    parser.add_argument("--worker", nargs=2, metavar=("DETECTOR", "FINDING"), help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", help=argparse.SUPPRESS)
    parser.add_argument("--result-file", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.worker:
        if not args.data_dir or not args.result_file:
            raise SystemExit("worker requires --data-dir and --result-file")
        return _worker(args.worker[0], args.worker[1], args.backend, Path(args.data_dir), Path(args.result_file))
    if args.promote and (not args.reviewer.strip() or not args.reason.strip()):
        raise SystemExit("--promote requires --reviewer and --reason")
    summary = run_suite(args)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

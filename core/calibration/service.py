"""Automated detector calibration, field evidence, review, and scaffolding."""

from __future__ import annotations

from datetime import datetime, timezone
import inspect
import ipaddress
import json
from pathlib import Path
import platform
import re
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from core.calibration.attestations import (
    PROJECT_ROOT, current_runtime_versions, document_digest, relative_hashes, scoring_policy_digest,
    verify_profile_attestation, write_attestation,
)
from core.calibration.contracts import (
    CalibrationCase, CalibrationMetrics, FieldEvidenceEntry, REQUIRED_VARIANTS,
    contains_sensitive_material,
)
from core.calibration.corpus import (
    flow_for_recipe, load_corpus, packet_from_spec, packets_for_case,
    stream_for_case, write_case_pcap, flows_for_case,
)
from core.detection.contracts import detector_alert_to_finding
from core.forensics.plugin_loader import PluginLoader


RUNNER_VERSION = "1.0.0"
MIN_POSITIVE_CASES = 10
MIN_BENIGN_CASES = 30
MIN_PRECISION = 0.90
MIN_RECALL = 0.80
MIN_FIELD_HOST_DAYS = 30.0
MAX_FIELD_HIGH_FALSE_RATE = 0.10
MAX_SENSOR_DROP_RATIO = 0.001
BOOTSTRAP_MIN_POSITIVE_CASES = 100
BOOTSTRAP_MIN_BENIGN_CASES = 300
BOOTSTRAP_MIN_PRECISION = 0.95
BOOTSTRAP_MIN_RECALL = 0.90


class CalibrationError(RuntimeError):
    pass


def _safe_token(value: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", value or ""):
        raise CalibrationError(f"unsafe calibration identifier: {value!r}")
    return value


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(child) for child in value]
    if isinstance(value, bytes):
        return {"length": len(value), "sha256": __import__("hashlib").sha256(value).hexdigest()}
    return value


def _deep_size(value: Any, seen: Optional[set] = None) -> int:
    seen = seen or set()
    identity = id(value)
    if identity in seen:
        return 0
    seen.add(identity)
    size = sys.getsizeof(value)
    if isinstance(value, dict):
        size += sum(_deep_size(key, seen) + _deep_size(child, seen) for key, child in value.items())
    elif isinstance(value, (list, tuple, set, frozenset)):
        size += sum(_deep_size(child, seen) for child in value)
    elif hasattr(value, "__dict__"):
        size += _deep_size(vars(value), seen)
    return size


class CalibrationService:
    def __init__(
        self, project_root: Path = PROJECT_ROOT, data_dir: Optional[Path] = None,
        corpus_dir: Optional[Path] = None, profile_path: Optional[Path] = None,
        bootstrap_path: Optional[Path] = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.data_dir = Path(data_dir or self.project_root / "data").resolve()
        self.corpus_dir = Path(corpus_dir or self.project_root / "calibration" / "corpus").resolve()
        self.profile_path = Path(profile_path or self.project_root / "core" / "detection" / "scoring_profiles.yaml").resolve()
        self.bootstrap_path = Path(
            bootstrap_path or self.project_root / "calibration" / "bootstrap-v2.0.yaml"
        ).resolve()
        self.report_dir = self.data_dir / "calibration" / "reports"
        self.field_dir = self.data_dir / "calibration" / "field"

    def _detector(self, detector_id: str):
        _safe_token(detector_id)
        matches = [
            detector for detector in PluginLoader().get_detectors()
            if bool(getattr(detector, "enabled", True))
            and getattr(getattr(detector, "manifest", None), "detector_id", None) == detector_id
        ]
        if len(matches) != 1:
            raise CalibrationError(f"expected one enabled detector for {detector_id}, found {len(matches)}")
        return matches[0]

    def _corpus_path(self, detector_id: str) -> Path:
        return self.corpus_dir / f"{_safe_token(detector_id)}.yaml"

    def run(self, detector_id: str, finding_type: str = None, backend: str = "all") -> Dict[str, Any]:
        if detector_id == "watchtower.sigma":
            raise CalibrationError("Sigma requires rule-level calibration and is excluded from detector calibration")
        detector = self._detector(detector_id)
        manifest = detector.manifest
        requested = [finding_type] if finding_type else list(manifest.finding_types)
        unknown = set(requested) - set(manifest.finding_types)
        if unknown:
            raise CalibrationError("detector does not declare: " + ", ".join(sorted(unknown)))
        if backend not in {"all", "python", "rust"}:
            raise CalibrationError("backend must be all, python, or rust")
        corpus_path = self._corpus_path(detector_id)
        cases = load_corpus(corpus_path)
        reports = [self._evaluate(detector, target, cases, corpus_path, backend) for target in requested]
        return {"detector_id": detector_id, "reports": reports, "passed": all(item["passed"] for item in reports)}

    def _evaluate(self, detector, finding_type: str, cases: List[CalibrationCase], corpus_path: Path,
                  backend: str) -> Dict[str, Any]:
        selected = [case for case in cases if case.finding_type == finding_type]
        if not selected:
            raise CalibrationError(f"no calibration cases for {finding_type}")
        metrics = CalibrationMetrics()
        evidence_values: List[float] = []
        failures: List[str] = []
        case_results: List[Dict[str, Any]] = []
        started = time.perf_counter()
        tracemalloc.start()
        runner_peak_memory = 0
        replay_directory = None
        replay_engine = None
        try:
            if any("integrated" in case.modes for case in selected):
                from core.forensics.engine import ForensicsEngine

                replay_directory = tempfile.TemporaryDirectory(
                    prefix="watchtower-calibration-batch-",
                )
                replay_root = Path(replay_directory.name)
                replay_engine = ForensicsEngine(
                    data_dir=str(replay_root / "data"),
                    silent=True,
                )
                self._active_replay = {
                    "root": replay_root,
                    "engine": replay_engine,
                    "pcaps": {},
                }
            for case in selected:
                result = self._evaluate_case(detector, case, backend)
                case_results.append(result)
                found = bool(result["primary_findings"])
                if case.label == "positive":
                    metrics.positive_cases += 1
                    if found:
                        metrics.true_positive += 1
                    else:
                        metrics.false_negative += 1
                else:
                    metrics.benign_cases += 1
                    if found:
                        metrics.false_positive += 1
                    else:
                        metrics.true_negative += 1
                    benign_impacts = {str(item.get("impact") or "").upper() for item in result["primary_findings"]}
                    if "HIGH" in benign_impacts or "CRITICAL" in benign_impacts:
                        metrics.high_benign += 1
                    if "CRITICAL" in benign_impacts:
                        metrics.critical_benign += 1
                evidence_values.extend(float(item.get("evidence_quality") or 0.0) for item in result["primary_findings"])
                metrics.deterministic = metrics.deterministic and result["deterministic"]
                metrics.backend_parity = metrics.backend_parity and result["backend_parity"]
                metrics.secrets_redacted = metrics.secrets_redacted and result["secrets_redacted"]
                metrics.variants.append(case.variant)
                failures.extend(result["failures"])
                metrics.peak_memory_bytes = max(metrics.peak_memory_bytes, int(result["state_bytes"]))
        finally:
            self._active_replay = None
            if replay_engine is not None:
                replay_engine.db.close()
            if replay_directory is not None:
                replay_directory.cleanup()
            _current, traced_peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            runner_peak_memory = int(traced_peak)
        metrics.execution_seconds = round(time.perf_counter() - started, 4)
        metrics.variants = sorted(set(metrics.variants))
        metrics.finalize(evidence_values)
        metrics.state_within_limit = metrics.peak_memory_bytes <= int(detector.manifest.memory_limit_bytes)

        if metrics.positive_cases < MIN_POSITIVE_CASES:
            failures.append(f"requires at least {MIN_POSITIVE_CASES} positive cases")
        if metrics.benign_cases < MIN_BENIGN_CASES:
            failures.append(f"requires at least {MIN_BENIGN_CASES} benign cases")
        if backend != "all" and any("rust" in case.backends and not case.unsupported.get("rust") for case in selected):
            failures.append("full calibration requires --backend all for declared Rust parity")
        missing_variants = REQUIRED_VARIANTS - set(metrics.variants)
        if missing_variants:
            failures.append("missing required variants: " + ", ".join(sorted(missing_variants)))
        if metrics.precision < MIN_PRECISION:
            failures.append(f"precision {metrics.precision:.3f} is below {MIN_PRECISION:.2f}")
        if metrics.recall < MIN_RECALL:
            failures.append(f"recall {metrics.recall:.3f} is below {MIN_RECALL:.2f}")
        if metrics.critical_benign:
            failures.append("benign corpus produced CRITICAL findings")
        if not metrics.deterministic:
            failures.append("finding output is not deterministic")
        if not metrics.backend_parity:
            failures.append("integrated backend findings differ")
        if not metrics.secrets_redacted:
            failures.append("sensitive test material reached findings")
        if not metrics.state_within_limit:
            failures.append("detector state exceeded the manifest memory limit")
        production_cases = [
            result for result in case_results
            if result.get("production_path_evaluated")
        ]
        if not any(result["label"] == "positive" for result in production_cases):
            failures.append("requires at least one positive integrated production-path case")
        if not any(result["label"] == "benign" for result in production_cases):
            failures.append("requires at least one benign integrated production-path case")

        corpus_passed = not failures
        field = self._aggregate_field(detector.manifest.detector_id, detector.manifest.version, finding_type)
        field_passed, field_failures = self._field_gate(field)
        bootstrap_passed, bootstrap_failures, bootstrap_id = self._bootstrap_gate(
            detector.manifest.detector_id,
            detector.manifest.version,
            finding_type,
            metrics.to_dict(),
            corpus_passed,
        )
        full_trust = corpus_passed and (field_passed or bootstrap_passed)
        awarded_level = "FIELD_CALIBRATED" if full_trust else "CORPUS_VALIDATED" if corpus_passed else "UNCALIBRATED"
        source_files = self._source_files(detector)
        policy_digest = self._policy_digest(detector.manifest.detector_id, finding_type)
        report = {
            "schema_version": 1,
            "runner_version": RUNNER_VERSION,
            "target": {
                "detector_id": detector.manifest.detector_id,
                "detector_version": detector.manifest.version,
                "finding_type": finding_type,
                "policy_digest": policy_digest,
            },
            "created_at": time.time(),
            "backend_selection": backend,
            "metrics": metrics.to_dict(),
            "runner_peak_memory_bytes": runner_peak_memory,
            "field_evidence": field,
            "field_failures": field_failures,
            "bootstrap_exception": ({"exception_id": bootstrap_id} if bootstrap_passed else None),
            "bootstrap_failures": bootstrap_failures,
            "passed": corpus_passed,
            "awarded_level": awarded_level,
            "failures": sorted(set(failures)),
            "cases": case_results,
            "source_files": relative_hashes(source_files),
            "corpus_files": relative_hashes([corpus_path]),
            "environment": {
                "python": platform.python_version(), "platform": platform.platform(),
                "rust_sensor_available": self._rust_available(),
            },
            "runtime_versions": current_runtime_versions(),
        }
        report["digest"] = document_digest(report)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        output = self.report_dir / f"{detector.manifest.detector_id}__{finding_type}__{report['digest'][:12]}.json"
        temporary = output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(output)
        report["report_path"] = str(output)
        return report

    def _evaluate_case(self, detector, case: CalibrationCase, backend: str) -> Dict[str, Any]:
        failures = []
        first = self._run_isolation(detector, case)
        state_bytes = _deep_size(detector)
        second = self._run_isolation(detector, case)
        normalized_first = self._normalize(first)
        deterministic = normalized_first == self._normalize(second)
        integrated: Dict[str, List[Dict[str, Any]]] = {}

        selected_backends = ("python", "rust") if backend == "all" else (backend,)
        if "integrated" in case.modes:
            if not packets_for_case(case):
                if not case.unsupported.get("integrated"):
                    failures.append(f"{case.case_id}: integrated mode has no packet recipe or declared reason")
            else:
                for selected_backend in selected_backends:
                    if selected_backend not in case.backends:
                        if not case.unsupported.get(selected_backend):
                            failures.append(f"{case.case_id}: {selected_backend} backend skipped without a reason")
                        continue
                    if selected_backend == "rust" and not self._rust_available():
                        failures.append(f"{case.case_id}: Rust backend is required but unavailable")
                        continue
                    modes = ("memory", "streaming") if selected_backend == "python" else ("memory", "streaming")
                    for mode in modes:
                        key = f"{selected_backend}-{mode}"
                        integrated[key] = self._run_integrated(case, selected_backend, mode)

        if integrated:
            baseline_key = "python-memory" if "python-memory" in integrated else sorted(integrated)[0]
            baseline = self._normalize(integrated[baseline_key])
            parity = all(self._normalize(value) == baseline for value in integrated.values())
            if "isolation" in case.modes and self._finding_signature(first) != self._finding_signature(integrated[baseline_key]):
                failures.append(f"{case.case_id}: isolation and integrated findings differ")
            primary_findings = integrated[baseline_key]
        else:
            parity = bool(case.unsupported.get("integrated")) or "integrated" not in case.modes
            primary_findings = first

        secret_values = [str(item) for item in (case.recipe.get("secret_values") or []) if str(item)]
        serialized = json.dumps(_json_ready([*first, *[item for values in integrated.values() for item in values]]), sort_keys=True)
        secrets_redacted = not any(secret in serialized for secret in secret_values)
        return {
            "case_id": case.case_id,
            "label": case.label,
            "variant": case.variant,
            "primary_findings": primary_findings,
            "integrated": integrated,
            "production_path_evaluated": bool(integrated),
            "deterministic": deterministic,
            "backend_parity": parity,
            "secrets_redacted": secrets_redacted,
            "state_bytes": state_bytes,
            "failures": failures,
        }

    def _run_isolation(self, detector, case: CalibrationCase) -> List[Dict[str, Any]]:
        restore = self._apply_detector_config(detector, case.recipe.get("detector_config") or {})
        try:
            detector.reset(f"calibration:{case.case_id}")
            alerts = []
            subject = str(case.recipe.get("src") or "10.250.0.10")
            if case.input_kind == "packet":
                packets = packets_for_case(case) or [packet_from_spec(case.recipe)]
                manifest = getattr(detector, "manifest", None)
                if manifest is not None and "conversation" in manifest.input_kinds:
                    # Stateful detectors are calibrated through the same V2
                    # conversation contract they consume in live/offline paths.
                    from core.packet_engine.conversations import ConversationTracker
                    from core.packet_engine.schemas import PacketEvent
                    tracker = ConversationTracker()
                    for packet in packets:
                        subject = self._packet_subject(packet)
                        import scapy.all as scapy
                        if scapy.IP in packet:
                            src_ip, dst_ip = str(packet[scapy.IP].src), str(packet[scapy.IP].dst)
                        elif scapy.IPv6 in packet:
                            src_ip, dst_ip = str(packet[scapy.IPv6].src), str(packet[scapy.IPv6].dst)
                        else:
                            continue
                        transport = packet[scapy.TCP] if scapy.TCP in packet else packet[scapy.UDP] if scapy.UDP in packet else None
                        protocol = "TCP" if scapy.TCP in packet else "UDP" if scapy.UDP in packet else "OTHER"
                        src_port = int(getattr(transport, "sport", 0) or 0)
                        dst_port = int(getattr(transport, "dport", 0) or 0)
                        flags = str(getattr(packet[scapy.TCP], "flags", "")) if scapy.TCP in packet else ""
                        event = PacketEvent(
                            timestamp=float(getattr(packet, "time", 0.0)),
                            src_ip=src_ip, dst_ip=dst_ip,
                            src_port=src_port, dst_port=dst_port,
                            protocol=protocol, size=len(packet), flags=flags,
                            interface="calibration", session_id=f"calibration:{case.case_id}",
                            source=f"calibration:{case.case_id}", backend="python",
                        )
                        _metadata, delta = tracker.update_with_delta(event)
                        alerts.extend(detector.detect(conversation=delta) or [])
                else:
                    for packet in packets:
                        subject = self._packet_subject(packet)
                        alerts.extend(detector.detect(packet=packet, **self._packet_kwargs(packet)) or [])
            elif case.input_kind == "stream":
                flow_id = (
                    subject, str(case.recipe.get("dst") or "10.250.0.20"),
                    int(case.recipe.get("sport") or 50000), int(case.recipe.get("dport") or 80), "TCP",
                )
                alerts.extend(detector.detect(
                    stream=stream_for_case(case), flow_id=flow_id,
                    direction=str(case.recipe.get("direction") or "to_server"),
                    timestamp=float(case.recipe.get("timestamp") or 1.0),
                    claimed_protocol=bool(case.recipe.get("claimed_protocol") or False),
                    truncated=bool(case.recipe.get("truncated") or False),
                ) or [])
            elif case.input_kind == "flow":
                flow = flow_for_recipe(case.recipe)
                subject = str(flow.flow_id[0])
                alerts.extend(detector.detect(flow=flow, arrival_times=list(flow.arrival_times)) or [])
                self._add_flow_evidence(alerts, flow)
            else:
                for flow in flows_for_case(case):
                    subject = str(flow.flow_id[0])
                    alerts.extend(detector.detect(flow=flow, arrival_times=list(flow.arrival_times)) or [])
                    self._add_flow_evidence(alerts, flow)
            alerts.extend(detector.finalize({"case_id": case.case_id}) or [])
            findings = [detector_alert_to_finding(detector, alert, subject) for alert in alerts]
            return [finding.to_dict() for finding in findings if finding.finding_type == case.finding_type]
        finally:
            for name, value in restore.items():
                setattr(detector, name, value)

    def _run_integrated(self, case: CalibrationCase, backend: str, mode: str) -> List[Dict[str, Any]]:
        from core.forensics.engine import ForensicsEngine

        def analyze(engine, pcap, source_name=None):
            matches = [
                detector for detector in engine.plugin_loader.get_detectors()
                if bool(getattr(detector, "enabled", True))
                and getattr(getattr(detector, "manifest", None), "detector_id", None)
                == case.detector_id
            ]
            if len(matches) != 1:
                raise CalibrationError(
                    f"expected one enabled integrated detector for {case.detector_id}, "
                    f"found {len(matches)}"
                )
            detector = matches[0]
            restore = self._apply_detector_config(
                detector, case.recipe.get("detector_config") or {},
            )
            try:
                engine.analyze_pcap(
                    str(pcap), mode=mode, backend=backend,
                    **({"source_name": source_name} if source_name else {}),
                )
            finally:
                for name, value in restore.items():
                    setattr(detector, name, value)

        active = getattr(self, "_active_replay", None)
        if active:
            root = active["root"]
            engine = active["engine"]
            pcap = active["pcaps"].get(case.case_id)
            if pcap is None:
                pcap = write_case_pcap(case, root / f"{case.case_id}.pcap")
                active["pcaps"][case.case_id] = pcap
            source = f"calibration:{case.case_id}"
            analyze(engine, pcap, source)
            findings = engine.db.get_detection_findings(
                source=source,
                finding_type=case.finding_type,
                limit=10000,
            )
            return [item for item in findings if item.get("detector_id") == case.detector_id]

        with tempfile.TemporaryDirectory(prefix="watchtower-calibration-") as directory:
            root = Path(directory)
            pcap = write_case_pcap(case, root / f"{case.case_id}.pcap")
            engine = ForensicsEngine(data_dir=str(root / "data"), silent=True)
            try:
                analyze(engine, pcap)
                findings = engine.db.get_detection_findings(finding_type=case.finding_type, limit=10000)
                return [item for item in findings if item.get("detector_id") == case.detector_id]
            finally:
                engine.db.close()

    @staticmethod
    def _add_flow_evidence(alerts, flow) -> None:
        src, dst, sport, dport, protocol = flow.flow_id
        for alert in alerts:
            alert.evidence = dict(alert.evidence or {})
            for key, value in {
                "src_ip": src, "dst_ip": dst, "src_port": sport,
                "dst_port": dport, "protocol": protocol,
            }.items():
                alert.evidence.setdefault(key, value)

    @staticmethod
    def _packet_subject(packet) -> str:
        import scapy.all as scapy

        if scapy.IP in packet:
            return str(packet[scapy.IP].src)
        if scapy.IPv6 in packet:
            return str(packet[scapy.IPv6].src)
        if scapy.ARP in packet:
            return str(packet[scapy.ARP].psrc)
        return "calibration-subject"

    @staticmethod
    def _packet_kwargs(packet) -> Dict[str, Any]:
        import scapy.all as scapy

        kwargs: Dict[str, Any] = {}
        if scapy.DNS in packet and scapy.DNSQR in packet:
            qname = packet[scapy.DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace")
            kwargs["domain"] = str(qname).rstrip(".")
            kwargs["metadata"] = {
                "dns_domain": kwargs["domain"],
                "dns_qtype": int(packet[scapy.DNSQR].qtype),
                "dns_nxdomain": int(packet[scapy.DNS].rcode or 0) == 3,
                "dns_is_response": bool(int(packet[scapy.DNS].qr or 0)),
                "dns_query_name_bytes": len(str(qname).rstrip(".")),
            }
        return kwargs

    @staticmethod
    def _apply_detector_config(detector, config: Dict[str, Any]) -> Dict[str, Any]:
        restore = {}
        if not isinstance(config, dict):
            return restore
        for name, value in config.items():
            if name.startswith("_") or not hasattr(detector, name):
                continue
            restore[name] = getattr(detector, name)
            current = getattr(detector, name)
            if isinstance(current, set):
                setattr(detector, name, set(value or ()))
            elif isinstance(current, dict):
                setattr(detector, name, dict(value or {}))
            else:
                setattr(detector, name, value)
        return restore

    @staticmethod
    def _normalize(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        fields = ("finding_type", "detector_id", "subject", "target", "impact", "evidence", "fingerprint")
        return sorted(
            [{field: _json_ready(item.get(field)) for field in fields} for item in findings],
            key=lambda item: json.dumps(item, sort_keys=True, default=str),
        )

    @staticmethod
    def _finding_signature(findings: Iterable[Dict[str, Any]]) -> List[Tuple[str, str]]:
        return sorted((str(item.get("finding_type")), str(item.get("subject"))) for item in findings)

    @staticmethod
    def _rust_available() -> bool:
        try:
            from core.packet_engine.rust_capture import rust_sensor_available
            return bool(rust_sensor_available())
        except Exception:
            return False

    def _source_files(self, detector) -> List[Path]:
        files = [
            Path(inspect.getfile(detector.__class__)),
            self.project_root / "core" / "forensics" / "base.py",
            self.project_root / "core" / "forensics" / "engine.py",
            self.project_root / "core" / "forensics" / "fast_packet.py",
            self.project_root / "core" / "forensics" / "plugin_loader.py",
            self.project_root / "core" / "forensics" / "rust_plan.py",
            self.project_root / "core" / "packet_engine" / "rust_analysis.py",
            self.project_root / "core" / "packet_engine" / "rust_capture.py",
            self.project_root / "core" / "packet_engine" / "schemas.py",
            self.project_root / "core" / "packet_engine" / "processors.py",
            self.project_root / "core" / "packet_engine" / "flow_worker.py",
            self.project_root / "core" / "packet_engine" / "conversations.py",
            self.project_root / "rust" / "watchtower-sensor" / "Cargo.lock",
            self.project_root / "pyproject.toml",
        ]
        files.extend(
            (self.project_root / "core" / "forensics" / "plugins" / "parsers").glob("*.py")
        )
        files.extend((self.project_root / "rust" / "watchtower-sensor" / "src").glob("*.rs"))
        files.extend((self.project_root / "core" / "detection").glob("*.py"))
        files.extend((self.project_root / "core" / "calibration").glob("*.py"))
        return [path for path in files if path.is_file()]

    def _policy_digest(self, detector_id: str, finding_type: str) -> str:
        from core.detection.scoring import ScoringConfig

        profile = ScoringConfig().profile_for(detector_id, finding_type)
        return scoring_policy_digest(profile.max_contribution, profile.base_impact, profile.half_life_seconds)

    def _aggregate_field(self, detector_id: str, version: str, finding_type: str) -> Dict[str, Any]:
        totals = {
            "relevant_host_days": 0.0, "complete_sessions": 0, "max_sensor_drop_ratio": 0.0,
            "high_findings": 0, "critical_findings": 0, "high_false_alerts": 0,
            "critical_false_alerts": 0, "unresolved_high_critical": 0,
        }
        if not self.field_dir.exists():
            return totals
        for path in sorted(self.field_dir.glob("*.json")):
            try:
                bundle = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for value in bundle.get("entries") or []:
                entry = FieldEvidenceEntry.from_dict(value)
                if (entry.detector_id, entry.detector_version, entry.finding_type) != (detector_id, version, finding_type):
                    continue
                for key in totals:
                    if key == "max_sensor_drop_ratio":
                        totals[key] = max(totals[key], getattr(entry, key))
                    else:
                        totals[key] += getattr(entry, key)
        return totals

    @staticmethod
    def _field_gate(field: Dict[str, Any]) -> Tuple[bool, List[str]]:
        failures = []
        host_days = float(field.get("relevant_host_days") or 0.0)
        if host_days < MIN_FIELD_HOST_DAYS:
            failures.append(f"requires {MIN_FIELD_HOST_DAYS:.0f} relevant benign host-days")
        if float(field.get("max_sensor_drop_ratio") or 0.0) > MAX_SENSOR_DROP_RATIO:
            failures.append("field capture sensor-drop ratio exceeded 0.1%")
        if int(field.get("critical_false_alerts") or 0):
            failures.append("field evidence contains CRITICAL false alerts")
        high_rate = float(field.get("high_false_alerts") or 0) / max(1.0, host_days)
        if high_rate > MAX_FIELD_HIGH_FALSE_RATE:
            failures.append("field HIGH false-alert rate exceeded 0.1 per host-day")
        if int(field.get("unresolved_high_critical") or 0):
            failures.append("field evidence contains unresolved HIGH/CRITICAL findings")
        return not failures, failures

    def _bootstrap_gate(
        self,
        detector_id: str,
        detector_version: str,
        finding_type: str,
        metrics: Dict[str, Any],
        corpus_passed: bool,
    ) -> Tuple[bool, List[str], str]:
        """Validate the one-time built-in exception to field host-day collection.

        This never relaxes corpus, parity, determinism, redaction, or bounded-state
        gates. It only replaces the 30-day field observation requirement for the
        exact built-in targets listed in the reviewed bootstrap policy.
        """
        if not self.bootstrap_path.is_file():
            return False, ["target is not authorized for the built-in bootstrap exception"], ""
        try:
            policy = yaml.safe_load(self.bootstrap_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return False, ["built-in bootstrap policy is invalid"], ""
        if policy.get("schema_version") != 1:
            return False, ["built-in bootstrap policy schema is unsupported"], ""
        expected = (detector_id, detector_version, finding_type)
        authorized = {
            (
                str(item.get("detector_id") or ""),
                str(item.get("detector_version") or ""),
                str(item.get("finding_type") or ""),
            )
            for item in (policy.get("targets") or [])
            if isinstance(item, dict)
        }
        if expected not in authorized:
            return False, ["target is not authorized for the built-in bootstrap exception"], ""

        failures = []
        if not corpus_passed:
            failures.append("the normal corpus gate must pass before bootstrap")
        if int(metrics.get("positive_cases") or 0) < BOOTSTRAP_MIN_POSITIVE_CASES:
            failures.append(f"bootstrap requires at least {BOOTSTRAP_MIN_POSITIVE_CASES} positive cases")
        if int(metrics.get("benign_cases") or 0) < BOOTSTRAP_MIN_BENIGN_CASES:
            failures.append(f"bootstrap requires at least {BOOTSTRAP_MIN_BENIGN_CASES} benign cases")
        if float(metrics.get("precision") or 0.0) < BOOTSTRAP_MIN_PRECISION:
            failures.append(f"bootstrap precision must be at least {BOOTSTRAP_MIN_PRECISION:.2f}")
        if float(metrics.get("recall") or 0.0) < BOOTSTRAP_MIN_RECALL:
            failures.append(f"bootstrap recall must be at least {BOOTSTRAP_MIN_RECALL:.2f}")
        if int(metrics.get("high_benign") or 0):
            failures.append("bootstrap corpus produced HIGH benign findings")
        if int(metrics.get("critical_benign") or 0):
            failures.append("bootstrap corpus produced CRITICAL benign findings")
        for field, message in (
            ("deterministic", "bootstrap findings are not deterministic"),
            ("backend_parity", "bootstrap backend parity failed"),
            ("secrets_redacted", "bootstrap secret redaction failed"),
            ("state_within_limit", "bootstrap state exceeded the manifest limit"),
        ):
            if metrics.get(field) is not True:
                failures.append(message)
        return not failures, failures, str(policy.get("exception_id") or "")

    def status(self, detector_id: str = None) -> Dict[str, Any]:
        loader = PluginLoader()
        result = []
        for detector in loader.get_detectors():
            if not bool(getattr(detector, "enabled", True)):
                continue
            manifest = getattr(detector, "manifest", None)
            if manifest is None or (detector_id and manifest.detector_id != detector_id):
                continue
            if manifest.detector_id == "watchtower.sigma":
                continue
            from core.detection.scoring import ScoringConfig
            config = ScoringConfig()
            for finding_type in manifest.finding_types:
                profile = config.profile_for(manifest.detector_id, finding_type, manifest.version)
                result.append({
                    "detector_id": manifest.detector_id, "detector_version": manifest.version,
                    "finding_type": finding_type, "calibration_level": profile.calibration_level,
                    "effective_cap": self._effective_cap(profile),
                    "attestation_digest": profile.attestation_digest,
                    "stale_reason": profile.stale_reason,
                    "report_count": len(list(self.report_dir.glob(f"{manifest.detector_id}__{finding_type}__*.json"))) if self.report_dir.exists() else 0,
                })
        if detector_id and not result:
            raise CalibrationError(f"no calibration targets found for {detector_id}")
        return {"model_version": "behavioral-v2.1", "targets": result}

    @staticmethod
    def _effective_cap(profile) -> float:
        if profile.calibration_level == "FIELD_CALIBRATED":
            return profile.max_contribution
        if profile.calibration_level == "CORPUS_VALIDATED":
            return min(profile.max_contribution, 20.0)
        return 5.0

    def promote(self, report_file: str, reviewer: str, reason: str) -> Dict[str, Any]:
        reviewer, reason = reviewer.strip(), reason.strip()
        if not reviewer or not reason:
            raise CalibrationError("reviewer and reason are required")
        path = Path(report_file).resolve()
        if not path.is_file():
            raise CalibrationError(f"calibration report does not exist: {path}")
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("digest") != document_digest(report):
            raise CalibrationError("calibration report digest mismatch")
        if not report.get("passed") or report.get("awarded_level") not in {"CORPUS_VALIDATED", "FIELD_CALIBRATED"}:
            raise CalibrationError("calibration report did not pass promotion gates")
        target = report.get("target") or {}
        detector = self._detector(str(target.get("detector_id") or ""))
        if detector.manifest.version != target.get("detector_version") or target.get("finding_type") not in detector.manifest.finding_types:
            raise CalibrationError("calibration report target is stale")
        current_sources = relative_hashes(self._source_files(detector))
        if current_sources != report.get("source_files"):
            raise CalibrationError("detector or calibration source changed after the report was generated")
        current_corpus = relative_hashes([self._corpus_path(detector.manifest.detector_id)])
        if current_corpus != report.get("corpus_files"):
            raise CalibrationError("calibration corpus changed after the report was generated")
        if report["awarded_level"] == "FIELD_CALIBRATED":
            field_passed, _ = self._field_gate(report.get("field_evidence") or {})
            bootstrap_passed, _, bootstrap_id = self._bootstrap_gate(
                str(target.get("detector_id") or ""),
                str(target.get("detector_version") or ""),
                str(target.get("finding_type") or ""),
                report.get("metrics") or {},
                bool(report.get("passed")),
            )
            declared_bootstrap = str((report.get("bootstrap_exception") or {}).get("exception_id") or "")
            bootstrap_passed = bootstrap_passed and bool(bootstrap_id) and declared_bootstrap == bootstrap_id
            if not field_passed and not bootstrap_passed:
                raise CalibrationError(
                    "FIELD_CALIBRATED promotion requires valid field evidence or an authorized built-in bootstrap"
                )

        attestation = {
            "schema_version": 1, "runner_version": RUNNER_VERSION,
            "target": target, "awarded_level": report["awarded_level"],
            "metrics": report["metrics"], "field_evidence": report["field_evidence"],
            "bootstrap_exception": report.get("bootstrap_exception"),
            "source_files": report["source_files"], "corpus_files": report["corpus_files"],
            "report_digest": report["digest"], "environment": report["environment"],
            "runtime_versions": report["runtime_versions"],
            "review": {"reviewer": reviewer, "reason": reason, "reviewed_at": time.time()},
        }
        attestation_path = write_attestation(attestation)
        attestation_value = json.loads(attestation_path.read_text(encoding="utf-8"))
        self._write_profile(target, report["awarded_level"], attestation_value["digest"])
        valid, stale_reason = verify_profile_attestation(
            attestation_value["digest"], target["detector_id"], target["detector_version"],
            target["finding_type"], report["awarded_level"], target["policy_digest"],
        )
        if not valid:
            raise CalibrationError(f"promoted attestation failed verification: {stale_reason}")
        return {
            "promoted": True, "calibration_level": report["awarded_level"],
            "attestation": str(attestation_path), "digest": attestation_value["digest"],
            "target": target,
        }

    def _write_profile(self, target: Dict[str, str], level: str, digest: str) -> None:
        data = yaml.safe_load(self.profile_path.read_text(encoding="utf-8")) or {}
        detectors = data.setdefault("detectors", {})
        detector = detectors.setdefault(target["detector_id"], {})
        detector["version"] = target["detector_version"]
        finding = detector.setdefault("findings", {}).setdefault(target["finding_type"], {})
        finding["calibration_level"] = level
        finding["attestation_digest"] = digest
        temporary = self.profile_path.with_suffix(".yaml.tmp")
        temporary.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        temporary.replace(self.profile_path)

    def invalidate_stale_profiles(self) -> Dict[str, Any]:
        """Atomically demote invalid trust claims; this operation cannot promote."""
        verification = self.verify()
        invalid = [item for item in verification["targets"] if not item["valid"]]
        if not invalid:
            return {"demoted": 0, "targets": []}
        data = yaml.safe_load(self.profile_path.read_text(encoding="utf-8")) or {}
        demoted = []
        for item in invalid:
            detector = (data.get("detectors") or {}).get(item["detector_id"]) or {}
            finding = (detector.get("findings") or {}).get(item["finding_type"])
            if not isinstance(finding, dict):
                continue
            previous = str(finding.get("calibration_level") or "UNCALIBRATED").upper()
            if previous == "UNCALIBRATED":
                continue
            finding["calibration_level"] = "UNCALIBRATED"
            finding.pop("attestation_digest", None)
            demoted.append({
                "detector_id": item["detector_id"],
                "finding_type": item["finding_type"],
                "previous_level": previous,
                "reason": item["reason"],
            })
        temporary = self.profile_path.with_suffix(".yaml.tmp")
        temporary.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        temporary.replace(self.profile_path)
        return {"demoted": len(demoted), "targets": demoted}

    def verify(self) -> Dict[str, Any]:
        data = yaml.safe_load(self.profile_path.read_text(encoding="utf-8")) or {}
        results, errors = [], []
        for detector_id, detector in (data.get("detectors") or {}).items():
            version = str(detector.get("version") or "")
            for finding_type, profile in (detector.get("findings") or {}).items():
                level = str(profile.get("calibration_level") or "UNCALIBRATED").upper()
                digest = str(profile.get("attestation_digest") or "")
                if level == "UNCALIBRATED":
                    valid, reason = True, ""
                else:
                    from core.detection.scoring import BASE_IMPACT, HALF_LIVES

                    default_cap = float(detector.get("max_contribution", 80.0))
                    base = {**BASE_IMPACT, **{str(key).upper(): float(value) for key, value in (profile.get("base_impact") or detector.get("base_impact") or {}).items()}}
                    half_life = {**HALF_LIVES, **{str(key).upper(): float(value) for key, value in (profile.get("half_life_seconds") or detector.get("half_life_seconds") or {}).items()}}
                    policy = scoring_policy_digest(float(profile.get("max_contribution", default_cap)), base, half_life)
                    valid, reason = verify_profile_attestation(digest, detector_id, version, finding_type, level, policy)
                item = {"detector_id": detector_id, "finding_type": finding_type, "level": level, "valid": valid, "reason": reason}
                results.append(item)
                if not valid:
                    errors.append(f"{detector_id}/{finding_type}: {reason}")
        return {"valid": not errors, "errors": errors, "targets": results}

    def field_export(self, since: str, output: str, db=None) -> Dict[str, Any]:
        from core.storage.database import WatchtowerDB
        from core.storage.models import CaptureSession, DetectionFinding, Flow

        since_timestamp = self._parse_since(since)
        owns_db = db is None
        db = db or WatchtowerDB(data_dir=str(self.data_dir))
        try:
            session = db._get_session()
            complete = session.query(CaptureSession).filter(
                CaptureSession.started_at >= since_timestamp,
                CaptureSession.processing_state == "complete",
                CaptureSession.complete.is_(True),
            ).all()
            accepted_ids, max_drop = [], 0.0
            for item in complete:
                denominator = max(1, int(item.received_packets or 0))
                ratio = float(item.dropped_packets or 0) / denominator
                max_drop = max(max_drop, ratio)
                if ratio <= MAX_SENSOR_DROP_RATIO:
                    accepted_ids.append(item.id)
            host_days = set()
            if accepted_ids:
                for flow in session.query(Flow).filter(Flow.capture_session_id.in_(accepted_ids)).all():
                    try:
                        address = ipaddress.ip_address(str(flow.src_ip))
                    except ValueError:
                        continue
                    if not address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
                        continue
                    try:
                        metadata = json.loads(flow.l7_metadata or "{}")
                    except (TypeError, json.JSONDecodeError):
                        metadata = {}
                    if metadata.get("generated_by") == "WatchTower":
                        continue
                    stamp = float(flow.last_seen or flow.start_time or 0.0)
                    day = datetime.fromtimestamp(stamp, timezone.utc).date().isoformat()
                    host_days.add((str(flow.src_ip), day))
            findings = session.query(DetectionFinding).filter(DetectionFinding.last_seen >= since_timestamp).all()
            grouped: Dict[Tuple[str, str, str], Dict[str, int]] = {}
            for detector in PluginLoader().get_detectors():
                manifest = getattr(detector, "manifest", None)
                if manifest is None or manifest.detector_id == "watchtower.sigma":
                    continue
                for finding_type in manifest.finding_types:
                    grouped[(manifest.detector_id, manifest.version, finding_type)] = {
                        "high_findings": 0, "critical_findings": 0, "high_false_alerts": 0,
                        "critical_false_alerts": 0, "unresolved_high_critical": 0,
                    }
            for finding in findings:
                key = (finding.detector_id, finding.detector_version, finding.finding_type)
                entry = grouped.setdefault(key, {
                    "high_findings": 0, "critical_findings": 0, "high_false_alerts": 0,
                    "critical_false_alerts": 0, "unresolved_high_critical": 0,
                })
                impact = str(finding.impact or "").upper()
                verdict = str(finding.disposition or "unknown")
                if impact == "HIGH":
                    entry["high_findings"] += 1
                    if verdict in {"false_positive", "benign_expected"}: entry["high_false_alerts"] += 1
                    if verdict == "unknown": entry["unresolved_high_critical"] += 1
                elif impact == "CRITICAL":
                    entry["critical_findings"] += 1
                    if verdict in {"false_positive", "benign_expected"}: entry["critical_false_alerts"] += 1
                    if verdict == "unknown": entry["unresolved_high_critical"] += 1
            entries = []
            for (detector_id, version, finding_type), counts in sorted(grouped.items()):
                entries.append({
                    "detector_id": detector_id, "detector_version": version, "finding_type": finding_type,
                    "relevant_host_days": float(len(host_days)), "complete_sessions": len(accepted_ids),
                    "max_sensor_drop_ratio": max_drop, **counts,
                })
            period_end = max((float(item.ended_at or item.started_at) for item in complete), default=time.time())
            bundle = {
                "schema_version": 1, "created_at": time.time(),
                "period_start": since_timestamp, "period_end": period_end,
                "exporter_version": RUNNER_VERSION,
                "entries": entries, "contains_payloads": False,
            }
            bundle["digest"] = document_digest(bundle)
            destination = Path(output).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
            return {"output": str(destination), "entries": len(entries), "digest": bundle["digest"]}
        finally:
            if owns_db:
                db.close()

    def ingest(self, field_bundle: str) -> Dict[str, Any]:
        path = Path(field_bundle).resolve()
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("digest") != document_digest(value):
            raise CalibrationError("field evidence bundle digest mismatch")
        if value.get("contains_payloads") is not False or contains_sensitive_material(value):
            raise CalibrationError("field evidence bundles may not contain payloads, credentials, tokens, or raw bytes")
        period_start = float(value.get("period_start") or 0.0)
        period_end = float(value.get("period_end") or 0.0)
        if period_start <= 0 or period_end < period_start:
            raise CalibrationError("field evidence requires a valid period_start and period_end")
        entries = [FieldEvidenceEntry.from_dict(item) for item in (value.get("entries") or [])]
        errors = [error for entry in entries for error in entry.validate()]
        if errors:
            raise CalibrationError("invalid field evidence: " + "; ".join(errors))
        self.field_dir.mkdir(parents=True, exist_ok=True)
        incoming_targets = {(entry.detector_id, entry.detector_version, entry.finding_type) for entry in entries}
        for existing_path in self.field_dir.glob("*.json"):
            existing = json.loads(existing_path.read_text(encoding="utf-8"))
            existing_start = float(existing.get("period_start") or 0.0)
            existing_end = float(existing.get("period_end") or 0.0)
            existing_targets = {
                (str(item.get("detector_id")), str(item.get("detector_version")), str(item.get("finding_type")))
                for item in (existing.get("entries") or [])
            }
            if incoming_targets & existing_targets and period_start <= existing_end and existing_start <= period_end:
                raise CalibrationError(f"field evidence overlaps an ingested period: {existing_path.name}")
        destination = self.field_dir / f"{value['digest']}.json"
        destination.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        return {"ingested": str(destination), "entries": len(entries), "digest": value["digest"]}

    @staticmethod
    def _parse_since(value: str) -> float:
        try:
            return float(value)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise CalibrationError("--since must be an epoch timestamp or ISO-8601 date") from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()

    def create_threshold_detector(
        self,
        detector_id: str,
        finding_type: str,
        description: str,
        metric: str,
        operator: str,
        threshold: int,
        category: str,
        impact: str,
        confidence_percent: int,
    ) -> Dict[str, Any]:
        """Create a working detector from a non-executable bounded template."""
        _safe_token(detector_id)
        _safe_token(finding_type)
        description = str(description or "").strip()
        if not description or len(description) > 1000:
            raise CalibrationError("detector description must be 1..1000 characters")
        expressions = {
            "byte_count": "float(flow.byte_count or 0)",
            "packet_count": "float(flow.packet_count or 0)",
            "tcp_syn_count": "float(flow.tcp_syn_count or 0)",
        }
        if metric not in expressions:
            raise CalibrationError("threshold metric must be byte_count, packet_count, or tcp_syn_count")
        comparisons = {"gte": ">=", "lte": "<="}
        if operator not in comparisons:
            raise CalibrationError("threshold operator must be gte or lte")
        threshold = int(threshold)
        if not 1 <= threshold <= 1024 * 1024 * 1024:
            raise CalibrationError("threshold must be 1..1073741824")
        category = str(category or "").upper()
        impact = str(impact or "").upper()
        if category not in {"THREAT", "ANOMALY", "EXPOSURE", "POLICY_VIOLATION"}:
            raise CalibrationError("invalid finding category")
        if impact not in {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise CalibrationError("invalid finding impact")
        confidence_percent = int(confidence_percent)
        if not 1 <= confidence_percent <= 100:
            raise CalibrationError("confidence_percent must be 1..100")

        slug = detector_id.replace("watchtower.", "").replace(".", "_").replace("-", "_")
        class_name = "".join(part.title() for part in slug.split("_")) + "Detector"
        detector_path = self.project_root / "core" / "forensics" / "plugins" / "detectors" / f"{slug}_detector.py"
        test_path = self.project_root / "tests" / f"test_{slug}_detector.py"
        corpus_path = self._corpus_path(detector_id)
        for path in (detector_path, test_path, corpus_path):
            if path.exists():
                raise CalibrationError(f"refusing to overwrite existing file: {path}")

        confidence = confidence_percent / 100.0
        detector_source = f'''from core.detection.contracts import DetectorManifestV2
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert


class {class_name}(BaseDetector):
    name = "{class_name.removesuffix('Detector')} Detector"
    description = {description!r}
    manifest = DetectorManifestV2(
        detector_id="{detector_id}", name=name, version="0.1.0",
        input_kinds=("flow",), finding_types=("{finding_type}",),
        signal_family="custom-threshold", correlation_group="{finding_type}",
        calibration_candidate=True,
    )
    finding_metadata = {{
        "{finding_type}": {{"category": "{category}", "impact": "{impact}", "confidence": {confidence!r}}},
    }}
    metric = "{metric}"
    operator = "{operator}"
    threshold = {threshold}

    def __init__(self):
        self.reset()

    def reset(self, source=None):
        self.emitted = set()

    def detect(self, flow=None, **kwargs):
        if flow is None:
            return []
        observed = {expressions[metric]}
        if not observed {comparisons[operator]} self.threshold:
            return []
        key = (tuple(flow.flow_id), self.metric, self.operator, self.threshold)
        if key in self.emitted:
            return []
        self.emitted.add(key)
        return [ForensicAlert(
            timestamp=float(flow.last_seen or 0.0),
            type="CUSTOM_THRESHOLD",
            severity="{impact}",
            score=0.0,
            explanation=self.description,
            evidence={{
                "metric": self.metric,
                "operator": self.operator,
                "threshold": self.threshold,
                "observed_value": observed,
                "flow": list(flow.flow_id),
            }},
        )]
'''
        test_source = f'''from core.calibration.corpus import flow_for_recipe
from core.forensics.plugins.detectors.{slug}_detector import {class_name}


def test_{slug}_threshold_and_reset():
    detector = {class_name}()
    assert detector.validate() == []
    positive = flow_for_recipe({{{metric!r}: {threshold}}})
    assert detector.detect(flow=positive)
    assert detector.detect(flow=positive) == []
    detector.reset("test")
    assert detector.detect(flow=positive)
'''
        if operator == "gte":
            positive_value, benign_value = threshold * 2, max(1, threshold // 2)
        else:
            positive_value, benign_value = max(1, threshold // 2), min(1024 * 1024 * 1024, threshold * 2)
        base_recipe = {
            "src": "10.250.90.10", "dst": "10.250.90.20",
            "sport": 59000, "dport": 8443, "protocol": "TCP",
            "start_time": 1.0, "last_seen": 2.0,
        }
        positive_recipe = {**base_recipe, metric: positive_value}
        benign_recipe = {**base_recipe, "dst": "10.250.90.21", metric: benign_value}
        corpus = {
            "schema_version": 1,
            "defaults": {
                "detector_id": detector_id,
                "finding_type": finding_type,
                "input_kind": "flow",
                "modes": ["isolation", "integrated"],
                "backends": ["python", "rust"],
            },
            "cases": [
                {
                    "id": f"{slug}.positive",
                    "label": "positive",
                    "variants": [
                        "positive", "malformed", "truncated", "fragmented", "retransmitted",
                        "reordered", "directional", "reset", "memory_bound", "positive_extra",
                    ],
                    "recipe": positive_recipe,
                },
                {
                    "id": f"{slug}.benign",
                    "repeat": 30,
                    "label": "benign",
                    "variant": "benign",
                    "recipe": benign_recipe,
                },
            ],
        }
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        detector_path.write_text(detector_source, encoding="utf-8")
        test_path.write_text(test_source, encoding="utf-8")
        corpus_path.write_text(yaml.safe_dump(corpus, sort_keys=False), encoding="utf-8")
        return {
            "detector": str(detector_path),
            "test": str(test_path),
            "corpus": str(corpus_path),
            "template": "flow-threshold-v1",
        }

    def scaffold(
        self, detector_id: str, finding_type: str, input_kind: str,
        description: str = "",
    ) -> Dict[str, Any]:
        _safe_token(detector_id)
        _safe_token(finding_type)
        if input_kind not in {"packet", "flow", "stream", "session", "metadata"}:
            raise CalibrationError("input kind must be packet, flow, stream, session, or metadata")
        description = str(description or "").strip()
        if len(description) > 1000:
            raise CalibrationError("detector description must be at most 1000 characters")
        slug = detector_id.replace("watchtower.", "").replace(".", "_").replace("-", "_")
        class_name = "".join(part.title() for part in slug.split("_")) + "Detector"
        detector_path = self.project_root / "core" / "forensics" / "plugins" / "detectors" / f"{slug}_detector.py"
        test_path = self.project_root / "tests" / f"test_{slug}_detector.py"
        corpus_path = self._corpus_path(detector_id)
        for path in (detector_path, test_path, corpus_path):
            if path.exists():
                raise CalibrationError(f"refusing to overwrite existing file: {path}")
        detector_source = f'''from core.detection.contracts import DetectorManifestV2\nfrom core.forensics.base import BaseDetector\n\n\nclass {class_name}(BaseDetector):\n    name = "{class_name.removesuffix('Detector')} Detector"\n    manifest = DetectorManifestV2(\n        detector_id="{detector_id}", name=name, version="0.1.0",\n        input_kinds=("{input_kind}",), finding_types=("{finding_type}",),\n        signal_family="candidate", correlation_group="{finding_type}",\n        calibration_candidate=True,\n    )\n    finding_metadata = {{\n        "{finding_type}": {{"category": "ANOMALY", "impact": "LOW", "confidence": 0.5}},\n    }}\n\n    def reset(self, source=None):\n        pass\n\n    def finalize(self, context=None):\n        return []\n\n    def detect(self, **kwargs):\n        return []\n'''
        detector_source = detector_source.replace(
            f"class {class_name}(BaseDetector):\n",
            f"class {class_name}(BaseDetector):\n    description = {description!r}\n",
            1,
        )
        test_source = f'''from core.forensics.plugins.detectors.{slug}_detector import {class_name}\n\n\ndef test_{slug}_contract_is_valid_and_not_self_calibrated():\n    detector = {class_name}()\n    assert detector.validate() == []\n    assert detector.manifest.calibration_candidate is True\n    assert detector.manifest.calibrated is False\n'''
        corpus = {
            "schema_version": 1,
            "defaults": {"detector_id": detector_id, "finding_type": finding_type, "input_kind": input_kind},
            "cases": [
                {"id": f"{slug}.positive.todo", "label": "positive", "variant": "positive", "modes": ["isolation"], "backends": ["python"], "recipe": {"packets": [{"payload_text": "TODO-positive"}]}},
                {"id": f"{slug}.benign.todo", "label": "benign", "variant": "benign", "modes": ["isolation"], "backends": ["python"], "recipe": {"packets": [{"payload_text": "normal"}]}},
            ],
        }
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        detector_path.write_text(detector_source, encoding="utf-8")
        test_path.write_text(test_source, encoding="utf-8")
        corpus_path.write_text(yaml.safe_dump(corpus, sort_keys=False), encoding="utf-8")
        return {"detector": str(detector_path), "test": str(test_path), "corpus": str(corpus_path)}

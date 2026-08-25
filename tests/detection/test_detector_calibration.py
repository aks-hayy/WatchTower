import json
from pathlib import Path

import pytest
import scapy.all as scapy
import yaml

import core.calibration.attestations as attestations
from core.calibration.attestations import (
    current_runtime_versions, document_digest, relative_hashes, scoring_policy_digest, write_attestation,
)
from core.calibration.contracts import CalibrationCase, REQUIRED_VARIANTS
from core.calibration.corpus import CorpusError, flow_for_recipe, load_corpus
from core.calibration.service import CalibrationError, CalibrationService
from core.detection.contracts import DetectionFindingV2, DetectorManifestV2
from core.detection.scoring import BASE_IMPACT, HALF_LIVES, PriorityScorer, ScoringConfig
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.storage.database import WatchtowerDB
from core.storage.models import CaptureSession, Flow, RiskSnapshot, SchemaMigration


class PassingDetector(BaseDetector):
    name = "Passing Calibration Detector"
    manifest = DetectorManifestV2(
        detector_id="test.calibration.detector", name=name, version="1.0.0",
        input_kinds=("flow",), finding_types=("recon.port_scan",),
        signal_family="test", correlation_group="test-recon",
    )
    finding_metadata = {
        "recon.port_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.95},
    }

    def reset(self, source=None):
        self.seen = 0

    def detect(self, flow=None, **kwargs):
        self.seen += 1
        if flow and flow.flow_id[3] == 9999:
            return [ForensicAlert(
                timestamp=flow.last_seen, type="PORT_SCAN", severity="MEDIUM", score=30,
                explanation="calibration positive", evidence={"target_port": 9999},
            )]
        return []


def _patch_attestation_root(monkeypatch, root: Path):
    monkeypatch.setattr(attestations, "PROJECT_ROOT", root)
    monkeypatch.setattr(attestations, "ATTESTATION_DIR", root / "calibration" / "attestations")


def _profile(path: Path, level="UNCALIBRATED", digest="", cap=60):
    data = {
        "model_version": "behavioral-v2.1",
        "uncalibrated_finding_cap": 5,
        "uncalibrated_total_cap": 10,
        "corpus_validated_finding_cap": 20,
        "corpus_validated_total_cap": 35,
        "detectors": {
            "test.calibration.detector": {
                "version": "1.0.0", "max_contribution": cap,
                "findings": {
                    "recon.port_scan": {
                        "calibration_level": level,
                        **({"attestation_digest": digest} if digest else {}),
                    },
                    "recon.host_scan": {"calibration_level": "UNCALIBRATED"},
                },
            },
        },
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return data


def _finding(finding_type="recon.port_scan"):
    return DetectionFindingV2(
        finding_type=finding_type, detector_id="test.calibration.detector", detector_version="1.0.0",
        category="ANOMALY", impact="HIGH", confidence=1.0, evidence_quality=1.0,
        calibration_state="FIELD_CALIBRATED", signal_family="test", correlation_group=finding_type,
        subject="10.0.0.5", observed_at=100.0, explanation="test", evidence={"dst_ip": "10.0.0.20"},
    )


def test_corpus_schema_expands_cases_and_rejects_duplicates(tmp_path):
    path = tmp_path / "corpus.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "defaults": {
            "detector_id": "test.calibration.detector", "finding_type": "recon.port_scan",
            "input_kind": "flow", "modes": ["isolation"], "backends": ["python"],
        },
        "cases": [{
            "id": "test.case", "repeat": 2, "label": "benign", "variant": "benign",
            "recipe": {"src": "10.0.0.1", "dst": "10.0.0.2"},
        }],
    }), encoding="utf-8")
    assert [item.case_id for item in load_corpus(path)] == ["test.case.001", "test.case.002"]
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["cases"] = [data["cases"][0] | {"repeat": 1}, data["cases"][0] | {"repeat": 1}]
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(CorpusError, match="duplicate"):
        load_corpus(path)


def test_corpus_matrix_seeds_generate_distinct_deterministic_scenarios(tmp_path):
    path = tmp_path / "seeded.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "matrix_seeds": 3,
        "defaults": {
            "detector_id": "test.calibration.detector",
            "finding_type": "recon.port_scan",
            "input_kind": "flow",
            "modes": ["isolation"],
            "backends": ["python"],
        },
        "cases": [{
            "id": "seeded.positive",
            "label": "positive",
            "variant": "positive",
            "recipe": {
                "src": "10.250.10.5", "dst": "10.250.20.5",
                "sport": 50000, "dport": 443, "start_time": 1.0,
            },
        }],
    }), encoding="utf-8")

    first = load_corpus(path)
    second = load_corpus(path)

    assert [case.case_id for case in first] == [
        "seeded.positive.seed001", "seeded.positive.seed002", "seeded.positive.seed003",
    ]
    assert first == second
    assert len({case.recipe["src"] for case in first}) == 3
    assert len({case.recipe["start_time"] for case in first}) == 3


def test_corpus_matrix_seeds_preserve_well_known_source_ports(tmp_path):
    path = tmp_path / "well-known-port.yaml"
    path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "matrix_seeds": 3,
        "defaults": {
            "detector_id": "test.calibration.detector",
            "finding_type": "network.dhcp.untrusted_server",
            "input_kind": "packet",
            "modes": ["isolation"],
            "backends": ["python"],
        },
        "cases": [{
            "id": "seeded.dhcp",
            "label": "positive",
            "variant": "positive",
            "recipe": {
                "src": "10.250.10.5", "dst": "255.255.255.255",
                "sport": 67, "dport": 68, "transport": "udp",
            },
        }],
    }), encoding="utf-8")

    cases = load_corpus(path)

    assert [case.recipe["sport"] for case in cases] == [67, 67, 67]


def test_lateral_corpus_emits_connection_start_before_authentication_failure():
    from core.calibration.corpus import packets_for_case

    case = next(
        item
        for item in load_corpus(
            attestations.PROJECT_ROOT
            / "calibration"
            / "corpus"
            / "watchtower.stateful.host.yaml"
        )
        if item.case_id == "stateful.lateral.positive.seed001"
    )
    packets = packets_for_case(case)

    for destination in {
        address
        for packet in packets
        if scapy.TCP in packet
        for address in (str(packet[scapy.IP].src), str(packet[scapy.IP].dst))
        if address != "10.250.63.10"
    }:
        related = [
            packet
            for packet in packets
            if scapy.TCP in packet
            and destination in {str(packet[scapy.IP].src), str(packet[scapy.IP].dst)}
        ]
        first = min(related, key=lambda packet: float(packet.time))
        assert str(first[scapy.IP].src) == "10.250.63.10"
        assert int(first[scapy.TCP].flags) & 0x02


def test_isolation_only_detector_cannot_reach_corpus_validated(tmp_path, monkeypatch):
    _patch_attestation_root(monkeypatch, tmp_path)
    service = CalibrationService(project_root=tmp_path, data_dir=tmp_path / "data")
    source = tmp_path / "detector.py"
    source.write_text("detector source", encoding="utf-8")
    corpus = tmp_path / "calibration" / "corpus" / "test.calibration.detector.yaml"
    corpus.parent.mkdir(parents=True)
    corpus.write_text("schema_version: 1\n", encoding="utf-8")
    monkeypatch.setattr(service, "_source_files", lambda detector: [source])
    monkeypatch.setattr(service, "_policy_digest", lambda detector_id, finding_type: "policy-digest")

    variants = sorted(REQUIRED_VARIANTS - {"benign"}) + ["positive"]
    cases = []
    for index, variant in enumerate(variants[:10]):
        cases.append(CalibrationCase(
            case_id=f"positive.{index:02d}", detector_id="test.calibration.detector",
            finding_type="recon.port_scan", label="positive", variant=variant,
            input_kind="flow", recipe={"src": "10.0.0.5", "dst": "10.0.0.20", "dport": 9999},
            modes=("isolation",), backends=("python",),
        ))
    for index in range(30):
        cases.append(CalibrationCase(
            case_id=f"benign.{index:02d}", detector_id="test.calibration.detector",
            finding_type="recon.port_scan", label="benign", variant="benign",
            input_kind="flow", recipe={"src": "10.0.0.5", "dst": "10.0.0.20", "dport": 80},
            modes=("isolation",), backends=("python",),
        ))
    report = service._evaluate(PassingDetector(), "recon.port_scan", cases, corpus, "python")
    assert report["passed"] is False
    assert report["awarded_level"] == "UNCALIBRATED"
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert "requires at least one positive integrated production-path case" in report["failures"]
    assert "requires at least one benign integrated production-path case" in report["failures"]
    assert "requires 30 relevant benign host-days" in report["field_failures"]


def test_integrated_result_is_authoritative_when_isolation_disagrees(tmp_path, monkeypatch):
    service = CalibrationService(project_root=tmp_path, data_dir=tmp_path / "data")
    detector = PassingDetector()
    case = CalibrationCase(
        case_id="production.miss",
        detector_id=detector.manifest.detector_id,
        finding_type="recon.port_scan",
        label="positive",
        variant="positive",
        input_kind="flow",
        recipe={
            "src": "10.0.0.5",
            "dst": "10.0.0.20",
            "dport": 9999,
            "packets": [{"src": "10.0.0.5", "dst": "10.0.0.20", "dport": 9999}],
        },
        modes=("isolation", "integrated"),
        backends=("python",),
    )
    monkeypatch.setattr(service, "_run_integrated", lambda *_args, **_kwargs: [])

    result = service._evaluate_case(detector, case, "python")

    assert result["production_path_evaluated"] is True
    assert result["primary_findings"] == []
    assert any("isolation and integrated findings differ" in item for item in result["failures"])


def test_attestation_controls_per_finding_trust_and_detects_source_or_policy_changes(tmp_path, monkeypatch):
    _patch_attestation_root(monkeypatch, tmp_path)
    source = tmp_path / "source.py"
    corpus = tmp_path / "corpus.yaml"
    source.write_text("one", encoding="utf-8")
    corpus.write_text("cases: []", encoding="utf-8")
    policy = scoring_policy_digest(60, BASE_IMPACT, HALF_LIVES)
    attestation = {
        "schema_version": 1,
        "target": {
            "detector_id": "test.calibration.detector", "detector_version": "1.0.0",
            "finding_type": "recon.port_scan", "policy_digest": policy,
        },
        "awarded_level": "CORPUS_VALIDATED",
        "source_files": relative_hashes([source]), "corpus_files": relative_hashes([corpus]),
        "runtime_versions": current_runtime_versions(),
        "review": {"reviewer": "analyst", "reason": "reviewed evidence", "reviewed_at": 1.0},
    }
    attestation_path = write_attestation(attestation)
    digest = json.loads(attestation_path.read_text(encoding="utf-8"))["digest"]
    profile_path = tmp_path / "profile.yaml"
    _profile(profile_path, level="CORPUS_VALIDATED", digest=digest)

    config = ScoringConfig(shipped_path=str(profile_path))
    assert config.profile_for("test.calibration.detector", "recon.port_scan", "1.0.0").calibration_level == "CORPUS_VALIDATED"
    assert config.profile_for("test.calibration.detector", "recon.host_scan", "1.0.0").calibration_level == "UNCALIBRATED"
    assessment = PriorityScorer(config).score([_finding(), _finding("recon.host_scan")], as_of=100.0)
    assert any(item.calibration_level == "CORPUS_VALIDATED" for item in assessment.contributors)
    assert assessment.priority_score < 50

    source.write_text("changed", encoding="utf-8")
    stale = ScoringConfig(shipped_path=str(profile_path)).profile_for(
        "test.calibration.detector", "recon.port_scan", "1.0.0",
    )
    assert stale.calibration_level == "UNCALIBRATED"
    assert "stale calibration dependency" in stale.stale_reason

    source.write_text("one", encoding="utf-8")
    _profile(profile_path, level="CORPUS_VALIDATED", digest=digest, cap=90)
    policy_stale = ScoringConfig(shipped_path=str(profile_path)).profile_for(
        "test.calibration.detector", "recon.port_scan", "1.0.0",
    )
    assert policy_stale.calibration_level == "UNCALIBRATED"
    assert "target mismatch" in policy_stale.stale_reason


def test_stale_profile_repair_can_only_demote_invalid_trust(tmp_path, monkeypatch):
    _patch_attestation_root(monkeypatch, tmp_path)
    profile_path = tmp_path / "profile.yaml"
    _profile(profile_path, level="CORPUS_VALIDATED", digest="0" * 64)
    service = CalibrationService(
        project_root=tmp_path,
        data_dir=tmp_path / "data",
        profile_path=profile_path,
    )

    result = service.invalidate_stale_profiles()

    assert result["demoted"] == 1
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    finding = profile["detectors"]["test.calibration.detector"]["findings"]["recon.port_scan"]
    assert finding == {"calibration_level": "UNCALIBRATED"}
    assert service.verify()["valid"] is True


def test_calibration_attestations_hash_every_rust_analysis_source():
    service = CalibrationService()
    relative = {
        path.relative_to(service.project_root).as_posix()
        for path in service._source_files(PassingDetector())
        if path.is_relative_to(service.project_root)
    }

    assert "rust/watchtower-sensor/src/main.rs" in relative
    assert "rust/watchtower-sensor/src/analysis.rs" in relative
    assert "rust/watchtower-sensor/src/wire.rs" in relative
    assert "core/forensics/rust_plan.py" in relative
    assert "core/packet_engine/rust_analysis.py" in relative
    assert "core/packet_engine/rust_capture.py" in relative


def test_reviewed_promotion_is_the_only_profile_update_path(tmp_path, monkeypatch):
    _patch_attestation_root(monkeypatch, tmp_path)
    profile_path = tmp_path / "profile.yaml"
    _profile(profile_path)
    source = tmp_path / "source.py"
    corpus = tmp_path / "calibration" / "corpus" / "test.calibration.detector.yaml"
    source.write_text("one", encoding="utf-8")
    corpus.parent.mkdir(parents=True)
    corpus.write_text("schema_version: 1", encoding="utf-8")
    service = CalibrationService(
        project_root=tmp_path, data_dir=tmp_path / "data", corpus_dir=corpus.parent,
        profile_path=profile_path,
    )
    detector = PassingDetector()
    monkeypatch.setattr(service, "_detector", lambda detector_id: detector)
    monkeypatch.setattr(service, "_source_files", lambda value: [source])
    policy = scoring_policy_digest(60, BASE_IMPACT, HALF_LIVES)
    report = {
        "schema_version": 1, "runner_version": "1.0.0",
        "target": {
            "detector_id": detector.manifest.detector_id, "detector_version": detector.manifest.version,
            "finding_type": "recon.port_scan", "policy_digest": policy,
        },
        "passed": True, "awarded_level": "CORPUS_VALIDATED",
        "metrics": {"precision": 1.0, "recall": 1.0}, "field_evidence": {},
        "source_files": relative_hashes([source]), "corpus_files": relative_hashes([corpus]),
        "environment": {"python": "test"}, "runtime_versions": current_runtime_versions(),
    }
    report["digest"] = document_digest(report)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(CalibrationError, match="reviewer and reason"):
        service.promote(str(report_path), "", "")
    promoted = service.promote(str(report_path), "reviewer", "validated corpus")
    assert promoted["promoted"] is True
    assert service.verify()["valid"] is True
    profile = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
    value = profile["detectors"][detector.manifest.detector_id]["findings"]["recon.port_scan"]
    assert value["calibration_level"] == "CORPUS_VALIDATED"
    assert value["attestation_digest"] == promoted["digest"]


def test_forged_field_level_report_cannot_bypass_field_or_bootstrap_gate(tmp_path, monkeypatch):
    _patch_attestation_root(monkeypatch, tmp_path)
    profile_path = tmp_path / "profile.yaml"
    _profile(profile_path)
    source = tmp_path / "source.py"
    corpus = tmp_path / "calibration" / "corpus" / "test.calibration.detector.yaml"
    source.write_text("one", encoding="utf-8")
    corpus.parent.mkdir(parents=True)
    corpus.write_text("schema_version: 1", encoding="utf-8")
    service = CalibrationService(
        project_root=tmp_path,
        data_dir=tmp_path / "data",
        corpus_dir=corpus.parent,
        profile_path=profile_path,
    )
    detector = PassingDetector()
    monkeypatch.setattr(service, "_detector", lambda detector_id: detector)
    monkeypatch.setattr(service, "_source_files", lambda value: [source])
    policy = scoring_policy_digest(60, BASE_IMPACT, HALF_LIVES)
    report = {
        "schema_version": 1,
        "runner_version": "1.0.0",
        "target": {
            "detector_id": detector.manifest.detector_id,
            "detector_version": detector.manifest.version,
            "finding_type": "recon.port_scan",
            "policy_digest": policy,
        },
        "passed": True,
        "awarded_level": "FIELD_CALIBRATED",
        "metrics": {
            "positive_cases": 100,
            "benign_cases": 300,
            "precision": 1.0,
            "recall": 1.0,
            "high_benign": 0,
            "critical_benign": 0,
            "deterministic": True,
            "backend_parity": True,
            "secrets_redacted": True,
            "state_within_limit": True,
        },
        "field_evidence": {},
        "bootstrap_exception": {"exception_id": "forged"},
        "source_files": relative_hashes([source]),
        "corpus_files": relative_hashes([corpus]),
        "environment": {"python": "test"},
        "runtime_versions": current_runtime_versions(),
    }
    report["digest"] = document_digest(report)
    report_path = tmp_path / "forged-report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(CalibrationError, match="field evidence or an authorized built-in bootstrap"):
        service.promote(str(report_path), "reviewer", "must not bypass trust gates")


def test_field_evidence_is_redacted_and_requires_thirty_host_days(tmp_path):
    service = CalibrationService(project_root=tmp_path, data_dir=tmp_path / "data")
    entry = {
        "detector_id": "test.calibration.detector", "detector_version": "1.0.0",
        "finding_type": "recon.port_scan", "relevant_host_days": 30,
        "complete_sessions": 3, "max_sensor_drop_ratio": 0.001,
        "high_findings": 0, "critical_findings": 0, "high_false_alerts": 3,
        "critical_false_alerts": 0, "unresolved_high_critical": 0,
    }
    bundle = {
        "schema_version": 1, "contains_payloads": False, "period_start": 1.0,
        "period_end": 86400.0, "entries": [entry],
    }
    bundle["digest"] = document_digest(bundle)
    path = tmp_path / "field.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert service.ingest(str(path))["entries"] == 1
    with pytest.raises(CalibrationError, match="overlaps"):
        service.ingest(str(path))
    assert service._field_gate(entry)[0] is True
    entry["relevant_host_days"] = 29
    assert service._field_gate(entry)[0] is False

    unsafe = {
        "schema_version": 1, "contains_payloads": False, "period_start": 1.0,
        "period_end": 2.0, "payload": "secret", "entries": [],
    }
    unsafe["digest"] = document_digest(unsafe)
    path.write_text(json.dumps(unsafe), encoding="utf-8")
    with pytest.raises(CalibrationError, match="may not contain"):
        service.ingest(str(path))


def test_builtin_bootstrap_skips_only_field_days_and_rejects_high_benign_findings(tmp_path):
    bootstrap_path = tmp_path / "calibration" / "bootstrap-v2.0.yaml"
    bootstrap_path.parent.mkdir(parents=True)
    bootstrap_path.write_text(yaml.safe_dump({
        "schema_version": 1,
        "exception_id": "builtins-v2.0",
        "targets": [{
            "detector_id": "test.calibration.detector",
            "detector_version": "1.0.0",
            "finding_type": "recon.port_scan",
        }],
    }), encoding="utf-8")
    service = CalibrationService(
        project_root=tmp_path,
        data_dir=tmp_path / "data",
        bootstrap_path=bootstrap_path,
    )
    metrics = {
        "positive_cases": 100,
        "benign_cases": 300,
        "precision": 0.95,
        "recall": 0.90,
        "high_benign": 0,
        "critical_benign": 0,
        "deterministic": True,
        "backend_parity": True,
        "secrets_redacted": True,
        "state_within_limit": True,
    }

    passed, failures, exception_id = service._bootstrap_gate(
        "test.calibration.detector", "1.0.0", "recon.port_scan", metrics, True,
    )
    assert passed is True
    assert failures == []
    assert exception_id == "builtins-v2.0"

    high_benign = metrics | {"high_benign": 1}
    passed, failures, _ = service._bootstrap_gate(
        "test.calibration.detector", "1.0.0", "recon.port_scan", high_benign, True,
    )
    assert passed is False
    assert "bootstrap corpus produced HIGH benign findings" in failures

    passed, failures, _ = service._bootstrap_gate(
        "vendor.custom.detector", "1.0.0", "recon.port_scan", metrics, True,
    )
    assert passed is False
    assert "target is not authorized for the built-in bootstrap exception" in failures


def test_scaffold_is_calibration_ready_and_refuses_overwrite(tmp_path):
    for relative in ("core/forensics/plugins/detectors", "tests", "calibration/corpus"):
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    service = CalibrationService(project_root=tmp_path, data_dir=tmp_path / "data")
    result = service.scaffold(
        "vendor.example.detector", "anomaly.example.detected", "packet",
        description="Detect a bounded example anomaly from structured packet evidence.",
    )
    source = Path(result["detector"]).read_text(encoding="utf-8")
    assert "Detect a bounded example anomaly" in source
    namespace = {}
    exec(compile(source, result["detector"], "exec"), namespace)
    detector_class = next(
        value for value in namespace.values()
        if isinstance(value, type) and value.__name__.endswith("Detector") and value is not BaseDetector
    )
    detector = detector_class()
    assert detector.validate() == []
    assert detector.manifest.calibration_candidate is True
    assert detector.manifest.calibrated is False
    with pytest.raises(CalibrationError, match="overwrite"):
        service.scaffold("vendor.example.detector", "anomaly.example.detected", "packet")


def test_threshold_detector_authoring_generates_bounded_logic_tests_and_corpus(tmp_path):
    for relative in ("core/forensics/plugins/detectors", "tests", "calibration/corpus"):
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    service = CalibrationService(project_root=tmp_path, data_dir=tmp_path / "data")

    result = service.create_threshold_detector(
        detector_id="vendor.large.flow",
        finding_type="exfil.custom.large_flow",
        description="Detect a large directional flow.",
        metric="byte_count",
        operator="gte",
        threshold=1024,
        category="ANOMALY",
        impact="MEDIUM",
        confidence_percent=80,
    )

    source = Path(result["detector"]).read_text(encoding="utf-8")
    namespace = {}
    exec(compile(source, result["detector"], "exec"), namespace)
    detector_class = next(
        value for value in namespace.values()
        if isinstance(value, type) and value.__name__.endswith("Detector") and value is not BaseDetector
    )
    detector = detector_class()
    assert detector.validate() == []
    assert detector.detect(flow=flow_for_recipe({"byte_count": 1024}))
    assert detector.detect(flow=flow_for_recipe({"byte_count": 1023})) == []
    assert "payload" not in source.lower()

    cases = load_corpus(Path(result["corpus"]))
    assert sum(case.label == "positive" for case in cases) == 10
    assert sum(case.label == "benign" for case in cases) == 30
    assert {case.variant for case in cases} >= REQUIRED_VARIANTS


def test_existing_findings_receive_v21_snapshot_on_database_upgrade(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_detection_finding(_finding())
    session = db._get_session()
    session.query(RiskSnapshot).delete(synchronize_session=False)
    session.query(SchemaMigration).filter_by(version="behavioral-v2.1-001").delete(synchronize_session=False)
    session.commit()
    db.close()

    upgraded = WatchtowerDB(data_dir=str(tmp_path))
    try:
        snapshot = upgraded.get_risk_snapshot("10.0.0.5")
        assert snapshot is not None
        assert snapshot["model_version"] == "behavioral-v2.1"
        assert 0.0 <= snapshot["priority_score"] <= 5.0
    finally:
        upgraded.close()


def test_calibration_inventory_excludes_disabled_legacy_detectors(tmp_path):
    service = CalibrationService(
        project_root=Path(__file__).resolve().parents[2],
        data_dir=tmp_path / "data",
    )

    targets = service.status()["targets"]
    detector_ids = {item["detector_id"] for item in targets}

    assert "watchtower.stateful.host" in detector_ids
    assert "watchtower.recon" not in detector_ids
    assert "watchtower.behavior.beacon" not in detector_ids
    assert "watchtower.exfiltration" not in detector_ids
    with pytest.raises(CalibrationError, match="expected one enabled detector"):
        service._detector("watchtower.recon")


def test_stateful_corpus_bounds_expensive_integrated_replays():
    corpus = load_corpus(
        Path(__file__).resolve().parents[2]
        / "calibration"
        / "corpus"
        / "watchtower.stateful.host.yaml"
    )

    for finding_type in {
        "recon.port_scan",
        "recon.host_scan",
        "recon.syn_flood",
        "lateral.admin_fanout",
        "behavior.beacon.suspected",
    }:
        cases = [case for case in corpus if case.finding_type == finding_type]
        integrated = [case for case in cases if "integrated" in case.modes]
        assert sum(case.label == "positive" for case in cases) == 100
        assert sum(case.label == "benign" for case in cases) == 300
        assert sum(case.label == "positive" for case in integrated) == 1
        assert sum(case.label == "benign" for case in integrated) == 1
        assert {case.variant for case in cases} >= REQUIRED_VARIANTS


def test_integrated_replay_applies_case_detector_policy(tmp_path):
    service = CalibrationService(
        project_root=Path(__file__).resolve().parents[2],
        data_dir=tmp_path / "data",
    )
    case = CalibrationCase(
        case_id="iot.modbus.integrated-policy",
        detector_id="watchtower.iot-ot.safety",
        finding_type="ot.modbus.unauthorized_write",
        label="positive",
        variant="positive",
        input_kind="packet",
        modes=("integrated",),
        backends=("python",),
        recipe={
            "detector_config": {
                "policy": {
                    "enabled": True,
                    "authorized_masters": ["10.250.70.10"],
                    "authorized_units": [1],
                    "authorized_write_functions": [6],
                },
            },
            "src": "10.250.70.99",
            "dst": "10.250.70.20",
            "sport": 55000,
            "dport": 502,
            "transport": "tcp",
            "payload_hex": "000100000006010600010002",
        },
    )

    findings = service._run_integrated(case, "python", "memory")

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "ot.modbus.unauthorized_write"


def test_field_export_counts_only_private_non_probe_host_days(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "data"))
    session = db._get_session()
    session.add(CaptureSession(
        id="complete-session", source_type="network", device_id="eth0", interface="Ethernet",
        backend="python", source="live_Ethernet", started_at=100.0, ended_at=200.0,
        status="STOPPED", received_packets=1000, dropped_packets=1,
        processing_state="complete", complete=True,
    ))
    session.add_all([
        Flow(
            src_ip="192.168.1.10", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
            protocol="TCP", start_time=110.0, last_seen=120.0, source="live_Ethernet",
            capture_session_id="complete-session", l7_metadata="{}",
        ),
        Flow(
            src_ip="127.250.0.10", dst_ip="8.8.8.8", src_port=50001, dst_port=443,
            protocol="TCP", start_time=120.0, last_seen=130.0, source="live_Ethernet",
            capture_session_id="complete-session", l7_metadata="{}",
        ),
        Flow(
            src_ip="192.168.1.20", dst_ip="8.8.4.4", src_port=50002, dst_port=443,
            protocol="TCP", start_time=130.0, last_seen=140.0, source="live_Ethernet",
            capture_session_id="complete-session", l7_metadata='{"generated_by": "WatchTower"}',
        ),
    ])
    session.commit()
    output = tmp_path / "field-export.json"
    service = CalibrationService(project_root=Path(__file__).resolve().parents[2], data_dir=tmp_path / "data")
    result = service.field_export("1", str(output), db=db)
    bundle = json.loads(output.read_text(encoding="utf-8"))
    assert result["entries"] > 0
    assert bundle["contains_payloads"] is False
    assert {entry["relevant_host_days"] for entry in bundle["entries"]} == {1.0}
    db.close()

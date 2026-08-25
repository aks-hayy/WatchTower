import math

import pytest

from core.detection.contracts import DetectionFindingV2, DetectorManifestV2, legacy_alert_to_finding
from core.detection.scoring import (
    PriorityScorer,
    ScoringConfig,
    clear_default_scoring_config_cache,
    default_scoring_config,
)
from core.forensics.models import ForensicAlert
from core.storage.database import WatchtowerDB


def finding(**overrides):
    values = {
        "finding_type": "credential.cleartext.ftp",
        "detector_id": "watchtower.credential.ftp",
        "detector_version": "2.0.0",
        "category": "EXPOSURE",
        "impact": "HIGH",
        "confidence": 0.9,
        "evidence_quality": 1.0,
        "calibration_state": "CALIBRATED",
        "signal_family": "credential",
        "correlation_group": "cleartext-credential",
        "subject": "192.168.1.10",
        "target": "192.168.1.20",
        "observed_at": 1000.0,
        "source": "pcap:test",
        "explanation": "A password was sent without transport encryption.",
        "evidence": {"protocol": "FTP", "dst_ip": "192.168.1.20", "dst_port": 21},
    }
    values.update(overrides)
    return DetectionFindingV2(**values)


def test_manifest_and_finding_validation_are_strict():
    manifest = DetectorManifestV2(
        detector_id="watchtower.credential.ftp", name="FTP", finding_types=("credential.cleartext.ftp",),
        required_evidence={"credential.cleartext.ftp": ("protocol", "dst_ip")},
    )
    assert manifest.validate() == []
    assert finding().validate(manifest) == []
    broken = finding(confidence=float("nan"))
    assert any("confidence" in error for error in broken.validate(manifest))


def test_finding_evidence_is_centrally_redacted():
    item = finding(evidence={
        "protocol": "HTTP", "authorization": "Bearer super-secret-token",
        "payload_excerpt": b"password=hunter2", "payload_length": 16,
    })
    serialized = str(item.evidence).lower()
    assert "super-secret-token" not in serialized
    assert "hunter2" not in serialized
    assert item.evidence["authorization"]["redacted"] is True
    assert item.evidence["payload_length"] == 16


def test_priority_is_bounded_deterministic_and_order_independent():
    scorer = PriorityScorer()
    findings = [
        finding(),
        finding(
            finding_type="intel.ioc_match", detector_id="watchtower.sigma",
            category="THREAT", impact="CRITICAL", confidence=0.95,
            signal_family="intel", correlation_group="sigma", evidence={"rule_id": "one"},
        ),
    ]
    one = scorer.score(findings, as_of=1000.0)
    two = scorer.score(reversed(findings), as_of=1000.0)
    assert one.priority_score == two.priority_score
    assert 0 <= one.priority_score <= 100
    assert math.isfinite(one.priority_score)
    assert one.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_correlated_findings_use_strongest_and_recurrence_is_bounded():
    scorer = PriorityScorer()
    single = scorer.score([finding()], as_of=1000.0)
    duplicate_group = scorer.score([
        finding(),
        finding(subject="192.168.1.10", target="192.168.1.30", evidence={"protocol": "FTP", "dst_ip": "192.168.1.30"}),
    ], as_of=1000.0)
    repeated = scorer.score([finding(occurrence_count=100)], as_of=1000.0)
    assert duplicate_group.priority_score == single.priority_score
    assert repeated.priority_score <= single.priority_score * 1.35 + 0.1


def test_uncalibrated_plugins_cannot_break_global_score():
    scorer = PriorityScorer()
    findings = [
        finding(
            detector_id=f"thirdparty.detector.{index}", finding_type=f"anomaly.thirdparty.{index}",
            impact="CRITICAL", confidence=1.0, calibration_state="UNCALIBRATED",
            correlation_group=f"thirdparty-{index}", evidence={"index": index},
        )
        for index in range(100)
    ]
    assessment = scorer.score(findings, as_of=1000.0)
    assert assessment.priority_score == 10.0
    assert len(assessment.contributors) == 1
    assert assessment.contributors[0].calibrated is False


def test_recency_decays_and_false_positive_is_removed():
    scorer = PriorityScorer()
    current = scorer.score([finding(impact="LOW")], as_of=1000.0)
    old = scorer.score([finding(impact="LOW")], as_of=1000.0 + 14 * 86400)
    suppressed = finding()
    suppressed.disposition = "false_positive"
    none = scorer.score([suppressed], as_of=1000.0)
    assert old.priority_score < current.priority_score
    assert none.priority_score == 0.0


def test_legacy_adapter_is_namespaced_and_uncalibrated():
    alert = ForensicAlert(10.0, "BEACONING", "HIGH", 30.0, "periodic", {"dst_ip": "8.8.8.8"})
    converted = legacy_alert_to_finding(alert, "192.168.1.10", source="live_Ethernet")
    assert converted.finding_type == "behavior.beacon.suspected"
    assert converted.calibration_state == "LEGACY_MAPPED"
    assert converted.validate() == []


def test_database_finding_dedup_snapshot_and_disposition(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    item = finding(capture_interface="Ethernet", capture_session_id="session-1")
    first = db.upsert_detection_finding(item)
    second = db.upsert_detection_finding(item)
    assert first["created"] is True
    assert second["created"] is False
    rows = db.get_detection_findings(subject=item.subject, source=item.source)
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2
    assessment = db.recompute_risk(
        item.subject, source=item.source, interface="Ethernet", capture_session_id="session-1", as_of=1000.0,
    )
    assert assessment["priority_score"] > 0
    result = db.set_finding_disposition(first["id"], "false_positive", "verified benign test")
    assert result["assessment"]["priority_score"] == 0.0
    db.close()


def test_node_scoped_risk_never_mixes_sensor_vantage_points(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    remote = finding(source="mesh:node-a:live", sensor_node_id="node-a")
    local = finding(source="live_Ethernet#one", sensor_node_id=db.local_sensor_node_id(), impact="LOW")
    db.upsert_detection_finding(remote)
    db.upsert_detection_finding(local)
    remote_assessment = db.recompute_risk(remote.subject, sensor_node_id="node-a", as_of=1000.0)
    local_assessment = db.recompute_risk(remote.subject, sensor_node_id=db.local_sensor_node_id(), as_of=1000.0)
    assert len(db.get_detection_findings(sensor_node_id="node-a")) == 1
    assert len(db.get_detection_findings(sensor_node_id=db.local_sensor_node_id())) == 1
    assert remote_assessment["scope"]["id"] == "node-a"
    assert local_assessment["scope"]["id"] == db.local_sensor_node_id()
    assert db.get_risk_snapshot(remote.subject, sensor_node_id="node-a")["sensor_node_id"] == "node-a"
    assert db.get_risk_snapshot(remote.subject, sensor_node_id=db.local_sensor_node_id())["sensor_node_id"] == db.local_sensor_node_id()
    db.close()


def test_v2_mode_projects_findings_for_legacy_alert_consumers(tmp_path, monkeypatch):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_detection_finding(finding())
    monkeypatch.setenv("WATCHTOWER_SCORING_MODE", "v2")
    alerts = db.get_alerts(entity_ip="192.168.1.10")
    assert alerts[0]["type"] == "CLEARTEXT_CREDENTIALS"
    assert alerts[0]["entity_ip"] == "192.168.1.10"
    assert alerts[0]["evidence"]["protocol"] == "FTP"
    db.close()


def test_invalid_scoring_override_is_rejected(tmp_path):
    path = tmp_path / "scoring.yaml"
    path.write_text("uncalibrated_finding_cap: 20\nuncalibrated_total_cap: 10\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid scoring configuration"):
        PriorityScorer(ScoringConfig(override_path=str(path)))


def test_default_scoring_config_reuses_verified_policy_until_files_change():
    clear_default_scoring_config_cache()
    first = default_scoring_config()
    second = default_scoring_config()

    assert second is first


def test_operator_override_cannot_raise_calibration_tier_caps(tmp_path):
    path = tmp_path / "scoring.yaml"
    path.write_text(
        "uncalibrated_finding_cap: 5\nuncalibrated_total_cap: 11\n"
        "corpus_validated_finding_cap: 20\ncorpus_validated_total_cap: 36\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Invalid scoring configuration"):
        PriorityScorer(ScoringConfig(override_path=str(path)))

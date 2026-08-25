from core.detection.policy import DetectionPolicy
from core.detection.stateful import StatefulHostDetector
from core.packet_engine.schemas import FlowAggregate
from core.storage.database import WatchtowerDB


def test_domain_allowlist_uses_dns_suffix_boundaries():
    policy = DetectionPolicy(config={"allowlists": {"domains": ["google.com"]}})

    allowed = policy.evaluate(
        "10.1.1.5", "SUSPICIOUS_DNS", "MEDIUM", 25, "entropy",
        {"domain": "mail.google.com"},
    )
    lookalike = policy.evaluate(
        "10.1.1.5", "SUSPICIOUS_DNS", "MEDIUM", 25, "entropy",
        {"domain": "evilgoogle.com"},
    )

    assert allowed.suppressed is True
    assert lookalike.suppressed is False


def test_ioc_match_overrides_allowlist_and_escalates():
    policy = DetectionPolicy(config={
        "allowlists": {"ips": ["8.8.8.8"]},
        "iocs": {"ips": ["8.8.8.8"]},
    })

    decision = policy.evaluate(
        "10.1.1.5", "KNOWN_BAD", "MEDIUM", 20, "matched",
        {"dst_ip": "8.8.8.8"},
    )

    assert decision.suppressed is False
    assert decision.severity == "CRITICAL"
    assert decision.score == 90.0
    assert decision.context["ioc_matches"] == ["ip:8.8.8.8"]


def test_low_sensitivity_subnet_reduces_score_and_severity():
    policy = DetectionPolicy(config={
        "subnets": {"192.168.1.0/24": {"sensitivity": 0.5}},
    })

    decision = policy.evaluate("192.168.1.20", "NOISY_BEHAVIOR", "HIGH", 40, "noise")

    assert decision.score == 20.0
    assert decision.severity == "LOW"


def test_database_deduplicates_without_reinflating_risk(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.alert_policy = DetectionPolicy(config={"dedup_window_seconds": 300})
    db.upsert_entity("192.168.1.10", timestamp=1.0)

    first = db.insert_alert(
        "192.168.1.10", 100.0, "BEACONING", "HIGH", 30, "periodic",
        evidence={"dst_ip": "8.8.8.8"},
    )
    duplicate = db.insert_alert(
        "192.168.1.10", 120.0, "BEACONING", "HIGH", 30, "periodic",
        evidence={"dst_ip": "8.8.8.8"},
    )

    alerts = db.get_alerts(entity_ip="192.168.1.10")
    assert first["created"] is True
    assert duplicate["created"] is False
    assert len(alerts) == 1
    assert alerts[0]["occurrence_count"] == 2
    assert alerts[0]["first_seen"] == 100.0
    assert alerts[0]["last_seen"] == 120.0
    assert db.get_entity("192.168.1.10")["risk_score"] == 30.0
    db.close()


def test_suppressed_alert_is_auditable_but_not_active(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.alert_policy = DetectionPolicy(config={"allowlists": {"ips": ["192.168.1.20"]}})

    result = db.insert_alert("192.168.1.20", 10.0, "SCAN", "HIGH", 50, "scanner")

    assert result["suppressed"] is True
    assert db.get_alerts(entity_ip="192.168.1.20") == []
    hidden = db.get_alerts(entity_ip="192.168.1.20", include_hidden=True)
    assert hidden[0]["suppression_reason"] == "IP allowlist"
    assert db.get_entity("192.168.1.20")["risk_score"] == 0.0
    db.close()


def test_dual_mode_policy_suppression_retains_zero_risk_v2_evidence(tmp_path):
    from core.forensics.engine import ForensicsEngine
    from core.forensics.models import ForensicAlert

    db = WatchtowerDB(data_dir=str(tmp_path))
    db.alert_policy = DetectionPolicy(config={"allowlists": {"ips": ["192.168.1.20"]}})
    engine = ForensicsEngine(db=db, data_dir=str(tmp_path), silent=True)
    alert = ForensicAlert(10.0, "TEST_POLICY", "HIGH", 50, "policy test", {"dst_ip": "8.8.8.8"})
    assert engine._store_alert("192.168.1.20", alert) is False
    findings = db.get_detection_findings(subject="192.168.1.20", include_suppressed=True)
    assert len(findings) == 1
    assert findings[0]["disposition"] == "benign_expected"
    assert db.recompute_risk("192.168.1.20", as_of=10.0, persist=False)["priority_score"] == 0
    db.close()


def test_stateful_detector_correlates_host_wide_behaviors():
    flows = {}
    for index in range(20):
        flow_id = ("192.168.1.10", f"192.168.1.{100 + index}", 50000 + index, 445, "TCP")
        flow = FlowAggregate(flow_id, 1.0, 2.0)
        flow.packet_count = 2
        flow.byte_count = 100
        flows[flow_id] = flow
    for port in range(20, 40):
        flow_id = ("192.168.1.10", "192.168.1.200", 51000 + port, port, "TCP")
        flow = FlowAggregate(flow_id, 1.0, 3.0)
        flow.packet_count = 1
        flow.byte_count = 60
        flows[flow_id] = flow
    exfil_id = ("192.168.1.10", "8.8.8.8", 52000, 443, "TCP")
    exfil = FlowAggregate(exfil_id, 1.0, 4.0)
    exfil.packet_count = 500
    exfil.byte_count = 120 * 1024 * 1024
    exfil.l7_metadata = {"reverse_byte_count": 1024 * 1024, "peer_novelty": True}
    flows[exfil_id] = exfil

    alerts = StatefulHostDetector().analyze(flows)
    types = {alert.type for _ip, alert in alerts}

    assert {"HORIZONTAL_SCAN", "SERVICE_ENUMERATION", "POTENTIAL_EXFILTRATION"} <= types

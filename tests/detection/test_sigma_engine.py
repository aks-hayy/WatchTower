import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
import yaml

from core.forensics.sigma_engine import SigmaCompatibilityError, SigmaEngine, SigmaPredicate, validate_rule
from core.forensics.sigma_sync import DEFAULT_REPOSITORY, SigmaCorpusManager, SigmaRuleManager
from core.storage.database import WatchtowerDB


def _rule(condition="selection", detection=None, rule_id=None):
    return {
        "title": "Test network rule", "id": rule_id or str(uuid4()), "status": "stable",
        "logsource": {"category": "network_connection"},
        "detection": detection or {"selection": {"DestinationPort": 445}, "condition": condition},
        "level": "high",
    }


def test_default_sigma_corpus_targets_official_repository(tmp_path):
    manager = SigmaCorpusManager(tmp_path / "managed")

    assert DEFAULT_REPOSITORY == "https://github.com/SigmaHQ/sigma.git"
    assert manager.status()["repository"] == DEFAULT_REPOSITORY


def test_sigma_predicate_modifiers_and_conditions():
    detection = {
        "selection_port": {"DestinationPort": [445, 3389]},
        "selection_net": {"SourceIp|cidr": "10.0.0.0/8"},
        "selection_name": {"remote_hostname|endswith": ".example.test"},
        "filter": {"SourceIp": "10.0.0.1"},
        "condition": "all of selection* and not filter",
    }
    predicate = SigmaPredicate(_rule(detection=detection))
    record = {"src_ip": "10.2.3.4", "dst_port": 445, "l7_metadata": {"remote_hostname": "host.example.test"}}
    assert predicate.matches(record)
    assert not predicate.matches({**record, "src_ip": "10.0.0.1"})


def test_sigma_rejects_unsupported_logic_explicitly():
    rule = _rule(detection={"selection": {"DestinationPort|base64": "NDQ1"}, "condition": "selection"})
    assert any("unsupported modifier" in reason for reason in validate_rule(rule))
    with pytest.raises(SigmaCompatibilityError):
        SigmaPredicate(rule)


def test_sigmahq_dns_rule_uses_dns_flows_only(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine

    rule = _rule(
        rule_id="2975af79-28c4-4d2f-a951-9095f229df29",
        detection={"selection": {"query|startswith": "aaa.stage."}, "condition": "selection"},
    )
    rule["logsource"] = {"category": "dns"}
    rule["level"] = "critical"
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "sigmahq-dns.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")
    for destination_port in (53, 443):
        db.upsert_flow(
            src_ip="10.0.0.2", dst_ip="1.1.1.1", src_port=50000 + destination_port,
            dst_port=destination_port, protocol="UDP" if destination_port == 53 else "TCP",
            start_time=float(destination_port), last_seen=float(destination_port), packet_count=1,
            byte_count=80, l7_metadata={"remote_hostname": "aaa.stage.example"},
            source="pcap:sigmahq",
        )

    engine = SigmaEngine(plugins_dir=rules, managed_dir=tmp_path / "managed",
                         custom_dir=tmp_path / "custom", db=db)
    matches = engine.run_hunt(source="pcap:sigmahq", persist=False)

    assert validate_rule(rule, upstream=True) == []
    assert len(matches) == 1


def _commit_rule(repo, rule):
    rules = repo / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "rule.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "-c", "user.name=WatchTower Tests", "-c", "user.email=watchtower-tests-at-example-invalid",
                    "commit", "-m", "rules"], cwd=repo, check=True, capture_output=True)


def test_sigma_atomic_sync_and_rollback(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    first = _rule(rule_id=str(uuid4()))
    _commit_rule(repo, first)
    manager = SigmaCorpusManager(tmp_path / "managed", repository=str(repo))
    manifest = manager.sync()
    assert manifest.accepted == 1
    assert manager.status()["manifest"]["commit"] == manifest.commit

    second = _rule(rule_id=str(uuid4()), detection={"selection": {"DestinationPort": 3389}, "condition": "selection"})
    _commit_rule(repo, second)
    second_manifest = manager.sync()
    assert second_manifest.commit != manifest.commit
    rolled_back = manager.rollback()
    assert rolled_back.commit == manifest.commit


def test_failed_sigma_sync_retains_active_rules(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    _commit_rule(repo, _rule())
    manager = SigmaCorpusManager(tmp_path / "managed", repository=str(repo))
    original = manager.sync().commit
    monkeypatch.setattr(manager, "_stage_rules", lambda *args: (_ for _ in ()).throw(RuntimeError("interrupted")))
    with pytest.raises(RuntimeError, match="interrupted"):
        manager.sync()
    assert manager.status()["manifest"]["commit"] == original


def test_sigma_preview_does_not_persist_alerts(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine
    db = WatchtowerDB(data_dir=tmp_path)
    db.upsert_entity(ip="10.0.0.2", source="pcap:test", timestamp=1.0)
    db.upsert_flow(src_ip="10.0.0.2", dst_ip="10.0.0.3", src_port=1234, dst_port=21,
                   protocol="TCP", start_time=1.0, last_seen=2.0, packet_count=1,
                   byte_count=60, source="pcap:test")
    engine = SigmaEngine(db=db)
    matches = engine.run_hunt(source="pcap:test", specific_rule="Suspicious FTP Data Transfer (Sample)", persist=False)
    assert len(matches) == 1
    assert db.get_alerts(source="pcap:test") == []


def test_sigma_identity_hunt_applies_the_same_scope_as_flow_hunt(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine

    rule = _rule(
        rule_id="3d6f0a3e-8f63-4bd4-a0cc-f11d3d6b64ab",
        detection={"selection": {"IpAddress|cidr": "10.0.0.0/24"}, "condition": "selection"},
    )
    rule["logsource"] = {"category": "network_identity"}
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "identity-scope.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")
    db.upsert_entity(ip="10.0.0.1", source="pcap:scope", timestamp=10.0)
    db.upsert_entity(ip="10.0.0.2", source="pcap:scope", timestamp=100.0)
    db.upsert_flow(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=1,
        byte_count=80, source="pcap:scope", capture_session_id="session-a",
        capture_interface="Ethernet", sensor_node_id="node-a",
    )
    db.upsert_flow(
        src_ip="10.0.0.2", dst_ip="8.8.4.4", src_port=50001, dst_port=443,
        protocol="TCP", start_time=100.0, last_seen=101.0, packet_count=1,
        byte_count=80, source="pcap:scope", capture_session_id="session-b",
        capture_interface="Wi-Fi", sensor_node_id="node-b",
    )
    engine = SigmaEngine(plugins_dir=rules, managed_dir=tmp_path / "managed",
                         custom_dir=tmp_path / "custom", db=db)

    matches = engine.run_hunt(
        source="pcap:scope", interface="Ethernet", capture_session_id="session-a",
        sensor_node_id="node-a", time_start=0.0, time_end=20.0,
        target_ips=["10.0.0.1"], persist=False,
    )

    assert len(matches) == 1
    assert matches[0].evidence["record_id"]
    db.close()


def test_sigma_identity_hunt_does_not_use_hostname_from_another_capture_session(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine

    rule = _rule(
        rule_id="2486f227-6448-4bad-b121-7ad4f44ec10c",
        detection={"selection": {"Hostname": "outside.example"}, "condition": "selection"},
    )
    rule["logsource"] = {"category": "network_identity"}
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "identity-session-scope.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")

    # Entity is a global-per-IP projection; this hostname was observed only in session B.
    db.upsert_entity(ip="10.0.0.1", hostname="outside.example", source="pcap:scope", timestamp=101.0)
    db.upsert_identity_observations([{
        "subject_ip": "10.0.0.1", "source": "pcap:scope", "capture_interface": "Wi-Fi",
        "capture_session_id": "session-b", "sensor_node_id": "node-b",
        "observation_type": "dns_name", "value": {"name": "outside.example"},
        "confidence": 0.88, "evidence_ref": "flow:session-b",
        "first_seen": 100.0, "last_seen": 101.0,
    }])
    db.upsert_flow(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=1,
        byte_count=80, source="pcap:scope", capture_session_id="session-a",
        capture_interface="Ethernet", sensor_node_id="node-a",
    )
    engine = SigmaEngine(plugins_dir=rules, managed_dir=tmp_path / "managed",
                         custom_dir=tmp_path / "custom", db=db)

    matches = engine.run_hunt(
        source="pcap:scope", interface="Ethernet", capture_session_id="session-a",
        sensor_node_id="node-a", time_start=0.0, time_end=20.0,
        target_ips=["10.0.0.1"], persist=False,
    )

    assert matches == []
    db.close()


def test_sigma_identity_hunt_matches_hostname_evidence_in_selected_capture_session(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine

    rule = _rule(
        rule_id="871a1ad6-46d0-4644-9a83-704664c4fa93",
        detection={"selection": {"Hostname": "inside.example"}, "condition": "selection"},
    )
    rule["logsource"] = {"category": "network_identity"}
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "identity-session-scope.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")
    db.upsert_entity(ip="10.0.0.1", hostname="legacy-global.example", source="pcap:scope", timestamp=11.0)
    db.upsert_identity_observations([{
        "subject_ip": "10.0.0.1", "source": "pcap:scope", "capture_interface": "Ethernet",
        "capture_session_id": "session-a", "sensor_node_id": "node-a",
        "observation_type": "dns_name", "value": {"name": "inside.example"},
        "confidence": 0.88, "evidence_ref": "flow:session-a",
        "first_seen": 10.0, "last_seen": 11.0,
    }])
    db.upsert_flow(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=1,
        byte_count=80, source="pcap:scope", capture_session_id="session-a",
        capture_interface="Ethernet", sensor_node_id="node-a",
        l7_metadata={"local_hostname": "flow.example"},
    )
    engine = SigmaEngine(plugins_dir=rules, managed_dir=tmp_path / "managed",
                         custom_dir=tmp_path / "custom", db=db)

    matches = engine.run_hunt(
        source="pcap:scope", interface="Ethernet", capture_session_id="session-a",
        sensor_node_id="node-a", time_start=0.0, time_end=20.0,
        target_ips=["10.0.0.1"], persist=False,
    )

    assert len(matches) == 1
    assert matches[0].evidence["record_id"] == "10.0.0.1"
    assert matches[0].timestamp == 10.0
    assert "identity:flow:session-a" in matches[0].evidence["evidence_refs"]
    assert any(reference.startswith("flow:") for reference in matches[0].evidence["evidence_refs"])
    db.close()


def test_identity_observation_query_enforces_all_requested_scope_dimensions(tmp_path):
    db = WatchtowerDB(data_dir=tmp_path / "db")
    base = {
        "subject_ip": "10.0.0.1", "source": "pcap:scope", "capture_interface": "Ethernet",
        "capture_session_id": "session-a", "sensor_node_id": "node-a",
        "observation_type": "dns_name", "value": {"name": "inside.example"},
        "confidence": 0.88, "first_seen": 10.0, "last_seen": 11.0,
    }
    variants = [
        {**base, "evidence_ref": "selected"},
        {**base, "source": "pcap:other", "evidence_ref": "wrong-source"},
        {**base, "capture_interface": "Wi-Fi", "evidence_ref": "wrong-interface"},
        {**base, "capture_session_id": "session-b", "evidence_ref": "wrong-session"},
        {**base, "sensor_node_id": "node-b", "evidence_ref": "wrong-node"},
        {**base, "first_seen": 1.0, "last_seen": 2.0, "evidence_ref": "before-window"},
        {**base, "first_seen": 21.0, "last_seen": 22.0, "evidence_ref": "after-window"},
        {**base, "subject_ip": "10.0.0.99", "evidence_ref": "wrong-target"},
    ]
    db.upsert_identity_observations(variants)

    result = db.get_identity_observations(
        source="pcap:scope", interface="Ethernet", capture_session_id="session-a",
        sensor_node_id="node-a", time_start=5.0, time_end=20.0,
        target_ips=["10.0.0.1"], limit=5000,
    )

    assert [row["evidence_ref"] for row in result] == ["selected"]
    db.close()


def test_scoped_sigma_persistence_retains_node_and_observation_times(tmp_path):
    from core.forensics.sigma_engine import SigmaEngine
    from core.storage.models import Alert, DetectionFinding

    rule = _rule(
        rule_id="a403794b-494d-4ecf-9f2d-70280713f42c",
        detection={"selection": {"Hostname": "inside.example"}, "condition": "selection"},
    )
    rule["logsource"] = {"category": "network_identity"}
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "identity-persist.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")
    db.upsert_identity_observations([{
        "subject_ip": "10.0.0.1", "source": "pcap:scope", "capture_interface": "Ethernet",
        "capture_session_id": "session-a", "sensor_node_id": "node-a",
        "observation_type": "dns_name", "value": {"name": "inside.example"},
        "confidence": 0.88, "evidence_ref": "flow:session-a",
        "first_seen": 10.0, "last_seen": 11.0,
    }])
    db.upsert_flow(
        src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=50000, dst_port=443,
        protocol="TCP", start_time=10.0, last_seen=11.0, packet_count=1,
        byte_count=80, source="pcap:scope", capture_session_id="session-a",
        capture_interface="Ethernet", sensor_node_id="node-a",
    )
    engine = SigmaEngine(plugins_dir=rules, managed_dir=tmp_path / "managed",
                         custom_dir=tmp_path / "custom", db=db)

    assert len(engine.run_hunt(
        source="pcap:scope", interface="Ethernet", capture_session_id="session-a",
        sensor_node_id="node-a", time_start=0.0, time_end=20.0,
        target_ips=["10.0.0.1"], persist=True,
    )) == 1

    with db.session_scope() as session:
        alert = session.query(Alert).filter_by(type="SIGMA_MATCH").one()
        finding = session.query(DetectionFinding).filter_by(finding_type="rule.sigma.match").one()
        assert alert.sensor_node_id == "node-a"
        assert finding.sensor_node_id == "node-a"
        assert finding.first_seen == 10.0
        assert finding.last_seen == 11.0
    db.close()


def test_remote_sigma_rule_requires_preview_hash_and_installs_separately(tmp_path, monkeypatch):
    rule = _rule()
    content = yaml.safe_dump(rule).encode("utf-8")
    manager = SigmaRuleManager(
        builtin_dir=tmp_path / "builtin",
        data_dir=tmp_path / "sigma",
    )
    monkeypatch.setattr(manager, "_fetch_url", lambda _url: content)

    preview = manager.preview_url("https://raw.githubusercontent.com/example/rule.yml")
    assert preview["compatible"] is True
    assert preview["sha256"]

    with pytest.raises(ValueError, match="changed after preview"):
        manager.install_url(preview["url"], "0" * 64)

    installed = manager.install_url(preview["url"], preview["sha256"])
    assert installed["source"] == "custom"
    inventory = manager.list_rules()
    assert inventory[0]["id"] == rule["id"]
    assert inventory[0]["source"] == "custom"


def test_sigma_inventory_and_hunts_use_watchtower_paths_outside_repository_cwd(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    working_dir = tmp_path / "operator-home"
    working_dir.mkdir()
    runtime_home = tmp_path / "runtime-home"
    environment = os.environ.copy()
    environment["WATCHTOWER_HOME"] = str(runtime_home)
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(repository), environment.get("PYTHONPATH", "")) if value
    )
    program = """
import json
from core.forensics.sigma_engine import SigmaEngine
from core.forensics.sigma_sync import SigmaCorpusManager, SigmaRuleManager
from core.storage.database import WatchtowerDB

db = WatchtowerDB()
rules = SigmaRuleManager().list_rules()
engine = SigmaEngine(db=db)
print(json.dumps({
    "rule_ids": sorted(rule["id"] for rule in rules if rule["compatible"]),
    "engine_rule_ids": sorted(rule["id"] for rule in engine.rules),
    "builtin_dir": str(SigmaRuleManager().builtin.resolve()),
    "managed_root": str(SigmaCorpusManager().root.resolve()),
    "rule_data_root": str(SigmaRuleManager().root.resolve()),
    "engine_rule_dirs": [str(path.resolve()) for path in engine.rule_dirs],
    "runtime_data": str(db.data_dir.resolve()),
}))
db.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=working_dir,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    expected_builtin = repository / "core" / "forensics" / "plugins" / "sigma"
    expected_sigma_root = repository / "data" / "sigma"
    expected_rule_ids = {
        "c92ab6e7-9d55-4f33-80f1-4ce91010f998",
        "8d4f40fb-f6f1-44be-8d03-81bda2bb8df0",
    }
    assert set(report["rule_ids"]) == expected_rule_ids
    assert set(report["engine_rule_ids"]) == expected_rule_ids
    assert Path(report["builtin_dir"]) == expected_builtin
    assert Path(report["managed_root"]) == expected_sigma_root
    assert Path(report["rule_data_root"]) == expected_sigma_root
    assert report["engine_rule_dirs"] == [
        str(expected_builtin),
        str(expected_sigma_root / "custom"),
        str(expected_sigma_root / "active"),
    ]
    assert Path(report["runtime_data"]) == runtime_home / "data"


def test_sigma_hunt_report_discloses_flow_cap_truncation(tmp_path, monkeypatch):
    import core.forensics.sigma_engine as sigma_engine

    monkeypatch.setattr(sigma_engine, "SIGMA_FLOW_HUNT_LIMIT", 1, raising=False)
    rules = tmp_path / "rules"
    rules.mkdir()
    rule = _rule(detection={"selection": {"DestinationPort": 445}, "condition": "selection"})
    (rules / "rule.yml").write_text(yaml.safe_dump(rule), encoding="utf-8")
    db = WatchtowerDB(data_dir=tmp_path / "db")
    for port in (80, 445):
        db.upsert_flow(
            src_ip="10.0.0.2", dst_ip="10.0.0.3", src_port=50000 + port,
            dst_port=port, protocol="TCP", start_time=float(port), last_seen=float(port),
            packet_count=100 if port == 80 else 1, byte_count=80, source="pcap:cap",
        )
    engine = sigma_engine.SigmaEngine(
        plugins_dir=rules, managed_dir=tmp_path / "managed",
        custom_dir=tmp_path / "custom", db=db,
    )

    report = engine.run_hunt_report(source="pcap:cap", persist=False)

    assert report["complete"] is False
    assert report["evaluated_flows"] == 1
    assert report["limitations"] == ["Flow evaluation reached the 1-record limit; matches may be missing."]
    assert report["alerts"] == []


def test_sigma_hunt_report_distinguishes_zero_compatible_rules(tmp_path):
    empty = tmp_path / "empty-rules"
    empty.mkdir()
    db = WatchtowerDB(data_dir=tmp_path / "db-empty-rules")
    engine = SigmaEngine(
        plugins_dir=empty, managed_dir=tmp_path / "managed-empty",
        custom_dir=tmp_path / "custom-empty", db=db,
    )

    report = engine.run_hunt_report(source="pcap:fixture", persist=False)

    assert report["complete"] is True
    assert report["coverage_status"] == "no_compatible_rules"
    assert report["evaluated_rules"] == 0

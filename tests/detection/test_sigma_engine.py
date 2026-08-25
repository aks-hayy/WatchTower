import subprocess
from uuid import uuid4

import pytest
import yaml

from core.forensics.sigma_engine import SigmaCompatibilityError, SigmaPredicate, validate_rule
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
    subprocess.run(["git", "-c", "user.name=WatchTower Tests", "-c", "user.email=tests@watchtower.local",
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

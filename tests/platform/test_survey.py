import hashlib
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.survey.probe_registry import ProbeRegistry
from core.survey.runner import SurveyConfig, SurveyRunner, parse_duration


class FakeDB:
    def __init__(self): self.observations = []
    def get_all_entities(self):
        return [{"ip": "192.168.50.2", "hostname": "inside"}, {"ip": "8.8.8.8", "hostname": "outside"}]
    def get_flows(self, **kwargs): return []
    def get_alerts(self, **kwargs): return []
    def insert_hardware_observation(self, observation): self.observations.append(observation); return len(self.observations)


def test_survey_scope_limits_and_hashed_case(tmp_path, monkeypatch):
    db = FakeDB()
    runner = SurveyRunner(db, tmp_path)
    monkeypatch.setattr(runner, "directly_connected_networks", lambda: [
        {"interface": "Ethernet", "address": "192.168.50.1", "network": "192.168.50.0/24", "version": 4}
    ])
    targets = []
    monkeypatch.setattr(runner, "_resolve", lambda source, target, limiter: None)
    monkeypatch.setattr(runner, "_arp_probe", lambda source, target, config, limiter: None)
    monkeypatch.setattr(runner, "_icmp_probe", lambda source, target, config, limiter: None)
    monkeypatch.setattr(runner, "_udp_discovery", lambda source, protocol, config, limiter: None)
    def probe(source, target, port, config, limiter):
        targets.append((target, port))
        return None
    monkeypatch.setattr(runner, "_tcp_probe", probe)
    report = runner.run(SurveyConfig(duration_seconds=0, active="safe", packets_per_second=100, concurrency=32), capture=False)
    assert targets and {target for target, _port in targets} == {"192.168.50.2"}
    assert len(targets) == len(set(targets)) == 7
    manifest_path = Path(report.case_path) / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for filename, digest in manifest["files"].items():
        assert hashlib.sha256((Path(report.case_path) / filename).read_bytes()).hexdigest() == digest


def test_survey_safety_caps_and_duration_parser(tmp_path):
    runner = SurveyRunner(FakeDB(), tmp_path)
    with pytest.raises(ValueError, match="100 packets"):
        runner.run(SurveyConfig(duration_seconds=0, packets_per_second=101), capture=False)
    with pytest.raises(ValueError, match="32 concurrent"):
        runner.run(SurveyConfig(duration_seconds=0, concurrency=33), capture=False)
    assert parse_duration("60m") == 3600
    assert parse_duration("1h") == 3600


def test_probe_registry_is_exact_and_auditable(tmp_path):
    registry = ProbeRegistry(tmp_path)
    registry.register("192.168.1.2", "192.168.1.3", 61001, 443, "TCP")
    assert registry.matches("192.168.1.2", "192.168.1.3", 61001, 443, "TCP")
    assert not registry.matches("192.168.1.2", "8.8.8.8", 61001, 443, "TCP")
    record = json.loads((tmp_path / "survey-probes.json").read_text(encoding="utf-8"))[0]
    assert record["generated_by"] == "WatchTower"


def test_probe_registry_concurrent_writers(tmp_path):
    registry = ProbeRegistry(tmp_path)
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(registry.register, "192.168.1.2", "192.168.1.3", 50000 + index, 443, "TCP")
                   for index in range(100)]
        for future in futures: future.result()
    records = json.loads((tmp_path / "survey-probes.json").read_text(encoding="utf-8"))
    assert len(records) == 100


def test_probe_audit_releases_connections_under_concurrency(tmp_path):
    from core.storage.database import WatchtowerDB
    db = WatchtowerDB(data_dir=tmp_path / "db")
    observation = {"timestamp": 1.0, "source_type": "survey", "observation_type": "survey_probe",
                   "subject": "192.168.1.2", "peer": "192.168.1.3", "metadata": {"generated_by": "WatchTower"}}
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(db.insert_hardware_observation, observation) for _ in range(100)]
        for future in futures: assert future.result() > 0

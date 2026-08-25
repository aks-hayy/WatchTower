from core.forensics.triage import OfflineTriageEngine


class FakeTriageDB:
    def __init__(self, findings):
        self.findings = findings
        self.flags = []

    def get_detection_findings(self, **_kwargs):
        return self.findings

    def upsert_triage_flag(self, case_id, values):
        self.flags.append({"case_id": case_id, **values})
        return self.flags[-1]


def _finding(item_id, target, finding_type, impact="MEDIUM", confidence=0.6):
    return {
        "id": item_id,
        "fingerprint": f"fp-{item_id}",
        "target": target,
        "subject": target,
        "finding_type": finding_type,
        "detector_id": f"detector-{finding_type}",
        "impact": impact,
        "confidence": confidence,
        "first_seen": 10.0,
        "last_seen": 20.0,
        "explanation": f"signal {finding_type}",
        "evidence_refs": [f"evidence:{item_id}"],
        "evidence": {"threshold": "test"},
    }


def test_triage_requires_one_strong_or_two_independent_weak_signals():
    db = FakeTriageDB([
        _finding(1, "198.51.100.9", "dns.tunnel.suspected"),
        _finding(2, "198.51.100.9", "behavior.beacon.suspected"),
        _finding(3, "198.51.100.10", "protocol.nonstandard_service"),
        _finding(4, "198.51.100.11", "intel.ioc_match", impact="HIGH", confidence=0.7),
    ])
    result = OfflineTriageEngine(db).run(case_id="case-1", source="pcap:1:test")
    assert result == {"flagged": 2, "signals": 4}
    assert {item["target_id"] for item in db.flags} == {"198.51.100.9", "198.51.100.11"}
    assert all(item["target_type"] == "ip" for item in db.flags)

import pytest

from core.storage.database import WatchtowerDB


@pytest.fixture
def db(tmp_path):
    db_instance = WatchtowerDB(data_dir=str(tmp_path))
    yield db_instance
    db_instance.close()


def test_same_ip_can_have_independent_entities_in_two_cases(db):
    db.create_forensic_case({"id": "case-a", "analysis_id": "analysis-a", "sha256": "a" * 64})
    db.create_forensic_case({"id": "case-b", "analysis_id": "analysis-b", "sha256": "b" * 64})

    db.upsert_case_entity("case-a", {"ip": "10.0.0.5", "hostname": "alpha", "confidence": 0.8})
    db.upsert_case_entity("case-b", {"ip": "10.0.0.5", "hostname": "bravo", "confidence": 0.9})

    assert db.get_case_entities("case-a", 100, None)["items"][0]["hostname"] == "alpha"
    assert db.get_case_entities("case-b", 100, None)["items"][0]["hostname"] == "bravo"


def test_triage_flag_is_case_scoped_and_idempotent(db):
    db.create_forensic_case({"id": "case-a", "analysis_id": "analysis-a", "sha256": "a" * 64})

    values = {
        "target_type": "ip",
        "target_id": "203.0.113.5",
        "fingerprint": "f" * 64,
        "reason": "IOC match",
        "confidence": 0.95,
        "status": "open",
    }

    first = db.upsert_triage_flag("case-a", values)
    second = db.upsert_triage_flag("case-a", values)

    assert first["id"] == second["id"]
    assert len(db.get_triage_flags("case-a")["items"]) == 1

import time

from core.forensics.identity import IdentityResolver
from core.forensics.models import ForensicAlert
from core.packet_engine.processors import AlertManager
from core.packet_engine.schemas import FlowAggregate
from core.storage.database import WatchtowerDB


def test_identity_resolver_preserves_stronger_observation():
    resolver = IdentityResolver()
    resolver.observe("10.0.0.5", "NTLM Parser", {"username": "ACME\\alice"}, 10.0)
    resolver.observe("10.0.0.5", "FTP Parser", {"username": "ftp://anonymous"}, 20.0)

    assert resolver.values_for("10.0.0.5")["username"] == "ACME\\alice"
    assert resolver.strongest_source("10.0.0.5").source == "NTLM Parser"


def test_entity_upsert_does_not_erase_or_downgrade_identity(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    db.upsert_entity(
        "10.0.0.5", hostname="trusted-host", username="ACME\\alice",
        confidence=0.92, identity_source="NTLM Parser", timestamp=10.0,
    )
    db.upsert_entity(
        "10.0.0.5", hostname=None, username="anonymous",
        confidence=0.45, identity_source="FTP Parser", timestamp=20.0,
    )

    entity = db.get_entity("10.0.0.5")
    assert entity["hostname"] == "trusted-host"
    assert entity["username"] == "ACME\\alice"
    assert entity["confidence_score"] == 0.92
    assert entity["last_seen"] == 20.0
    db.close()


def test_forensic_alert_records_use_flow_source_ip():
    flow = FlowAggregate(("10.0.0.5", "8.8.8.8", 50000, 443, "TCP"), time.time(), time.time())
    alert = ForensicAlert(time.time(), "KNOWN_BAD", "HIGH", 80.0, "matched", {})

    records = AlertManager().process_alerts(flow, 0.0, 80.0, [alert])

    forensic = next(record for record in records if record.entity_type == "FORENSIC")
    assert forensic.entity_id == "10.0.0.5"

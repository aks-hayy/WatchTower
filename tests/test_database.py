import pytest
import os
from core.storage.database import WatchtowerDB

@pytest.fixture
def db():
    # Use a temporary test database
    test_dir = "data/test_db"
    db_instance = WatchtowerDB(data_dir=test_dir)
    yield db_instance
    
    # Cleanup
    db_instance.close()
    import shutil
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)

def test_db_initialization(db):
    assert os.path.exists(os.path.join(db.data_dir, "watchtower.db"))
    # Verify tables exist using SQLAlchemy inspector
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    assert "flows" in tables
    assert "alerts" in tables
    assert "entities" in tables

def test_entity_persistence(db):
    db.upsert_entity("1.2.3.4", mac="AA:BB:CC:DD:EE:FF", hostname="test-host")
    entity = db.get_entity("1.2.3.4")
    assert entity["ip"] == "1.2.3.4"
    assert entity["hostname"] == "test-host"
    assert entity["mac"] == "AA:BB:CC:DD:EE:FF"

def test_alert_persistence(db):
    import time
    db.upsert_entity("1.2.3.4")
    db.insert_alert("1.2.3.4", time.time(), "TEST_ALERT", "HIGH", 80, "Test explanation")
    alerts = db.get_alerts(entity_ip="1.2.3.4")
    assert len(alerts) == 1
    assert alerts[0]["type"] == "TEST_ALERT"
    assert alerts[0]["score"] == 80

def test_db_reset(db):
    db.upsert_entity("1.1.1.1")
    import time
    db.insert_alert("1.1.1.1", time.time(), "ALERT", "LOW", 10, "msg")
    db.reset_all()
    assert len(db.get_all_entities()) == 0
    assert len(db.get_alerts()) == 0

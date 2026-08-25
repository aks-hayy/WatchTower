import pytest


fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from core.api.server import create_app
from core.storage.database import WatchtowerDB


def test_ai_conversation_api_round_trip_and_delete(tmp_path):
    database = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(db=database)
    try:
        with TestClient(app) as client:
            created = client.post("/api/v2/ai/conversations", json={
                "title": "Scoped analyst test",
                "provider": "ollama",
                "scope": {"source": "pcap:fixture", "interface": "Ethernet", "max_records": 20},
            })
            assert created.status_code == 201
            conversation = created.json()
            assert conversation["scope"]["source"] == "pcap:fixture"

            listed = client.get("/api/v2/ai/conversations")
            assert listed.status_code == 200
            assert [item["id"] for item in listed.json()] == [conversation["id"]]

            fetched = client.get(f"/api/v2/ai/conversations/{conversation['id']}")
            assert fetched.status_code == 200
            assert fetched.json()["messages"] == []

            deleted = client.delete(f"/api/v2/ai/conversations/{conversation['id']}")
            assert deleted.status_code == 200
            assert client.get(f"/api/v2/ai/conversations/{conversation['id']}").status_code == 404
    finally:
        database.close()

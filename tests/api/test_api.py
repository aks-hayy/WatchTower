import pytest
from fastapi.testclient import TestClient
import multiprocessing
import os

server = pytest.importorskip(
    "core.packet_engine.server",
    reason="API/auth server is intentionally deferred while backend hardening is in progress",
)
create_app = server.create_app

@pytest.fixture
def client():
    # Setup a mock queue
    q = multiprocessing.Queue()
    app = create_app(q, data_dir="data/test_api_data")
    
    # Ensure test data dir exists
    os.makedirs("data/test_api_data", exist_ok=True)
    
    with TestClient(app) as c:
        yield c
    
    # No easy way to cleanup the shm/wal files while process is still semi-active in test client
    # but we'll try later or use unique paths.

def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_auth_status_unauthorized(client):
    response = client.get("/api/interfaces")
    # Should be 401 because we have auth middleware
    assert response.status_code == 401

def test_auth_status_exempt(client):
    response = client.get("/api/status")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_rate_limiting(client):
    # Try login multiple times
    for _ in range(6):
        response = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    
    # 6th attempt should be rate limited (limit is 5/minute in our code)
    assert response.status_code == 429
    # SlowAPI default response
    assert "Rate limit exceeded" in response.text

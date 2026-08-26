import json

import pytest
from fastapi.testclient import TestClient

from core.api.server import create_app
from core.auth import AuthError, OperatorAuthService, SESSION_LIFETIME_SECONDS
from core.storage.database import WatchtowerDB
from core.storage.models import OperatorSession, SecurityAuditEvent


class OfflineDaemon:
    def get_status(self):
        return {"running": False, "healthy": False, "interfaces": []}


class EmptyRegistry:
    def list_devices(self):
        return []


class MemoryCredentialStore:
    def __init__(self):
        self.values = {}

    def set(self, reference, value):
        self.values[reference] = value

    def get(self, reference):
        return self.values.get(reference)

    def delete(self, reference):
        self.values.pop(reference, None)
        return True


class Clock:
    def __init__(self, value=1_000_000.0):
        self.value = value

    def __call__(self):
        return self.value


def test_operator_session_has_only_an_eight_hour_absolute_expiry(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    clock = Clock()
    auth = OperatorAuthService(db, clock=clock)
    result = auth.setup_pin("824691", client_type="browser")
    token = result["token"]
    expires_at = result["session"]["expires_at"]

    for advance in (60, 60 * 60, 7 * 60 * 60):
        clock.value = 1_000_000.0 + advance
        assert auth.authenticate(token).expires_at == expires_at

    assert expires_at == 1_000_000.0 + SESSION_LIFETIME_SECONDS
    clock.value = expires_at + 0.01
    with pytest.raises(AuthError, match="eight-hour"):
        auth.authenticate(token)
    row = db._get_session().query(OperatorSession).one()
    assert row.revoke_reason == "absolute_expiry"
    db.close()


def test_pin_failures_are_rate_limited_and_audit_never_contains_pin(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    clock = Clock()
    auth = OperatorAuthService(db, clock=clock)
    auth.setup_pin("824691")
    for _ in range(5):
        with pytest.raises(AuthError):
            auth.verify_pin("000000")
    with pytest.raises(AuthError) as blocked:
        auth.verify_pin("824691")
    assert blocked.value.code == "temporarily_locked"
    for row in db._get_session().query(SecurityAuditEvent).all():
        assert "824691" not in row.details_json
        assert "000000" not in row.details_json
        json.loads(row.details_json)
    db.close()


def test_pin_and_recovery_accept_copy_paste_whitespace_without_changing_credentials(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    auth = OperatorAuthService(db)
    setup = auth.setup_pin(" 824691 ")

    auth.lock(setup["token"])
    assert auth.verify_pin(" 824691 ")["status"]["state"] == "unlocked"

    auth.lock(None, all_sessions=True)
    recovered = auth.reset_with_recovery(
        f"  {setup['recovery_code'].lower().replace('-', ' - ')}  ",
        " 739182 ",
    )
    assert recovered["session"]["client_type"] == "cli"
    assert auth.verify_pin("739182")["status"]["state"] == "unlocked"
    db.close()


def test_api_first_run_setup_lock_and_unlock(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    app = create_app(
        db=db,
        daemon=OfflineDaemon(),
        registry=EmptyRegistry(),
        enforce_auth=True,
    )
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
        blocked = client.get("/api/v1/system")
        assert blocked.status_code == 428
        assert blocked.json()["error"]["code"] == "setup_required"

        setup = client.post("/api/v2/auth/setup", json={
            "mode": "secure",
            "pin": "824691",
            "display_name": "Analyst",
        })
        assert setup.status_code == 200
        assert setup.json()["status"]["authenticated"]
        assert "recovery_code" in setup.json()
        assert setup.cookies.get("watchtower_session")
        assert client.get("/api/v1/system").status_code == 200

        assert client.post("/api/v2/auth/lock").status_code == 200
        assert client.get("/api/v1/system").status_code == 401
        unlocked = client.post("/api/v2/auth/pin/verify", json={
            "pin": "824691",
            "client_type": "browser",
        })
        assert unlocked.status_code == 200
        assert unlocked.json()["status"]["authenticated"]
        assert client.get("/api/v1/system").status_code == 200


def test_webauthn_rejects_non_loopback_origins(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    auth = OperatorAuthService(db)
    setup = auth.setup_pin("824691")
    with pytest.raises(AuthError) as exc:
        auth.start_webauthn_registration(setup["token"], "https://attacker.example")
    assert exc.value.code == "invalid_origin"
    db.close()


def test_controller_ui_adopts_the_shared_controller_cli_session(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    credentials = MemoryCredentialStore()
    app = create_app(
        db=db,
        daemon=OfflineDaemon(),
        registry=EmptyRegistry(),
        enforce_auth=True,
        credential_store=credentials,
    )
    with TestClient(app) as first, TestClient(app) as second:
        setup = first.post("/api/v2/auth/setup", json={
            "mode": "secure", "pin": "824691", "display_name": "Analyst",
        })
        assert setup.status_code == 200
        assert credentials.values["watchtower-cli-session"]

        adopted = second.get("/api/v2/auth/status")
        assert adopted.status_code == 200
        assert adopted.json()["state"] == "unlocked"
        assert second.get("/api/v1/system").status_code == 200

        assert first.post("/api/v2/auth/lock").status_code == 200
        assert credentials.values == {}
    db.close()


def test_disabled_authentication_does_not_require_a_session_or_step_up(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    auth = OperatorAuthService(db)
    auth.disable_first_run()

    assert auth.authenticate(None) is None
    assert auth.require_step_up("") is None
    assert auth.status()["state"] == "disabled"
    db.close()


def test_disabled_first_run_can_later_establish_pin_and_reenable(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    auth = OperatorAuthService(db)
    auth.disable_first_run()

    enabled = auth.set_enabled(True, "", "824691")

    assert enabled["state"] == "locked"
    assert enabled["auth_enabled"] is True
    assert enabled["recovery_code"]
    unlocked = auth.verify_pin("824691")
    assert unlocked["status"]["state"] == "unlocked"
    db.close()

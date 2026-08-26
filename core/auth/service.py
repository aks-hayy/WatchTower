"""Local operator trust boundary.

Biometric verification remains inside the platform authenticator. WatchTower
stores only WebAuthn public-key material and absolute-duration session tokens.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
import json
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from core.storage.models import (
    OperatorAccount,
    OperatorChallenge,
    OperatorCredential,
    OperatorSession,
    SecurityAuditEvent,
)


AUTH_COOKIE = "watchtower_session"
SESSION_LIFETIME_SECONDS = 8 * 60 * 60
STEP_UP_MAX_AGE_SECONDS = 5 * 60
CHALLENGE_LIFETIME_SECONDS = 5 * 60
OPERATOR_ID = "local-operator"
CLI_CREDENTIAL_REFERENCE = "watchtower-cli-session"


class AuthError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class OperatorAuthService:
    def __init__(self, db, clock=time.time):
        self.db = db
        self.clock = clock
        self.passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

    @staticmethod
    def _token_hash(token: str) -> str:
        return sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _b64(value: bytes) -> str:
        return urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _unb64(value: str) -> bytes:
        return urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def _account(self) -> Optional[OperatorAccount]:
        return self.db._get_session().query(OperatorAccount).filter_by(id=OPERATOR_ID).first()

    def _installation_id(self) -> str:
        value = self.db.get_metadata("trust.installation_id")
        if value:
            return value
        value = str(uuid.uuid4())
        self.db.set_metadata("trust.installation_id", value)
        return value

    def status(self, token: Optional[str] = None) -> Dict[str, Any]:
        session = self.authenticate(token, required=False) if token else None
        account = self._account()
        credential_count = 0
        if account:
            credential_count = self.db._get_session().query(OperatorCredential).filter_by(
                operator_id=account.id,
            ).count()
        state = "setup_required"
        if account and account.setup_completed:
            state = "disabled" if not account.auth_enabled else ("unlocked" if session else "locked")
        return {
            "state": state,
            "setup_required": state == "setup_required",
            "auth_enabled": bool(account.auth_enabled) if account else True,
            "authenticated": session is not None,
            "operator": account.display_name if account else None,
            "credential_count": credential_count,
            "session": self._session_public(session) if session else None,
            "session_lifetime_seconds": SESSION_LIFETIME_SECONDS,
            "step_up_max_age_seconds": STEP_UP_MAX_AGE_SECONDS,
            "idle_timeout_seconds": None,
            "installation_id": self._installation_id(),
        }

    def setup_pin(
        self,
        pin: str,
        display_name: str = "Local Operator",
        client_type: str = "browser",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        pin = self._normalize_pin(pin)
        self._validate_pin(pin)
        session = self.db._get_session()
        account = self._account()
        if account and account.setup_completed:
            raise AuthError("already_configured", "WatchTower operator authentication is already configured", 409)
        now = self.clock()
        recovery_code = "-".join(secrets.token_hex(3).upper() for _ in range(4))
        if account is None:
            account = OperatorAccount(
                id=OPERATOR_ID,
                display_name=(display_name or "Local Operator")[:160],
                auth_enabled=True,
                setup_completed=True,
                pin_hash=self.passwords.hash(pin),
                recovery_hash=self.passwords.hash(recovery_code),
                failed_attempts=0,
                created_at=now,
                updated_at=now,
            )
            session.add(account)
        else:
            account.display_name = (display_name or "Local Operator")[:160]
            account.auth_enabled = True
            account.setup_completed = True
            account.pin_hash = self.passwords.hash(pin)
            account.recovery_hash = self.passwords.hash(recovery_code)
            account.failed_attempts = 0
            account.locked_until = None
            account.updated_at = now
        session.commit()
        raw_token, operator_session = self._create_session(client_type)
        self._audit("auth.setup", "success", client_type, request_id, {"method": "pin"})
        return {
            "status": self.status(raw_token),
            "token": raw_token,
            "recovery_code": recovery_code,
            "session": self._session_public(operator_session),
        }

    def disable_first_run(self, request_id: Optional[str] = None) -> Dict[str, Any]:
        session = self.db._get_session()
        account = self._account()
        if account and account.setup_completed:
            raise AuthError("already_configured", "Authentication settings are already configured", 409)
        now = self.clock()
        if account is None:
            account = OperatorAccount(
                id=OPERATOR_ID,
                display_name="Local Operator",
                auth_enabled=False,
                setup_completed=True,
                failed_attempts=0,
                created_at=now,
                updated_at=now,
            )
            session.add(account)
        else:
            account.setup_completed = True
            account.auth_enabled = False
            account.updated_at = now
        session.commit()
        self._audit("auth.setup", "success", "browser", request_id, {"method": "disabled"})
        return self.status()

    def set_enabled(self, enabled: bool, token: str, pin: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        current = self.require_step_up(token)
        pin = self._normalize_pin(pin)
        account = self._account()
        if account is None:
            raise AuthError("setup_required", "Operator authentication has not been configured", 409)
        recovery_code = None
        if enabled and not account.pin_hash:
            self._validate_pin(pin)
            recovery_code = "-".join(secrets.token_hex(3).upper() for _ in range(4))
            account.pin_hash = self.passwords.hash(pin)
            account.recovery_hash = self.passwords.hash(recovery_code)
            account.failed_attempts = 0
            account.locked_until = None
        else:
            self._verify_pin_value(pin)
        account.auth_enabled = bool(enabled)
        account.updated_at = self.clock()
        self.db._get_session().commit()
        self._audit(
            "auth.settings",
            "success",
            current.client_type if current is not None else "browser",
            request_id,
            {"auth_enabled": bool(enabled)},
        )
        result = self.status(token if enabled else None)
        if recovery_code:
            result["recovery_code"] = recovery_code
        return result

    def verify_pin(
        self,
        pin: str,
        client_type: str = "browser",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            self._verify_pin_value(pin)
        except AuthError:
            self._audit("auth.unlock", "failure", client_type, request_id, {"method": "pin"})
            raise
        raw_token, session = self._create_session(client_type)
        self._audit("auth.unlock", "success", client_type, request_id, {"method": "pin"})
        return {"token": raw_token, "session": self._session_public(session), "status": self.status(raw_token)}

    def step_up_pin(self, token: str, pin: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        operator_session = self.authenticate(token)
        pin = self._normalize_pin(pin)
        self._verify_pin_value(pin)
        operator_session.step_up_at = self.clock()
        self.db._get_session().commit()
        self._audit("auth.step_up", "success", operator_session.client_type, request_id, {"method": "pin"})
        return {"session": self._session_public(operator_session), "status": self.status(token)}

    def authenticate(self, token: Optional[str], required: bool = True) -> Optional[OperatorSession]:
        account = self._account()
        if account and account.setup_completed and not account.auth_enabled:
            return None
        if not account or not account.setup_completed:
            if required:
                raise AuthError("setup_required", "Complete WatchTower operator setup before using the API", 428)
            return None
        if not token:
            if required:
                raise AuthError("authentication_required", "Unlock WatchTower to continue")
            return None
        now = self.clock()
        row = self.db._get_session().query(OperatorSession).filter_by(
            token_hash=self._token_hash(token),
        ).first()
        if row is None or row.revoked_at is not None:
            if required:
                raise AuthError("invalid_session", "The WatchTower session is invalid or locked")
            return None
        if float(row.expires_at) <= now:
            if row.revoked_at is None:
                row.revoked_at = now
                row.revoke_reason = "absolute_expiry"
                self.db._get_session().commit()
            if required:
                raise AuthError("session_expired", "The eight-hour WatchTower session has expired")
            return None
        if row.installation_id != self._installation_id():
            if required:
                raise AuthError("installation_mismatch", "The session belongs to another WatchTower installation")
            return None
        return row

    def require_step_up(self, token: str) -> Optional[OperatorSession]:
        account = self._account()
        if account and account.setup_completed and not account.auth_enabled:
            return None
        row = self.authenticate(token)
        if self.clock() - float(row.step_up_at) > STEP_UP_MAX_AGE_SECONDS:
            raise AuthError("step_up_required", "Re-authenticate before performing this sensitive operation", 403)
        return row

    def lock(self, token: Optional[str], all_sessions: bool = False, reason: str = "operator_lock") -> int:
        session = self.db._get_session()
        now = self.clock()
        query = session.query(OperatorSession).filter(
            OperatorSession.operator_id == OPERATOR_ID,
            OperatorSession.revoked_at.is_(None),
        )
        if not all_sessions:
            if not token:
                return 0
            query = query.filter(OperatorSession.token_hash == self._token_hash(token))
        rows = query.all()
        for row in rows:
            row.revoked_at = now
            row.revoke_reason = reason[:160]
        if rows:
            session.commit()
        return len(rows)

    def factors(self) -> Dict[str, Any]:
        account = self._account()
        rows = self.db._get_session().query(OperatorCredential).filter_by(operator_id=OPERATOR_ID).all()
        return {
            "pin": bool(account and account.pin_hash),
            "recovery": bool(account and account.recovery_hash),
            "passkeys": [
                {
                    "id": row.id,
                    "nickname": row.nickname,
                    "created_at": row.created_at,
                    "last_used_at": row.last_used_at,
                }
                for row in rows
            ],
        }

    def start_webauthn_registration(self, token: str, origin: str, nickname: str = "Windows Hello") -> Dict[str, Any]:
        self.authenticate(token)
        rp_id = self._validated_rp(origin)
        challenge = secrets.token_bytes(32)
        credentials = self.db._get_session().query(OperatorCredential).filter_by(operator_id=OPERATOR_ID).all()
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name="WatchTower",
            user_name=OPERATOR_ID,
            user_id=OPERATOR_ID.encode("utf-8"),
            user_display_name=self._account().display_name,
            challenge=challenge,
            timeout=CHALLENGE_LIFETIME_SECONDS * 1000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id))
                for row in credentials
            ],
        )
        record = self._store_challenge("registration", challenge, origin, rp_id)
        return {"challenge_id": record.id, "options": json.loads(options_to_json(options)), "nickname": nickname[:120]}

    def finish_webauthn_registration(
        self,
        token: str,
        challenge_id: str,
        credential: Dict[str, Any],
        nickname: str = "Windows Hello",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        operator_session = self.authenticate(token)
        challenge = self._challenge(challenge_id, "registration")
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=self._unb64(challenge.challenge),
                expected_rp_id=challenge.rp_id,
                expected_origin=challenge.origin,
                require_user_verification=True,
            )
        except Exception as exc:
            self._audit("auth.passkey.register", "failure", operator_session.client_type, request_id, {})
            raise AuthError("webauthn_verification_failed", f"Passkey verification failed: {exc}", 422) from exc
        session = self.db._get_session()
        encoded_id = bytes_to_base64url(verified.credential_id)
        if session.query(OperatorCredential).filter_by(credential_id=encoded_id).first():
            raise AuthError("credential_exists", "This passkey is already registered", 409)
        session.add(OperatorCredential(
            id=str(uuid.uuid4()),
            operator_id=OPERATOR_ID,
            credential_id=encoded_id,
            public_key=self._b64(verified.credential_public_key),
            sign_count=int(verified.sign_count),
            transports_json=json.dumps(credential.get("response", {}).get("transports") or []),
            nickname=(nickname or "Windows Hello")[:120],
            created_at=self.clock(),
        ))
        challenge.consumed_at = self.clock()
        operator_session.step_up_at = self.clock()
        session.commit()
        self._audit("auth.passkey.register", "success", operator_session.client_type, request_id, {})
        return {"status": self.status(token), "factors": self.factors()}

    def start_webauthn_authentication(self, origin: str) -> Dict[str, Any]:
        rp_id = self._validated_rp(origin)
        credentials = self.db._get_session().query(OperatorCredential).filter_by(operator_id=OPERATOR_ID).all()
        if not credentials:
            raise AuthError("passkey_unavailable", "No passkey is registered for this operator", 409)
        challenge = secrets.token_bytes(32)
        options = generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            timeout=CHALLENGE_LIFETIME_SECONDS * 1000,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(row.credential_id))
                for row in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        record = self._store_challenge("authentication", challenge, origin, rp_id)
        return {"challenge_id": record.id, "options": json.loads(options_to_json(options))}

    def finish_webauthn_authentication(
        self,
        challenge_id: str,
        credential: Dict[str, Any],
        client_type: str = "browser",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        challenge = self._challenge(challenge_id, "authentication")
        credential_id = str(credential.get("id") or credential.get("rawId") or "")
        row = self.db._get_session().query(OperatorCredential).filter_by(credential_id=credential_id).first()
        if row is None:
            raise AuthError("credential_unknown", "The passkey is not registered with WatchTower")
        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=self._unb64(challenge.challenge),
                expected_rp_id=challenge.rp_id,
                expected_origin=challenge.origin,
                credential_public_key=self._unb64(row.public_key),
                credential_current_sign_count=int(row.sign_count or 0),
                require_user_verification=True,
            )
        except Exception as exc:
            self._audit("auth.unlock", "failure", client_type, request_id, {"method": "passkey"})
            raise AuthError("webauthn_verification_failed", f"Passkey verification failed: {exc}", 422) from exc
        now = self.clock()
        row.sign_count = int(verified.new_sign_count)
        row.last_used_at = now
        challenge.consumed_at = now
        self.db._get_session().commit()
        raw_token, operator_session = self._create_session(client_type)
        self._audit("auth.unlock", "success", client_type, request_id, {"method": "passkey"})
        return {"token": raw_token, "session": self._session_public(operator_session), "status": self.status(raw_token)}

    def reset_with_recovery(
        self,
        recovery_code: str,
        new_pin: str,
        client_type: str = "cli",
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        recovery_code = self._normalize_recovery_code(recovery_code)
        new_pin = self._normalize_pin(new_pin)
        self._validate_pin(new_pin)
        account = self._account()
        if not account or not account.recovery_hash:
            raise AuthError("recovery_unavailable", "No WatchTower recovery code is configured", 409)
        try:
            valid = self.passwords.verify(account.recovery_hash, recovery_code)
        except (VerifyMismatchError, InvalidHashError):
            valid = False
        if not valid:
            self._audit("auth.recovery", "failure", client_type, request_id, {})
            raise AuthError("invalid_recovery_code", "The recovery code is invalid")
        recovery = "-".join(secrets.token_hex(3).upper() for _ in range(4))
        account.pin_hash = self.passwords.hash(new_pin)
        account.recovery_hash = self.passwords.hash(recovery)
        account.failed_attempts = 0
        account.locked_until = None
        account.auth_enabled = True
        account.updated_at = self.clock()
        self.lock(None, all_sessions=True, reason="recovery_reset")
        self.db._get_session().commit()
        raw_token, operator_session = self._create_session(client_type)
        self._audit("auth.recovery", "success", client_type, request_id, {})
        return {"token": raw_token, "recovery_code": recovery, "session": self._session_public(operator_session)}

    def reset_as_os_admin(
        self,
        new_pin: str,
        reason: str,
        is_admin: bool,
        client_type: str = "cli",
    ) -> Dict[str, Any]:
        if not is_admin:
            raise AuthError("administrator_required", "Local administrator privileges are required", 403)
        if len(reason.strip()) < 8:
            raise AuthError("reason_required", "Provide an auditable recovery reason", 422)
        account = self._account()
        if account is None:
            return self.setup_pin(new_pin, client_type=client_type)
        new_pin = self._normalize_pin(new_pin)
        self._validate_pin(new_pin)
        recovery = "-".join(secrets.token_hex(3).upper() for _ in range(4))
        account.pin_hash = self.passwords.hash(new_pin)
        account.recovery_hash = self.passwords.hash(recovery)
        account.auth_enabled = True
        account.setup_completed = True
        account.failed_attempts = 0
        account.locked_until = None
        account.updated_at = self.clock()
        self.lock(None, all_sessions=True, reason="os_admin_recovery")
        self.db._get_session().commit()
        raw_token, operator_session = self._create_session(client_type)
        self._audit("auth.os_admin_recovery", "success", client_type, None, {"reason": reason[:500]})
        return {"token": raw_token, "recovery_code": recovery, "session": self._session_public(operator_session)}

    def _verify_pin_value(self, pin: str) -> None:
        normalized_pin = self._normalize_pin(pin)
        account = self._account()
        if not account or not account.setup_completed or not account.auth_enabled:
            raise AuthError("authentication_unavailable", "PIN authentication is not enabled", 409)
        now = self.clock()
        if account.locked_until and float(account.locked_until) > now:
            wait = max(1, int(float(account.locked_until) - now))
            raise AuthError("temporarily_locked", f"Too many attempts. Try again in {wait} seconds", 429)
        valid = False
        if account.pin_hash:
            try:
                valid = self.passwords.verify(account.pin_hash, normalized_pin)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
            # Keep accounts created by older versions usable if an operator
            # deliberately chose leading/trailing whitespace.
            if not valid and normalized_pin != pin:
                try:
                    valid = self.passwords.verify(account.pin_hash, pin)
                except (VerifyMismatchError, InvalidHashError):
                    valid = False
        if not valid:
            account.failed_attempts = int(account.failed_attempts or 0) + 1
            if account.failed_attempts >= 5:
                account.locked_until = now + min(300, 2 ** min(account.failed_attempts - 4, 8))
            account.updated_at = now
            self.db._get_session().commit()
            raise AuthError("invalid_pin", "The operator PIN is incorrect")
        account.failed_attempts = 0
        account.locked_until = None
        account.updated_at = now
        if self.passwords.check_needs_rehash(account.pin_hash):
            account.pin_hash = self.passwords.hash(normalized_pin)
        self.db._get_session().commit()

    @staticmethod
    def _normalize_pin(pin: str) -> str:
        return str(pin or "").strip()

    @staticmethod
    def _normalize_recovery_code(code: str) -> str:
        # Generated codes contain no whitespace. Removing pasted spaces or
        # newlines and normalizing case makes the one-time flow reliable.
        return "".join(str(code or "").split()).upper()

    @staticmethod
    def _validate_pin(pin: str) -> None:
        if len(pin or "") < 6 or len(pin) > 128:
            raise AuthError("invalid_pin", "Use a PIN with at least six characters", 422)

    def _create_session(self, client_type: str) -> tuple[str, OperatorSession]:
        now = self.clock()
        raw_token = secrets.token_urlsafe(48)
        row = OperatorSession(
            id=str(uuid.uuid4()),
            operator_id=OPERATOR_ID,
            token_hash=self._token_hash(raw_token),
            client_type=(client_type or "browser")[:32],
            installation_id=self._installation_id(),
            created_at=now,
            authenticated_at=now,
            step_up_at=now,
            expires_at=now + SESSION_LIFETIME_SECONDS,
        )
        self.db._get_session().add(row)
        self.db._get_session().commit()
        return raw_token, row

    @staticmethod
    def _session_public(row: OperatorSession) -> Dict[str, Any]:
        return {
            "id": row.id,
            "client_type": row.client_type,
            "authenticated_at": row.authenticated_at,
            "step_up_at": row.step_up_at,
            "expires_at": row.expires_at,
        }

    def _store_challenge(self, kind: str, challenge: bytes, origin: str, rp_id: str) -> OperatorChallenge:
        now = self.clock()
        row = OperatorChallenge(
            id=str(uuid.uuid4()),
            operator_id=OPERATOR_ID,
            kind=kind,
            challenge=self._b64(challenge),
            origin=origin,
            rp_id=rp_id,
            created_at=now,
            expires_at=now + CHALLENGE_LIFETIME_SECONDS,
        )
        self.db._get_session().add(row)
        self.db._get_session().commit()
        return row

    def _challenge(self, challenge_id: str, kind: str) -> OperatorChallenge:
        row = self.db._get_session().query(OperatorChallenge).filter_by(id=challenge_id, kind=kind).first()
        if row is None or row.consumed_at is not None or float(row.expires_at) <= self.clock():
            raise AuthError("challenge_expired", "The WebAuthn challenge is invalid, expired, or already used", 409)
        return row

    @staticmethod
    def _validated_rp(origin: str) -> str:
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise AuthError("invalid_origin", "WebAuthn is restricted to the local WatchTower origin", 403)
        return parsed.hostname

    def _audit(
        self,
        event_type: str,
        outcome: str,
        client_type: str,
        request_id: Optional[str],
        details: Dict[str, Any],
    ) -> None:
        allowed = {
            str(key)[:80]: value
            for key, value in details.items()
            if key not in {"pin", "secret", "token", "credential", "recovery_code"}
        }
        self.db._get_session().add(SecurityAuditEvent(
            id=str(uuid.uuid4()),
            operator_id=OPERATOR_ID,
            event_type=event_type[:120],
            outcome=outcome[:32],
            client_type=(client_type or "unknown")[:32],
            request_id=(request_id or "")[:64] or None,
            details_json=json.dumps(allowed, sort_keys=True, default=str)[:4000],
            created_at=self.clock(),
        ))
        self.db._get_session().commit()

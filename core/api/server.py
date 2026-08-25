"""Loopback HTTP control plane used by the WatchTower operator UI."""

import logging
import json
import os
from pathlib import Path
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, File, Form, Query, Request, Response, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from core.api.schemas import (
    AlertDto,
    CalibrationPromoteRequest,
    AIApprovalRequest,
    AIConversationRequest,
    AICredentialRequest,
    AIProviderConnectRequest,
    AIProviderModelRequest,
    AuthChallengeRequest,
    AuthPinRequest,
    AuthRecoveryRequest,
    AuthSettingsRequest,
    AuthSetupRequest,
    AuthVerifyRequest,
    MeshCommandRequest,
    MeshControllerSetupRequest,
    MeshEnrollmentRequest,
    MeshRevokeRequest,
    AIRunRequest,
    CalibrationRunRequest,
    CapabilityResponse,
    CaptureActionRequest,
    CaptureDeviceDto,
    EntityDto,
    FlowDto,
    HealthResponse,
    HuntRequest,
    ResetRequest,
    SigmaRemoteRequest,
    FindingDispositionRequest,
    EnrichmentRebuildRequest,
    IdentityRebuildRequest,
    IdentityConfirmRequest,
    IdentityEnrichRequest,
    ScoringRecomputeRequest,
    StopCaptureRequest,
    StopCaptureSessionRequest,
    SystemInfo,
)
from core.api.service import ApiServiceError, WatchtowerApiService
from core.ai.config import CredentialStore
from core.graph.worker import GraphMaterializerWorker
from core.auth import AUTH_COOKIE, AuthError, OperatorAuthService, SESSION_LIFETIME_SECONDS
from core.auth.service import CLI_CREDENTIAL_REFERENCE
from core.context import context
from core import __version__


logger = logging.getLogger("watchtower.api")


def create_app(db=None, daemon=None, registry=None, jobs=None, enforce_auth: Optional[bool] = None,
               credential_store=None) -> FastAPI:
    service = WatchtowerApiService(db=db, daemon=daemon, registry=registry, jobs=jobs)
    owns_database = db is None
    enforce_auth = owns_database if enforce_auth is None else bool(enforce_auth)
    auth = OperatorAuthService(service.db) if hasattr(service.db, "_get_session") else None
    credentials = credential_store or CredentialStore()

    @asynccontextmanager
    async def lifespan(_app):
        graph_worker = GraphMaterializerWorker(service.graph())
        service.graph_worker = graph_worker
        graph_worker.start()
        yield
        graph_worker.stop()
        service.close()
        if owns_database:
            service.db.close()

    app = FastAPI(
        title="WatchTower Local API",
        version=__version__,
        description="Versioned loopback control plane for WatchTower analyst clients.",
        lifespan=lifespan,
    )
    app.state.service = service
    app.state.auth = auth
    app.state.enforce_auth = enforce_auth
    app.state.credentials = credentials
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:3000",
            "http://127.0.0.1:4173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://localhost:4173",
            "http://localhost:5173",
        ],
        allow_origin_regex=r"^http://(127\.0\.0\.1|localhost):\d+$",
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Server-Timing"],
    )

    def get_service() -> WatchtowerApiService:
        return app.state.service

    def get_auth() -> OperatorAuthService:
        if app.state.auth is None:
            raise ApiServiceError(503, "auth_unavailable", "The local authentication service is unavailable")
        return app.state.auth

    def shared_cli_token(authentication: OperatorAuthService) -> Optional[str]:
        try:
            token = credentials.get(CLI_CREDENTIAL_REFERENCE)
            if token and authentication.authenticate(token, required=False):
                return token
            if token:
                credentials.delete(CLI_CREDENTIAL_REFERENCE)
        except Exception as exc:
            logger.warning("Controller CLI session store is unavailable: %s", exc)
        return None

    def remember_cli_token(token: Optional[str]) -> None:
        if not token:
            return
        try:
            credentials.set(CLI_CREDENTIAL_REFERENCE, token)
        except Exception as exc:
            logger.warning("Could not persist the controller CLI session: %s", exc)

    def clear_cli_token() -> None:
        try:
            credentials.delete(CLI_CREDENTIAL_REFERENCE)
        except Exception:
            pass

    @staticmethod
    def request_token(request: Request) -> Optional[str]:
        authorization = request.headers.get("Authorization", "")
        if authorization.lower().startswith("bearer "):
            return authorization[7:].strip()
        return request.cookies.get(AUTH_COOKIE)

    def require_step_up(request: Request):
        if not app.state.enforce_auth:
            return None
        try:
            return get_auth().require_step_up(request_token(request) or "")
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @staticmethod
    def set_auth_cookie(response: Response, token: str, request: Request) -> None:
        response.set_cookie(
            AUTH_COOKIE,
            token,
            max_age=SESSION_LIFETIME_SECONDS,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            path="/",
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.perf_counter()
        scope_token = service.db.begin_scope(request_id) if hasattr(service.db, "begin_scope") else None
        try:
            public_auth_paths = {
                "/api/v1/health",
                "/api/v2/auth/status",
                "/api/v2/auth/setup",
                "/api/v2/auth/challenge",
                "/api/v2/auth/verify",
                "/api/v2/auth/pin/verify",
                "/api/v2/auth/recovery",
            }
            if (
                app.state.enforce_auth
                and request.method != "OPTIONS"
                and request.url.path not in public_auth_paths
                and not request.url.path.startswith(("/docs", "/openapi.json"))
            ):
                try:
                    request.state.operator_session = get_auth().authenticate(request_token(request))
                except AuthError as exc:
                    return JSONResponse(
                        status_code=exc.status_code,
                        content={
                            "error": {"code": exc.code, "message": exc.message, "details": {}},
                            "request_id": request_id,
                        },
                        headers={"X-Request-ID": request_id},
                    )
                finally:
                    # Authentication is complete before endpoint dispatch. Release
                    # its read transaction so long-lived SSE responses never pin a
                    # database connection for their entire lifetime.
                    service.db.remove()
            response = await call_next(request)
            elapsed_ms = (time.perf_counter() - started) * 1000
            response.headers["X-Request-ID"] = request_id
            response.headers["Server-Timing"] = f"app;dur={elapsed_ms:.2f}"
            logger.info("%s %s %s %.2fms request_id=%s", request.method, request.url.path, response.status_code, elapsed_ms, request_id)
            return response
        finally:
            if scope_token is not None:
                service.db.end_scope(scope_token)

    @app.exception_handler(ApiServiceError)
    async def api_error(request: Request, exc: ApiServiceError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}, "request_id": request.state.request_id},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        issues = [
            {key: value for key, value in issue.items() if key != "ctx"}
            for issue in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": "Request validation failed", "details": {"issues": issues}}, "request_id": request.state.request_id},
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        logger.exception("Unhandled API error request_id=%s", request.state.request_id)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "Internal server error", "details": {}}, "request_id": request.state.request_id},
        )

    @app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
    def health(api: WatchtowerApiService = Depends(get_service)):
        return api.health()

    @app.get("/api/v2/auth/status", tags=["authentication"])
    def auth_status(request: Request, response: Response, authentication: OperatorAuthService = Depends(get_auth)):
        supplied = request_token(request)
        token = supplied or shared_cli_token(authentication)
        if token and not supplied:
            set_auth_cookie(response, token, request)
        return authentication.status(token)

    @app.post("/api/v2/auth/setup", tags=["authentication"])
    def auth_setup(
        payload: AuthSetupRequest,
        request: Request,
        response: Response,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            if payload.mode == "disabled":
                return authentication.disable_first_run(request.state.request_id)
            result = authentication.setup_pin(
                payload.pin or "",
                payload.display_name,
                request_id=request.state.request_id,
            )
            token = result.pop("token")
            remember_cli_token(token)
            set_auth_cookie(response, token, request)
            return result
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/pin/verify", tags=["authentication"])
    def auth_pin_verify(
        payload: AuthPinRequest,
        request: Request,
        response: Response,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            result = authentication.verify_pin(
                payload.pin,
                payload.client_type,
                request.state.request_id,
            )
            token = result.pop("token")
            remember_cli_token(token)
            set_auth_cookie(response, token, request)
            return result
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/challenge", tags=["authentication"])
    def auth_challenge(
        payload: AuthChallengeRequest,
        request: Request,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        origin = request.headers.get("Origin") or str(request.base_url).rstrip("/")
        try:
            if payload.kind == "registration":
                return authentication.start_webauthn_registration(
                    request_token(request) or "",
                    origin,
                    payload.nickname,
                )
            return authentication.start_webauthn_authentication(origin)
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/verify", tags=["authentication"])
    def auth_verify(
        payload: AuthVerifyRequest,
        request: Request,
        response: Response,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            if payload.kind == "registration":
                return authentication.finish_webauthn_registration(
                    request_token(request) or "",
                    payload.challenge_id,
                    payload.credential,
                    payload.nickname,
                    request.state.request_id,
                )
            result = authentication.finish_webauthn_authentication(
                payload.challenge_id,
                payload.credential,
                payload.client_type,
                request.state.request_id,
            )
            token = result.pop("token")
            remember_cli_token(token)
            set_auth_cookie(response, token, request)
            return result
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/step-up", tags=["authentication"])
    def auth_step_up(
        payload: AuthPinRequest,
        request: Request,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            return authentication.step_up_pin(
                request_token(request) or "",
                payload.pin,
                request.state.request_id,
            )
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/lock", tags=["authentication"])
    def auth_lock(
        request: Request,
        response: Response,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        authentication.lock(request_token(request))
        clear_cli_token()
        response.delete_cookie(AUTH_COOKIE, path="/", samesite="strict")
        return {"status": "locked"}

    @app.get("/api/v2/auth/factors", tags=["authentication"])
    def auth_factors(authentication: OperatorAuthService = Depends(get_auth)):
        return authentication.factors()

    @app.post("/api/v2/auth/settings", tags=["authentication"])
    def auth_settings(
        payload: AuthSettingsRequest,
        request: Request,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            result = authentication.set_enabled(
                payload.enabled,
                request_token(request) or "",
                payload.pin,
                request.state.request_id,
            )
            if not payload.enabled:
                clear_cli_token()
            return result
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.post("/api/v2/auth/recovery", tags=["authentication"])
    def auth_recovery(
        payload: AuthRecoveryRequest,
        request: Request,
        response: Response,
        authentication: OperatorAuthService = Depends(get_auth),
    ):
        try:
            result = authentication.reset_with_recovery(
                payload.recovery_code,
                payload.new_pin,
                request_id=request.state.request_id,
            )
            token = result.pop("token")
            remember_cli_token(token)
            set_auth_cookie(response, token, request)
            return result
        except AuthError as exc:
            raise ApiServiceError(exc.status_code, exc.code, exc.message) from exc

    @app.get("/api/v1/capabilities", response_model=CapabilityResponse, tags=["system"])
    def capabilities(api: WatchtowerApiService = Depends(get_service)):
        return api.capabilities()

    @app.get("/api/v1/system", response_model=SystemInfo, tags=["system"])
    def system(api: WatchtowerApiService = Depends(get_service)):
        return api.system_info()

    @app.get("/api/v1/interfaces", response_model=list[CaptureDeviceDto], tags=["capture"])
    def interfaces(api: WatchtowerApiService = Depends(get_service)):
        return api.devices()

    @app.get("/api/v1/sessions", tags=["capture"])
    def sessions(interface: Optional[str] = None, limit: int = Query(100, ge=1, le=1000),
                 node: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.sessions(interface, limit, sensor_node_id=node)

    @app.get("/api/v1/stats", tags=["traffic"])
    def stats(source: str = "live", interface: Optional[str] = None, node: Optional[str] = None,
              api: WatchtowerApiService = Depends(get_service)):
        return api.stats(source, interface, node)

    @app.get("/api/v1/flows", response_model=list[FlowDto], tags=["traffic"])
    def flows(
        source: Optional[str] = "live",
        interface: Optional[str] = None,
        session: Optional[str] = None,
        entity: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = Query(None, ge=0, le=65535),
        limit: int = Query(250, ge=1, le=5000),
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.flows(source, interface, session, entity, protocol, port, limit, sensor_node_id=node)

    @app.get("/api/v1/alerts", response_model=list[AlertDto], tags=["detections"])
    def alerts(
        source: Optional[str] = "live",
        interface: Optional[str] = None,
        session: Optional[str] = None,
        entity: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = Query(250, ge=1, le=5000),
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.alerts(source, interface, session, entity, severity, limit, sensor_node_id=node)

    @app.get("/api/v2/findings", tags=["scoring-v2"])
    def findings_v2(
        subject: Optional[str] = None, source: Optional[str] = None,
        interface: Optional[str] = None, session: Optional[str] = None,
        finding_type: Optional[str] = None, include_suppressed: bool = False,
        limit: int = Query(100, ge=1, le=500), cursor: Optional[str] = None,
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.finding_page(
            subject, source, interface, session, finding_type,
            include_suppressed, limit, cursor, node,
        )

    @app.get("/api/v2/flows", tags=["traffic-v2"])
    def flows_v2(
        source: Optional[str] = "live", interface: Optional[str] = None,
        session: Optional[str] = None, entity: Optional[str] = None,
        protocol: Optional[str] = None, port: Optional[int] = Query(None, ge=0, le=65535),
        limit: int = Query(100, ge=1, le=500), cursor: Optional[str] = None,
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.flow_page(source, interface, session, entity, protocol, port, limit, cursor, node)

    @app.get("/api/v2/alerts", tags=["detections-v2"])
    def alerts_v2(
        source: Optional[str] = "live", interface: Optional[str] = None,
        session: Optional[str] = None, entity: Optional[str] = None,
        severity: Optional[str] = None, limit: int = Query(100, ge=1, le=500),
        cursor: Optional[str] = None, node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.alert_page(source, interface, session, entity, severity, limit, cursor, node)

    @app.get("/api/v2/topology", tags=["traffic-v2"])
    def topology_v2(
        source: Optional[str] = "live", interface: Optional[str] = None,
        session: Optional[str] = None, limit: int = Query(100, ge=1, le=500),
        cursor: Optional[str] = None, node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.topology_page(source, interface, session, limit, cursor, node)

    @app.get("/api/v2/risk/entities/{ip}", tags=["scoring-v2"])
    def risk_v2(ip: str, source: Optional[str] = None, interface: Optional[str] = None,
                session: Optional[str] = None, node: Optional[str] = None,
                api: WatchtowerApiService = Depends(get_service)):
        return api.scoring_risk(ip, source, interface, session, explain=False, sensor_node_id=node)

    @app.get("/api/v2/risk/entities", tags=["scoring-v2"])
    def risk_entities_v2(
        source: Optional[str] = None, interface: Optional[str] = None,
        session: Optional[str] = None, limit: int = Query(100, ge=1, le=500),
        cursor: Optional[str] = None, node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.scoring_entities(source, interface, session, limit, cursor, node)

    @app.get("/api/v2/dashboard/summary", tags=["dashboard-v2"])
    def dashboard_summary_v2(
        source: str = "live", interface: Optional[str] = None,
        session: Optional[str] = None, node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.dashboard_summary(source, interface, session, node)

    @app.get("/api/v2/flows/{flow_id}", tags=["traffic-v2"])
    def flow_detail_v2(flow_id: int, api: WatchtowerApiService = Depends(get_service)):
        return api.flow_detail(flow_id)

    @app.get("/api/v2/findings/{finding_id}", tags=["scoring-v2"])
    def finding_detail_v2(finding_id: int, api: WatchtowerApiService = Depends(get_service)):
        return api.finding_detail(finding_id)

    @app.get("/api/v2/risk/entities/{ip}/explain", tags=["scoring-v2"])
    def explain_risk_v2(ip: str, source: Optional[str] = None, interface: Optional[str] = None,
                        session: Optional[str] = None, node: Optional[str] = None,
                        api: WatchtowerApiService = Depends(get_service)):
        return api.scoring_risk(ip, source, interface, session, explain=True, sensor_node_id=node)

    @app.get("/api/v2/scoring/status", tags=["scoring-v2"])
    def scoring_status_v2(api: WatchtowerApiService = Depends(get_service)):
        return api.scoring_status()

    @app.post("/api/v2/findings/{finding_id}/disposition", tags=["scoring-v2"])
    def disposition_v2(finding_id: int, payload: FindingDispositionRequest,
                       api: WatchtowerApiService = Depends(get_service)):
        return api.scoring_disposition(finding_id, payload.verdict, payload.reason, payload.actor, payload.scope)

    @app.post("/api/v2/scoring/recompute", tags=["scoring-v2"])
    def recompute_v2(payload: ScoringRecomputeRequest,
                     api: WatchtowerApiService = Depends(get_service)):
        return api.scoring_recompute(
            payload.source, payload.interface, payload.session, payload.as_of, payload.dry_run, payload.node,
        )

    @app.get("/api/v2/ai/status", tags=["ai"])
    def ai_status(api: WatchtowerApiService = Depends(get_service)):
        return api.ai_status()

    @app.get("/api/v2/ai/providers", tags=["ai"])
    def ai_providers(api: WatchtowerApiService = Depends(get_service)):
        return {"providers": api.ai_status()["providers"]}

    @app.post("/api/v2/ai/providers/{provider}/connect", tags=["ai"])
    def ai_provider_connect(provider: str, payload: AIProviderConnectRequest,
                            _auth=Depends(require_step_up),
                            api: WatchtowerApiService = Depends(get_service)):
        return api.ai_provider_connect(provider, payload.secret, payload.model, payload.base_url)

    @app.post("/api/v2/ai/providers/{provider}/test", tags=["ai"])
    def ai_provider_test(provider: str, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_provider_test(provider)

    @app.delete("/api/v2/ai/providers/{provider}", tags=["ai"])
    def ai_provider_disconnect(provider: str, _auth=Depends(require_step_up),
                               api: WatchtowerApiService = Depends(get_service)):
        return api.ai_provider_disconnect(provider)

    @app.get("/api/v2/ai/providers/{provider}/models", tags=["ai"])
    def ai_provider_models(provider: str, refresh: bool = False,
                           api: WatchtowerApiService = Depends(get_service)):
        return api.ai_provider_models(provider, refresh)

    @app.post("/api/v2/ai/providers/{provider}/model", tags=["ai"])
    def ai_provider_model(provider: str, payload: AIProviderModelRequest,
                          api: WatchtowerApiService = Depends(get_service)):
        return api.ai_provider_set_model(provider, payload.model)

    @app.get("/api/v2/ai/research/sources", tags=["ai"])
    def ai_research_sources(api: WatchtowerApiService = Depends(get_service)):
        return {"sources": api.ai_status()["research_sources"]}

    @app.get("/api/v2/ai/conversations", tags=["ai"])
    def ai_conversations(limit: int = Query(100, ge=1, le=100), api: WatchtowerApiService = Depends(get_service)):
        return api.ai_conversations(limit)

    @app.post("/api/v2/ai/conversations", status_code=201, tags=["ai"])
    def create_ai_conversation(payload: AIConversationRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_create_conversation(payload.title, payload.provider, payload.scope.model_dump())

    @app.get("/api/v2/ai/conversations/{conversation_id}", tags=["ai"])
    def ai_conversation(conversation_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_conversation(conversation_id)

    @app.delete("/api/v2/ai/conversations/{conversation_id}", tags=["ai"])
    def delete_ai_conversation(conversation_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_delete_conversation(conversation_id)

    @app.post("/api/v2/ai/runs", status_code=202, tags=["ai"])
    def start_ai_run(payload: AIRunRequest, request: Request,
                     api: WatchtowerApiService = Depends(get_service)):
        operator_session = getattr(request.state, "operator_session", None)
        return api.ai_start_run(
            payload.prompt,
            payload.conversation_id,
            payload.provider,
            payload.scope.model_dump(),
            payload.research_mode,
            getattr(operator_session, "id", None),
            payload.mode,
        )

    @app.get("/api/v2/ai/runs/{run_id}", tags=["ai"])
    def ai_run(run_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_run(run_id)

    @app.get("/api/v2/ai/runs/{run_id}/events", tags=["ai"])
    def ai_events(run_id: str, after: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        def event_stream():
            cursor = after
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                for event in api.ai_events(run_id, cursor):
                    cursor = int(event["sequence"])
                    yield f"event: {event['kind']}\ndata: {json.dumps(event, separators=(',', ':'), default=str)}\n\n"
                current = api.ai_run(run_id)
                if str(current.get("status")).upper() in {"COMPLETE", "DEGRADED", "NEEDS_SCOPE", "FAILED", "REJECTED"}:
                    yield f"event: terminal\ndata: {json.dumps({'status': current.get('status')})}\n\n"
                    return
                time.sleep(0.5)
        return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    @app.post("/api/v2/ai/approvals/{approval_id}/confirm", tags=["ai"])
    def confirm_ai_approval(approval_id: str, payload: AIApprovalRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_approve(approval_id, payload.confirmation)

    @app.post("/api/v2/ai/approvals/{approval_id}/reject", tags=["ai"])
    def reject_ai_approval(approval_id: str, payload: AIApprovalRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.ai_reject(approval_id, payload.reason)

    @app.post("/api/v2/ai/credentials", tags=["ai"])
    def set_ai_credential(payload: AICredentialRequest, _auth=Depends(require_step_up),
                          api: WatchtowerApiService = Depends(get_service)):
        return api.ai_set_credential(payload.reference, payload.secret)

    @app.delete("/api/v2/ai/credentials/{reference}", tags=["ai"])
    def delete_ai_credential(reference: str, _auth=Depends(require_step_up),
                             api: WatchtowerApiService = Depends(get_service)):
        return api.ai_delete_credential(reference)

    @app.get("/api/v1/entities", response_model=list[EntityDto], tags=["investigation"])
    def entities(
        source: Optional[str] = "live",
        search: Optional[str] = None,
        limit: int = Query(500, ge=1, le=10000),
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.entities(source, search, limit, node)

    @app.get("/api/v1/entities/{ip}/investigation", tags=["investigation"])
    def investigate(ip: str, source: Optional[str] = None, node: Optional[str] = None,
                    api: WatchtowerApiService = Depends(get_service)):
        return api.investigate(ip, source, node)

    @app.get("/api/v1/lookup/{ip}", tags=["investigation"])
    def lookup(ip: str, source: Optional[str] = None, node: Optional[str] = None,
               api: WatchtowerApiService = Depends(get_service)):
        return api.lookup(ip, source, node)

    @app.get("/api/v1/enrichment/status", tags=["investigation"])
    def enrichment_status(source: Optional[str] = None, interface: Optional[str] = None,
                          session: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.enrichment_status(source, interface, session)

    @app.post("/api/v1/enrichment/rebuild", tags=["investigation"])
    def enrichment_rebuild(payload: EnrichmentRebuildRequest,
                           api: WatchtowerApiService = Depends(get_service)):
        return api.rebuild_enrichment(payload.source, payload.interface, payload.session, payload.dry_run)

    @app.get("/api/v1/identities", tags=["investigation"])
    def endpoint_identities(source: Optional[str] = None, interface: Optional[str] = None,
                            session: Optional[str] = None, limit: int = Query(1000, ge=1, le=5000),
                            api: WatchtowerApiService = Depends(get_service)):
        return api.endpoint_identities(source, interface, session, limit)

    @app.get("/api/v1/identities/status", tags=["investigation"])
    def identity_status(source: Optional[str] = None, interface: Optional[str] = None,
                        session: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.identity_status(source, interface, session)

    @app.get("/api/v2/identities/status", tags=["identity-v2"])
    def identity_status_v2(source: Optional[str] = None, interface: Optional[str] = None,
                           session: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.identity_status(source, interface, session)

    @app.get("/api/v2/identities/unconfirmed", tags=["identity-v2"])
    def identity_unconfirmed(source: Optional[str] = None, interface: Optional[str] = None,
                             session: Optional[str] = None, limit: int = Query(500, ge=1, le=1000),
                             api: WatchtowerApiService = Depends(get_service)):
        return {"items": api.identity_unconfirmed(source, interface, session, limit), "limit": limit}

    @app.get("/api/v2/identities/{ip}/explain", tags=["identity-v2"])
    def identity_explain_v2(ip: str, source: Optional[str] = None, interface: Optional[str] = None,
                            session: Optional[str] = None, node: Optional[str] = None,
                            api: WatchtowerApiService = Depends(get_service)):
        return api.identity_explain(ip, source, interface, session, node)

    @app.post("/api/v2/identities/confirm", tags=["identity-v2"])
    def identity_confirm(payload: IdentityConfirmRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.identity_confirm(payload.ips, payload.source, payload.interface, payload.session, payload.dry_run)

    @app.post("/api/v2/identities/enrich", tags=["identity-v2"])
    def identity_enrich(payload: IdentityEnrichRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.identity_enrich(payload.ips, payload.source, payload.session)

    @app.get("/api/v2/endpoint/sysmon/status", tags=["endpoint"])
    def endpoint_sysmon_status(sensor_node_id: Optional[str] = None,
                               api: WatchtowerApiService = Depends(get_service)):
        return api.endpoint_telemetry_status(sensor_node_id)

    @app.get("/api/v2/endpoint/processes", tags=["endpoint"])
    def endpoint_processes(ip: Optional[str] = None, sensor_node_id: Optional[str] = None,
                           limit: int = Query(100, ge=1, le=500),
                           api: WatchtowerApiService = Depends(get_service)):
        return api.endpoint_processes(ip, sensor_node_id, limit)

    @app.get("/api/v2/mesh/status", tags=["mesh"])
    def mesh_status(api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_status()

    @app.post("/api/v2/mesh/controller/init", tags=["mesh"])
    def mesh_initialize(host: str = "127.0.0.1", _auth=Depends(require_step_up),
                        api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_initialize(host)

    @app.post("/api/v2/mesh/controller/setup", tags=["mesh"])
    def mesh_setup(payload: MeshControllerSetupRequest, _auth=Depends(require_step_up),
                   api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_setup(
            payload.mode, payload.address, payload.enrollment_port, payload.ingest_port,
            payload.acknowledge_public_risk,
        )

    @app.post("/api/v2/mesh/controller/start", tags=["mesh"])
    def mesh_start(api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_lifecycle("start")

    @app.post("/api/v2/mesh/controller/stop", tags=["mesh"])
    def mesh_stop(api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_lifecycle("stop")

    @app.post("/api/v2/mesh/controller/restart", tags=["mesh"])
    def mesh_restart(api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_lifecycle("restart")

    @app.post("/api/v2/mesh/controller/rotate-certificate", tags=["mesh"])
    def mesh_rotate_certificate(_auth=Depends(require_step_up),
                                api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_rotate_certificate()

    @app.get("/api/v2/mesh/nodes", tags=["mesh"])
    def mesh_nodes(limit: int = Query(100, ge=1, le=500), api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_nodes(limit)

    @app.get("/api/v2/fleet/summary", tags=["fleet"])
    def fleet_summary(api: WatchtowerApiService = Depends(get_service)):
        return api.fleet_summary()

    @app.post("/api/v2/mesh/enrollments", tags=["mesh"])
    def mesh_enrollment(payload: MeshEnrollmentRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_enrollment(payload.name, payload.ttl_seconds, payload.max_uses)

    @app.post("/api/v2/mesh/nodes/{node_id}/revoke", tags=["mesh"])
    def mesh_revoke(node_id: str, payload: MeshRevokeRequest, _auth=Depends(require_step_up),
                    api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_revoke(node_id, payload.reason)

    @app.delete("/api/v2/mesh/nodes/{node_id}", tags=["mesh"])
    def mesh_remove(node_id: str, reason: str = Query(..., min_length=1, max_length=1000),
                    _auth=Depends(require_step_up), api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_revoke(node_id, reason)

    @app.post("/api/v2/mesh/nodes/{node_id}/commands", tags=["mesh"])
    def mesh_command(node_id: str, payload: MeshCommandRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.mesh_command(node_id, payload.action, payload.arguments, payload.ttl_seconds)

    @app.get("/api/v2/graph/status", tags=["evidence-graph"])
    def graph_status(api: WatchtowerApiService = Depends(get_service)):
        return api.graph_status()

    @app.post("/api/v2/graph/materialize", tags=["evidence-graph"])
    def graph_materialize(limit: int = Query(250, ge=1, le=1000), api: WatchtowerApiService = Depends(get_service)):
        return api.graph_materialize(limit)

    @app.get("/api/v2/graph/neighborhood/{ip}", tags=["evidence-graph"])
    def graph_neighborhood(ip: str, node: Optional[str] = None, depth: int = Query(2, ge=1, le=3),
                           limit: int = Query(100, ge=1, le=250), api: WatchtowerApiService = Depends(get_service)):
        return api.graph_neighborhood(ip, node, depth, limit)

    @app.get("/api/v2/graph/path", tags=["evidence-graph"])
    def graph_path(source_ip: str, target_ip: str, node: Optional[str] = None,
                   api: WatchtowerApiService = Depends(get_service)):
        return api.graph_path(source_ip, target_ip, node)

    @app.get("/api/v2/graph/timeline/{ip}", tags=["evidence-graph"])
    def graph_timeline(ip: str, node: Optional[str] = None, start: Optional[float] = None, end: Optional[float] = None,
                       limit: int = Query(200, ge=1, le=500), api: WatchtowerApiService = Depends(get_service)):
        return api.graph_timeline(ip, node, start, end, limit)

    @app.post("/api/v1/identities/rebuild", tags=["investigation"])
    def identity_rebuild(payload: IdentityRebuildRequest,
                         api: WatchtowerApiService = Depends(get_service)):
        return api.rebuild_identities(payload.source, payload.interface, payload.session, payload.dry_run)

    @app.get("/api/v1/evidence", tags=["investigation"])
    def evidence(source: Optional[str] = "live", entity: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.evidence(source, entity)

    @app.get("/api/v1/topology", tags=["traffic"])
    def topology(
        source: Optional[str] = "live",
        interface: Optional[str] = None,
        session: Optional[str] = None,
        node: Optional[str] = None,
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.topology(source, interface, session, node)

    @app.post("/api/v1/capture/start", tags=["capture"])
    def start_capture(payload: CaptureActionRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.start_capture(payload.interface, payload.backend, payload.source_type)

    @app.post("/api/v1/capture/stop", tags=["capture"])
    def stop_capture(payload: StopCaptureRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.stop_capture(payload.interface)

    @app.get("/api/v2/pipeline/health", tags=["capture-v2"])
    def pipeline_health_v2(api: WatchtowerApiService = Depends(get_service)):
        return api.pipeline_health()

    @app.get("/api/v2/captures/{session_id}", tags=["capture-v2"])
    def capture_session_v2(session_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.capture_session(session_id)

    @app.post("/api/v2/captures/{session_id}/stop", status_code=202, tags=["capture-v2"])
    def stop_capture_session_v2(session_id: str, payload: StopCaptureSessionRequest,
                                api: WatchtowerApiService = Depends(get_service)):
        return api.request_capture_stop(session_id, payload.reason)

    @app.post("/api/v1/hunts/sigma", tags=["detections"])
    def hunt(payload: HuntRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.run_hunt(payload.source, payload.interface, payload.rule, payload.persist)

    @app.get("/api/v1/plugins", tags=["plugins"])
    def plugins(api: WatchtowerApiService = Depends(get_service)):
        return api.plugin_inventory()

    @app.get("/api/v1/plugins/calibration/status", tags=["plugins"])
    def plugin_calibration_status(detector_id: Optional[str] = None, api: WatchtowerApiService = Depends(get_service)):
        return api.plugin_calibration_status(detector_id)

    @app.post("/api/v1/plugins/calibration/run", tags=["plugins"])
    def plugin_calibration_run(payload: CalibrationRunRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.plugin_calibration_run(payload.detector_id, payload.finding_type, payload.backend)

    @app.post("/api/v1/plugins/calibration/promote", tags=["plugins"])
    def plugin_calibration_promote(payload: CalibrationPromoteRequest, _auth=Depends(require_step_up),
                                   api: WatchtowerApiService = Depends(get_service)):
        return api.plugin_calibration_promote(payload.report_path, payload.reviewer, payload.reason)

    @app.post("/api/v1/plugins/calibration/verify", tags=["plugins"])
    def plugin_calibration_verify(api: WatchtowerApiService = Depends(get_service)):
        return api.plugin_calibration_verify()

    @app.get("/api/v1/sigma/rules", tags=["sigma"])
    @app.get("/api/v2/sigma/rules", tags=["sigma"])
    def sigma_rules(api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_rules()

    @app.get("/api/v1/sigma/status", tags=["sigma"])
    @app.get("/api/v2/sigma/status", tags=["sigma"])
    def sigma_status(api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_status()

    @app.post("/api/v1/sigma/preview", tags=["sigma"])
    @app.post("/api/v2/sigma/preview", tags=["sigma"])
    def sigma_preview(payload: SigmaRemoteRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_preview(payload.url)

    @app.post("/api/v1/sigma/install", tags=["sigma"])
    @app.post("/api/v2/sigma/install", tags=["sigma"])
    def sigma_install(payload: SigmaRemoteRequest, api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_install(payload.url, payload.expected_sha256 or "")

    @app.post("/api/v1/sigma/sync", tags=["sigma"])
    @app.post("/api/v2/sigma/sync", tags=["sigma"])
    def sigma_sync(api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_sync()

    @app.post("/api/v1/sigma/rollback", tags=["sigma"])
    @app.post("/api/v2/sigma/rollback", tags=["sigma"])
    def sigma_rollback(api: WatchtowerApiService = Depends(get_service)):
        return api.sigma_rollback()

    @app.get("/api/v2/pcap/analyses", tags=["forensics-v2"])
    def pcap_analyses(limit: int = Query(50, ge=1, le=250),
                      api: WatchtowerApiService = Depends(get_service)):
        return {"items": api.pcap_jobs(limit)}

    @app.get("/api/v2/pcap/cases", tags=["forensics-v2"])
    def pcap_cases(limit: int = Query(100, ge=1, le=500),
                   api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_cases(limit)

    @app.get("/api/v2/pcap/cases/{case_id}", tags=["forensics-v2"])
    def pcap_case(case_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_case(case_id)

    @app.get("/api/v2/pcap/cases/{case_id}/custody", tags=["forensics-v2"])
    def pcap_case_custody(case_id: str, limit: int = Query(250, ge=1, le=1000),
                          api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_case_custody(case_id, limit)

    @app.get("/api/v2/pcap/cases/{case_id}/flags", tags=["forensics-v2"])
    def pcap_case_flags(case_id: str, status: Optional[str] = Query(None),
                        limit: int = Query(100, ge=1, le=500),
                        api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_case_flags(case_id, status, limit)

    @app.post("/api/v2/pcap/cases/{case_id}/flags", status_code=201, tags=["forensics-v2"])
    def create_pcap_case_flag(case_id: str, payload: Dict[str, Any],
                              api: WatchtowerApiService = Depends(get_service)):
        return api.create_pcap_case_flag(case_id, payload)

    @app.get("/api/v2/pcap/analyses/{job_id}", tags=["forensics-v2"])
    def pcap_analysis(job_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_analysis(job_id)

    @app.get("/api/v2/pcap/analyses/{job_id}/events", tags=["forensics-v2"])
    def pcap_analysis_events(job_id: str, api: WatchtowerApiService = Depends(get_service)):
        def event_stream():
            prior = None
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                current = api.pcap_progress(job_id)
                marker = (
                    current.get("status"),
                    current.get("bytes_processed"),
                    current.get("progress"),
                    current.get("error"),
                )
                if marker != prior:
                    yield f"event: progress\ndata: {json.dumps(current, separators=(',', ':'), default=str)}\n\n"
                    prior = marker
                if str(current.get("status") or "").lower() in {"complete", "partial", "cancelled", "failed"}:
                    yield f"event: terminal\ndata: {json.dumps({'status': current.get('status')})}\n\n"
                    return
                time.sleep(0.35)
        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/v2/pcap/analyses", status_code=202, tags=["forensics-v2"])
    async def submit_pcap_v2(
        file: UploadFile = File(...),
        mode: str = Form("auto"),
        backend: Optional[str] = Form(None),
        keylog: Optional[UploadFile] = File(default=None),
        api: WatchtowerApiService = Depends(get_service),
    ):
        filename = Path(file.filename or "capture.pcap").name
        suffix = Path(filename).suffix.lower()
        if suffix not in {".pcap", ".pcapng", ".cap"}:
            raise ApiServiceError(422, "invalid_pcap", "Upload a .pcap, .pcapng, or .cap file")
        upload_dir = Path(context.temp_dir) / "api-pcap"
        upload_dir.mkdir(parents=True, exist_ok=True)
        path = upload_dir / f"{uuid.uuid4().hex}{suffix}"
        keylog_path = None
        written = 0
        reserve = 256 * 1024 * 1024
        try:
            with path.open("wb") as destination:
                while chunk := await file.read(1024 * 1024):
                    if shutil.disk_usage(upload_dir).free - len(chunk) < reserve:
                        raise ApiServiceError(507, "insufficient_storage", "Not enough free disk space for this PCAP")
                    destination.write(chunk)
                    written += len(chunk)
            if written < 4:
                raise ApiServiceError(422, "invalid_pcap", "The uploaded PCAP is empty or truncated")
            with path.open("rb") as uploaded:
                magic = uploaded.read(4)
            if magic not in {
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
            }:
                raise ApiServiceError(422, "invalid_pcap", "The file header is not a supported PCAP or PCAPNG format")
            if keylog is not None:
                raw_keylog = await keylog.read(16 * 1024 * 1024 + 1)
                if len(raw_keylog) > 16 * 1024 * 1024 or b"\x00" in raw_keylog:
                    raise ApiServiceError(422, "invalid_tls_keylog", "TLS keylog must be a text file no larger than 16 MiB")
                text_keylog = raw_keylog.decode("ascii", errors="strict")
                valid_lines = [
                    line for line in text_keylog.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                ]
                if valid_lines and not all(len(line.split()) >= 3 for line in valid_lines):
                    raise ApiServiceError(422, "invalid_tls_keylog", "TLS keylog contains malformed entries")
                keylog_path = upload_dir / f"{uuid.uuid4().hex}.keylog"
                keylog_path.write_bytes(raw_keylog)
            if keylog_path:
                return api.jobs.submit(
                    str(path), filename, mode, backend, keylog_path=str(keylog_path),
                )
            return api.jobs.submit(str(path), filename, mode, backend)
        except UnicodeDecodeError as exc:
            raise ApiServiceError(422, "invalid_tls_keylog", "TLS keylog must contain ASCII text") from exc
        except Exception:
            for temporary in (path, keylog_path):
                if temporary:
                    try:
                        os.remove(temporary)
                    except FileNotFoundError:
                        pass
            raise
        finally:
            await file.close()
            if keylog is not None:
                await keylog.close()

    @app.post("/api/v2/pcap/analyses/{job_id}/cancel", tags=["forensics-v2"])
    def cancel_pcap_v2(job_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.cancel_pcap(job_id)

    def pcap_projection(job_id: str, kind: str, limit: int, cursor: str,
                        api: WatchtowerApiService):
        return api.pcap_analysis_page(job_id, kind, limit, cursor)

    @app.get("/api/v2/pcap/analyses/{job_id}/flows", tags=["forensics-v2"])
    def pcap_flows(job_id: str, limit: int = Query(100, ge=1, le=500),
                   cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "flows", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/entities", tags=["forensics-v2"])
    def pcap_entities(job_id: str, limit: int = Query(100, ge=1, le=500),
                      cursor: Optional[str] = Query(None), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "entities", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/findings", tags=["forensics-v2"])
    def pcap_findings(job_id: str, limit: int = Query(100, ge=1, le=500),
                      cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "findings", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/alerts", tags=["forensics-v2"])
    def pcap_alerts(job_id: str, limit: int = Query(100, ge=1, le=500),
                    cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "alerts", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/artifacts", tags=["forensics-v2"])
    def pcap_artifacts(job_id: str, limit: int = Query(100, ge=1, le=500),
                       cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "artifacts", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/streams", tags=["forensics-v2"])
    def pcap_streams(job_id: str, limit: int = Query(100, ge=1, le=500),
                     cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "streams", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/evidence", tags=["forensics-v2"])
    def pcap_evidence(job_id: str, limit: int = Query(100, ge=1, le=500),
                      cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return pcap_projection(job_id, "evidence", limit, cursor, api)

    @app.get("/api/v2/pcap/analyses/{job_id}/topology", tags=["forensics-v2"])
    def pcap_topology(job_id: str, limit: int = Query(250, ge=1, le=5000),
                      cursor: int = Query(0, ge=0), mode: str = Query("analyst"),
                      api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_topology(job_id, limit, cursor, mode)

    @app.get("/api/v2/pcap/analyses/{job_id}/timeline", tags=["forensics-v2"])
    def pcap_timeline(job_id: str, limit: int = Query(2000, ge=1, le=5000),
                      cursor: int = Query(0, ge=0), api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_timeline(job_id, limit, cursor)

    @app.get(
        "/api/v2/pcap/analyses/{job_id}/deep-dissection",
        tags=["forensics-v2"],
    )
    def pcap_deep_dissection(
        job_id: str,
        limit: int = Query(100, ge=1, le=1000),
        cursor: int = Query(0, ge=0),
        api: WatchtowerApiService = Depends(get_service),
    ):
        return api.pcap_deep_dissection(job_id, limit, cursor)

    @app.get("/api/v1/pcap/jobs", tags=["forensics"])
    def pcap_jobs(limit: int = Query(50, ge=1, le=250), api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_jobs(limit)

    @app.get("/api/v1/pcap/jobs/{job_id}", tags=["forensics"])
    def pcap_job(job_id: str, include_results: bool = True, api: WatchtowerApiService = Depends(get_service)):
        return api.pcap_job(job_id, include_results)

    @app.post("/api/v1/pcap/jobs", status_code=202, tags=["forensics"])
    async def submit_pcap(
        file: UploadFile = File(...),
        mode: str = Form("auto"),
        backend: Optional[str] = Form(None),
        api: WatchtowerApiService = Depends(get_service),
    ):
        filename = Path(file.filename or "capture.pcap").name
        suffix = Path(filename).suffix.lower()
        if suffix not in {".pcap", ".pcapng", ".cap"}:
            raise ApiServiceError(422, "invalid_pcap", "Upload a .pcap, .pcapng, or .cap file")
        upload_dir = Path(context.temp_dir) / "api-pcap"
        upload_dir.mkdir(parents=True, exist_ok=True)
        path = upload_dir / f"{uuid.uuid4().hex}{suffix}"
        written = 0
        reserve = 256 * 1024 * 1024
        try:
            with path.open("wb") as destination:
                while chunk := await file.read(1024 * 1024):
                    if shutil.disk_usage(upload_dir).free - len(chunk) < reserve:
                        raise ApiServiceError(507, "insufficient_storage", "Not enough free disk space for this PCAP")
                    destination.write(chunk)
                    written += len(chunk)
            if written < 4:
                raise ApiServiceError(422, "invalid_pcap", "The uploaded PCAP is empty or truncated")
            with path.open("rb") as uploaded:
                magic = uploaded.read(4)
            valid_magic = {
                b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
            }
            if magic not in valid_magic:
                raise ApiServiceError(422, "invalid_pcap", "The file header is not a supported PCAP or PCAPNG format")
            return api.submit_pcap(str(path), filename, mode, backend)
        except Exception:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            raise
        finally:
            await file.close()

    @app.post("/api/v1/pcap/jobs/{job_id}/cancel", tags=["forensics"])
    def cancel_pcap(job_id: str, api: WatchtowerApiService = Depends(get_service)):
        return api.cancel_pcap(job_id)

    @app.get("/api/v1/forensics/reports", tags=["forensics"])
    def forensic_reports(api: WatchtowerApiService = Depends(get_service)):
        return api.forensic_reports()

    @app.post("/api/v1/database/reset", tags=["system"])
    def reset_database(payload: ResetRequest, _auth=Depends(require_step_up),
                       api: WatchtowerApiService = Depends(get_service)):
        return api.reset_database(payload.confirmation, mode="operational")

    @app.post("/api/v2/operations/reset", tags=["system-v2"])
    def reset_database_v2(payload: ResetRequest, _auth=Depends(require_step_up),
                          api: WatchtowerApiService = Depends(get_service)):
        return api.reset_database(payload.confirmation, mode=payload.mode)

    return app


app = create_app()


def main():
    import uvicorn

    uvicorn.run("core.api.server:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()

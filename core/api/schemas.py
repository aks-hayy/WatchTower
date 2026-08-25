"""Stable public DTOs exposed by the local WatchTower API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.backend_policy import backend_policy


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class HealthResponse(ApiModel):
    status: str
    version: str
    database: str
    daemon: str
    daemon_healthy: bool = False


class CapabilityResponse(ApiModel):
    api_version: str = "v1"
    ai_mode: str = "local-agentic"
    ai_provider_ready: bool = False
    capture_backends: List[str]
    capture_sources: List[str]
    features: Dict[str, bool]


class SystemInfo(ApiModel):
    hostname: str
    platform: str
    uptime: float
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    is_admin: bool
    capture_capable: bool
    version: str


class CaptureDeviceDto(ApiModel):
    source_type: str
    device_id: str
    name: str
    description: str = ""
    addresses: List[str] = Field(default_factory=list)
    mac: Optional[str] = None
    backends: List[str] = Field(default_factory=list)
    available: bool = True
    unavailable_reason: str = ""
    capturing: bool = False
    engine: Optional[Dict[str, Any]] = None


class EndpointIdentitySummaryDto(ApiModel):
    entity_ip: str
    identity_type: str
    identity_label: str
    confidence: float
    verification: str
    identity_state: Optional[str] = None
    evidence_completeness: Optional[float] = None
    next_action: Optional[str] = None
    observation_count: Optional[int] = None
    model_version: str
    updated_at: Optional[float] = None


class FlowDto(ApiModel):
    id: int
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str
    start_time: float = 0
    last_seen: float = 0
    packet_count: int = 0
    byte_count: int = 0
    duration: float = 0
    source: str
    capture_session_id: Optional[str] = None
    capture_interface: Optional[str] = None
    capture_backend: Optional[str] = None
    capture_type: str = "network"
    sensor_node_id: Optional[str] = None
    l7_metadata: Dict[str, Any] = Field(default_factory=dict)
    src_identity: Optional[EndpointIdentitySummaryDto] = None
    dst_identity: Optional[EndpointIdentitySummaryDto] = None


class AlertDto(ApiModel):
    id: int
    entity_ip: str
    type: str
    severity: str
    score: float = 0
    explanation: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = 0
    source: str
    capture_session_id: Optional[str] = None
    capture_interface: Optional[str] = None
    capture_backend: Optional[str] = None
    capture_type: str = "network"
    sensor_node_id: Optional[str] = None
    ai_verdict: Optional[str] = None
    occurrence_count: int = 1


class EntityDto(ApiModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    os: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    asset_role: Optional[str] = None
    risk_score: float = 0
    confidence_score: float = 0
    identity_source: Optional[str] = None
    alert_count: int = 0
    carved_file_count: int = 0
    flow_count: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    source: str = "live"


class CaptureActionRequest(ApiModel):
    interface: str = Field(min_length=1, max_length=256)
    backend: Optional[str] = None
    source_type: str = "network"

    @model_validator(mode="after")
    def select_backend(self):
        self.backend = backend_policy.capture_backend(
            source_type=self.source_type,
            requested_backend=self.backend,
        )
        return self


class StopCaptureRequest(ApiModel):
    interface: str = Field(min_length=1, max_length=256)


class StopCaptureSessionRequest(ApiModel):
    reason: str = Field(default="operator_stop", min_length=1, max_length=128)


class HuntRequest(ApiModel):
    source: Optional[str] = None
    interface: Optional[str] = None
    rule: Optional[str] = None
    persist: bool = True


class ResetRequest(ApiModel):
    confirmation: str
    mode: str = "operational"


class SigmaRemoteRequest(ApiModel):
    url: str = Field(min_length=8, max_length=2048)
    expected_sha256: Optional[str] = Field(default=None, min_length=64, max_length=64)


class FindingDispositionRequest(ApiModel):
    verdict: str
    reason: str = ""
    actor: str = "local-analyst"
    scope: str = "finding"


class ScoringRecomputeRequest(ApiModel):
    source: Optional[str] = None
    interface: Optional[str] = None
    session: Optional[str] = None
    node: Optional[str] = None
    as_of: Optional[float] = None
    dry_run: bool = False


class EnrichmentRebuildRequest(ApiModel):
    source: Optional[str] = None
    interface: Optional[str] = None
    session: Optional[str] = None
    dry_run: bool = False


class IdentityRebuildRequest(ApiModel):
    source: Optional[str] = None
    interface: Optional[str] = None
    session: Optional[str] = None
    dry_run: bool = False


class IdentityConfirmRequest(ApiModel):
    ips: List[str] = Field(default_factory=list, max_length=100)
    source: Optional[str] = None
    interface: Optional[str] = None
    session: Optional[str] = None
    dry_run: bool = False


class IdentityEnrichRequest(ApiModel):
    ips: List[str] = Field(default_factory=list, max_length=100)
    source: Optional[str] = None
    session: Optional[str] = None


class CalibrationRunRequest(ApiModel):
    detector_id: str = Field(min_length=3, max_length=128)
    finding_type: Optional[str] = Field(default=None, min_length=3, max_length=160)
    backend: str = "all"


class CalibrationPromoteRequest(ApiModel):
    report_path: str = Field(min_length=1, max_length=4096)
    reviewer: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=1000)


class AIScopeRequest(ApiModel):
    source: Optional[str] = Field(default=None, max_length=256)
    interface: Optional[str] = Field(default=None, max_length=256)
    session_id: Optional[str] = Field(default=None, max_length=256)
    node_id: Optional[str] = Field(default=None, max_length=256)
    time_start: Optional[float] = None
    time_end: Optional[float] = None
    case_id: Optional[str] = Field(default=None, max_length=256)
    target_ips: List[str] = Field(default_factory=list, max_length=100)
    max_records: int = Field(default=250, ge=1, le=500)


class AIConversationRequest(ApiModel):
    title: str = Field(default="New investigation", min_length=1, max_length=256)
    provider: str = Field(default="ollama", min_length=2, max_length=64, pattern="^[a-z0-9_-]+$")
    scope: AIScopeRequest = Field(default_factory=AIScopeRequest)


class AIRunRequest(ApiModel):
    prompt: str = Field(min_length=1, max_length=12000)
    conversation_id: Optional[str] = Field(default=None, max_length=64)
    provider: str = Field(default="ollama", min_length=2, max_length=64, pattern="^[a-z0-9_-]+$")
    scope: AIScopeRequest = Field(default_factory=AIScopeRequest)
    research_mode: str = Field(default="auto", pattern="^(auto|off)$")
    mode: str = Field(default="auto", pattern="^(auto|general|investigate|action)$")


class AIApprovalRequest(ApiModel):
    confirmation: str = Field(default="", max_length=256)
    reason: str = Field(default="operator rejected", max_length=1000)


class AICredentialRequest(ApiModel):
    reference: str = Field(min_length=3, max_length=128, pattern="^[A-Za-z0-9_.-]+$")
    secret: str = Field(min_length=1, max_length=4096)


class AuthSetupRequest(ApiModel):
    mode: str = Field(default="secure", pattern="^(secure|disabled)$")
    pin: Optional[str] = Field(default=None, min_length=6, max_length=128)
    display_name: str = Field(default="Local Operator", min_length=1, max_length=160)


class AuthPinRequest(ApiModel):
    pin: str = Field(min_length=6, max_length=128)
    client_type: str = Field(default="browser", pattern="^(browser|cli)$")


class AuthChallengeRequest(ApiModel):
    kind: str = Field(pattern="^(registration|authentication)$")
    nickname: str = Field(default="Windows Hello", min_length=1, max_length=120)


class AuthVerifyRequest(ApiModel):
    kind: str = Field(pattern="^(registration|authentication)$")
    challenge_id: str = Field(min_length=16, max_length=64)
    credential: Dict[str, Any]
    nickname: str = Field(default="Windows Hello", min_length=1, max_length=120)
    client_type: str = Field(default="browser", pattern="^(browser|cli)$")


class AuthSettingsRequest(ApiModel):
    enabled: bool
    pin: str = Field(min_length=6, max_length=128)


class AuthRecoveryRequest(ApiModel):
    recovery_code: str = Field(min_length=12, max_length=128)
    new_pin: str = Field(min_length=6, max_length=128)


class AIProviderConnectRequest(ApiModel):
    secret: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    model: Optional[str] = Field(default=None, min_length=1, max_length=160)
    base_url: Optional[str] = Field(default=None, min_length=8, max_length=2048)


class AIProviderModelRequest(ApiModel):
    model: str = Field(min_length=1, max_length=160)


class MeshEnrollmentRequest(ApiModel):
    name: Optional[str] = Field(default=None, max_length=256)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    max_uses: int = Field(default=1, ge=1, le=10)


class MeshControllerSetupRequest(ApiModel):
    mode: str = Field(default="local", pattern="^(local|vpn|public)$")
    address: Optional[str] = Field(default=None, max_length=253)
    enrollment_port: int = Field(default=9443, ge=1, le=65535)
    ingest_port: int = Field(default=9444, ge=1, le=65535)
    acknowledge_public_risk: bool = False


class MeshCommandRequest(ApiModel):
    action: str = Field(pattern="^(capture\\.start|capture\\.stop|case\\.export)$")
    arguments: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=300, ge=30, le=3600)


class MeshRevokeRequest(ApiModel):
    reason: str = Field(min_length=1, max_length=1000)

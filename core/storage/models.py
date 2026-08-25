from sqlalchemy import Column, Integer, String, Float, ForeignKey, Boolean, LargeBinary, Text, Index, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
from datetime import date

Base = declarative_base()

class Entity(Base):
    __tablename__ = "entities"
    ip = Column(String, primary_key=True)
    mac = Column(String, index=True)
    hostname = Column(String)
    netbios_name = Column(String)
    username = Column(String)
    full_name = Column(String)
    os = Column(String)
    vendor = Column(String)
    device_type = Column(String)
    asset_role = Column(String) # e.g. "Workstation", "IoT", "Server"
    confidence_score = Column(Float, default=0.0)
    identity_source = Column(String) # e.g. "Passive", "Active:NetBIOS", "Active:DNS"
    ja3_hash = Column(String)
    ja4_string = Column(String)
    tls_library = Column(String)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    first_seen = Column(Float)
    last_seen = Column(Float)
    reverse_dns = Column(String)
    source = Column(String, default="live")

    alerts = relationship("Alert", back_populates="entity", cascade="all, delete-orphan")
    carved_files = relationship("CarvedFile", back_populates="entity", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    timestamp = Column(Float)
    type = Column(String)
    severity = Column(String)
    score = Column(Float)
    explanation = Column(String)
    evidence = Column(Text) # JSON string
    source = Column(String, default="live")
    capture_session_id = Column(String, index=True)
    sensor_node_id = Column(String, index=True)
    capture_interface = Column(String, index=True)
    capture_backend = Column(String)
    capture_type = Column(String, default="network")
    sensor_node_id = Column(String, index=True)
    
    # AI 2.0 Fields
    ai_verdict = Column(String) # THREAT, FALSE_POSITIVE, UNKNOWN
    ai_reasoning = Column(Text)
    ai_status = Column(String, default="PENDING") # PENDING, INVESTIGATING, DONE, ERROR
    ai_cycle = Column(Integer, default=1)
    is_hidden = Column(Boolean, default=False) # For suppressed FPs
    fingerprint = Column(String, index=True)
    occurrence_count = Column(Integer, default=1)
    first_seen = Column(Float)
    last_seen = Column(Float)
    suppression_reason = Column(String)
    policy_context = Column(Text)

    entity = relationship("Entity", back_populates="alerts")

class Flow(Base):
    __tablename__ = "flows"
    id = Column(Integer, primary_key=True, autoincrement=True)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    start_time = Column(Float)
    last_seen = Column(Float)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    tcp_syn_count = Column(Integer, default=0)
    tcp_rst_count = Column(Integer, default=0)
    avg_packet_size = Column(Float, default=0)
    duration = Column(Float, default=0)
    interarrival_mean = Column(Float, default=0)
    interarrival_std = Column(Float, default=0)
    packet_size_variance = Column(Float, default=0)
    l7_metadata = Column(Text) # JSON string
    session_date = Column(String)
    source = Column(String, default="live")
    capture_session_id = Column(String, index=True)
    capture_interface = Column(String, index=True)
    capture_backend = Column(String)
    capture_type = Column(String, default="network")
    sensor_node_id = Column(String, index=True)

    __table_args__ = (
        UniqueConstraint('src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'source', name='_flow_uc'),
    )

class CarvedFile(Base):
    __tablename__ = "carved_files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    filename = Column(String)
    extension = Column(String)
    sha256 = Column(String, unique=True)
    size = Column(Integer)
    flow_src = Column(String)
    flow_dst = Column(String)
    timestamp = Column(Float)
    vt_results = Column(Text) # JSON string
    data = Column(LargeBinary)
    source = Column(String, default="live")
    capture_session_id = Column(String, index=True)
    sensor_node_id = Column(String, index=True)

    entity = relationship("Entity", back_populates="carved_files")

class DailyStats(Base):
    __tablename__ = "daily_stats"
    date = Column(String, primary_key=True)
    source = Column(String, primary_key=True, default="live")
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    total_flows = Column(Integer, default=0)
    snapshot_count = Column(Integer, default=0)
    protocol_distribution = Column(Text) # JSON string
    port_distribution = Column(Text) # JSON string
    top_talkers = Column(Text) # JSON string

class Timeline(Base):
    __tablename__ = "timeline"
    timestamp = Column(Integer, primary_key=True)
    source = Column(String, primary_key=True, default="live")
    date = Column(String, nullable=False)
    packets = Column(Integer, default=0)
    bytes = Column(Integer, default=0)

class ForensicReport(Base):
    __tablename__ = "forensic_reports"
    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String)
    timestamp = Column(Float)
    total_flows = Column(Integer, default=0)
    total_entities = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    summary = Column(Text) # JSON string
    status = Column(String, default="RUNNING")
    analysis_mode = Column(String, default="memory")
    backend = Column(String, default="python")
    bytes_processed = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    error = Column(Text)
    completed_at = Column(Float)
    spool_path = Column(Text)


class ForensicCase(Base):
    __tablename__ = "forensic_cases"
    id = Column(String, primary_key=True)
    analysis_id = Column(String, nullable=False, unique=True, index=True)
    sha256 = Column(String, nullable=False, index=True)
    filename = Column(String)
    byte_count = Column(Integer, nullable=False, default=0)
    capture_started_at = Column(Float)
    capture_ended_at = Column(Float)
    link_type = Column(String)
    parser_version = Column(String)
    backend = Column(String)
    backend_version = Column(String)
    state = Column(String, nullable=False, default="created", index=True)
    progress = Column(Float, nullable=False, default=0.0)
    warnings_json = Column(Text, nullable=False, default="[]")
    visibility_limitations_json = Column(Text, nullable=False, default="[]")
    report_hash = Column(String)
    retained_input = Column(Boolean, nullable=False, default=False)
    retention_mode = Column(String, nullable=False, default="discard")
    encryption_format = Column(String)
    configuration_hash = Column(String, index=True)
    pipeline_version = Column(String)
    created_at = Column(Float, nullable=False, index=True)
    completed_at = Column(Float)


class ForensicAnalysisRevision(Base):
    __tablename__ = "forensic_analysis_revisions"
    analysis_id = Column(String, primary_key=True)
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    pcap_sha256 = Column(String, nullable=False, index=True)
    pipeline_version = Column(String, nullable=False)
    configuration_hash = Column(String, nullable=False, index=True)
    backend = Column(String, nullable=False)
    backend_version = Column(String)
    state = Column(String, nullable=False, default="queued", index=True)
    created_at = Column(Float, nullable=False, index=True)
    started_at = Column(Float)
    completed_at = Column(Float)
    report_hash = Column(String)
    visibility_limitations_json = Column(Text, nullable=False, default="[]")
    evidence_components_json = Column(Text, nullable=False, default="{}")


class ForensicPacketIndex(Base):
    __tablename__ = "forensic_packet_indexes"
    analysis_id = Column(
        String,
        ForeignKey("forensic_analysis_revisions.analysis_id", ondelete="CASCADE"),
        primary_key=True,
    )
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    pcap_sha256 = Column(String, nullable=False, index=True)
    schema_version = Column(Integer, nullable=False)
    manifest_path = Column(Text, nullable=False)
    manifest_sha256 = Column(String, nullable=False)
    row_count = Column(Integer, nullable=False, default=0)
    partition_count = Column(Integer, nullable=False, default=0)
    first_timestamp = Column(Float)
    last_timestamp = Column(Float)
    state = Column(String, nullable=False, default="complete", index=True)
    created_at = Column(Float, nullable=False, index=True)


class ForensicConversation(Base):
    __tablename__ = "forensic_conversations"
    id = Column(String, primary_key=True)
    analysis_id = Column(
        String,
        ForeignKey("forensic_analysis_revisions.analysis_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id = Column(
        String,
        ForeignKey("forensic_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sensor_node_id = Column(String, nullable=False)
    source = Column(String, nullable=False)
    interface = Column(String, nullable=False)
    session_id = Column(String, nullable=False)
    protocol = Column(String, nullable=False)
    endpoint_a_ip = Column(String, nullable=False)
    endpoint_a_port = Column(Integer, nullable=False)
    endpoint_b_ip = Column(String, nullable=False)
    endpoint_b_port = Column(Integer, nullable=False)
    initiator_ip = Column(String, nullable=False)
    initiator_port = Column(Integer, nullable=False)
    responder_ip = Column(String, nullable=False)
    responder_port = Column(Integer, nullable=False)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    to_responder_packets = Column(Integer, nullable=False, default=0)
    to_responder_bytes = Column(Integer, nullable=False, default=0)
    to_initiator_packets = Column(Integer, nullable=False, default=0)
    to_initiator_bytes = Column(Integer, nullable=False, default=0)
    syn_count = Column(Integer, nullable=False, default=0)
    syn_ack_count = Column(Integer, nullable=False, default=0)
    rst_count = Column(Integer, nullable=False, default=0)
    established = Column(Boolean, nullable=False, default=False)
    application_json = Column(Text, nullable=False, default="{}")
    generation = Column(Integer, nullable=False, default=0)
    backend = Column(String, nullable=False)
    source_type = Column(String, nullable=False)
    completeness = Column(String, nullable=False, default="complete")
    created_at = Column(Float, nullable=False, index=True)
    updated_at = Column(Float, nullable=False)


class ForensicDeepDissectionRecord(Base):
    __tablename__ = "forensic_deep_dissection_records"
    id = Column(String, primary_key=True)
    analysis_id = Column(
        String,
        ForeignKey("forensic_analysis_revisions.analysis_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id = Column(
        String,
        ForeignKey("forensic_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ordinal = Column(Integer, nullable=False)
    record_sha256 = Column(String, nullable=False)
    fields_json = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False, index=True)
    __table_args__ = (
        UniqueConstraint(
            "analysis_id",
            "ordinal",
            name="uq_forensic_deep_dissection_revision_ordinal",
        ),
    )


class ForensicEvidenceComponent(Base):
    __tablename__ = "forensic_evidence_components"
    analysis_id = Column(
        String,
        ForeignKey("forensic_analysis_revisions.analysis_id", ondelete="CASCADE"),
        primary_key=True,
    )
    component = Column(String, primary_key=True)
    case_id = Column(
        String,
        ForeignKey("forensic_cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sha256 = Column(String, nullable=False)
    record_count = Column(Integer, nullable=False, default=0)
    state = Column(String, nullable=False, default="complete", index=True)
    created_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=False)


class ForensicEvidenceEnvelope(Base):
    __tablename__ = "forensic_evidence_envelopes"
    id = Column(String, primary_key=True)
    job_id = Column(String, nullable=False, index=True)
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = Column(String, nullable=False)
    credential_reference = Column(Text, nullable=False)
    nonce = Column(Text, nullable=False)
    format_version = Column(String, nullable=False)
    digest = Column(String, nullable=False, index=True)
    encrypted_path = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("job_id", "purpose", name="_forensic_evidence_job_purpose_uc"),
    )


class ForensicCaseCustodyEvent(Base):
    """Append-only chain-of-custody event for an offline forensic case."""
    __tablename__ = "forensic_case_custody"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    digest = Column(String, nullable=False)
    metadata_json = Column(Text, nullable=False, default="{}")
    timestamp = Column(Float, nullable=False, index=True)


class ForensicCaseEntity(Base):
    __tablename__ = "forensic_case_entities"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String, nullable=False)
    mac = Column(String, index=True)
    hostname = Column(String)
    netbios_name = Column(String)
    username = Column(String)
    full_name = Column(String)
    os = Column(String)
    vendor = Column(String)
    device_type = Column(String)
    asset_role = Column(String)
    reverse_dns = Column(String)
    provenance_json = Column(Text, nullable=False, default="{}")
    confidence = Column(Float, nullable=False, default=0.0)
    total_packets = Column(Integer, nullable=False, default=0)
    total_bytes = Column(Integer, nullable=False, default=0)
    first_seen = Column(Float)
    last_seen = Column(Float)

    __table_args__ = (
        UniqueConstraint("case_id", "ip", name="_forensic_case_entity_scope_uc"),
    )


class ForensicTriageFlag(Base):
    __tablename__ = "forensic_triage_flags"
    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String, ForeignKey("forensic_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String, nullable=False)
    target_type = Column(String, nullable=False, index=True)
    target_id = Column(String, nullable=False, index=True)
    detector = Column(String)
    source = Column(String)
    finding_ids_json = Column(Text, nullable=False, default="[]")
    evidence_refs_json = Column(Text, nullable=False, default="[]")
    observed_values_json = Column(Text, nullable=False, default="{}")
    reason = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    status = Column(String, nullable=False, default="open", index=True)
    actor = Column(String, nullable=False, default="system")
    first_seen = Column(Float)
    last_seen = Column(Float, index=True)
    created_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=False)
    resolved_at = Column(Float)

    __table_args__ = (
        UniqueConstraint("case_id", "fingerprint", name="_forensic_triage_flag_scope_uc"),
    )


class AssetProfile(Base):
    __tablename__ = "asset_profiles"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, index=True, nullable=False)
    source = Column(String, default="live", nullable=False)
    scope = Column(String)
    subnet = Column(String)
    role = Column(String)
    role_confidence = Column(Float, default=0.0)
    profile_data = Column(Text, nullable=False)
    profiled_at = Column(Float)

    __table_args__ = (
        UniqueConstraint("entity_ip", "source", name="_asset_profile_uc"),
    )

class EvidenceLink(Base):
    __tablename__ = "evidence_links"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, index=True, nullable=False)
    source = Column(String, default="live", nullable=False)
    evidence_type = Column(String, nullable=False)
    evidence_ref = Column(String, nullable=False)
    timestamp = Column(Float)
    summary = Column(Text)
    details = Column(Text)
    confidence = Column(Float, default=1.0)

    __table_args__ = (
        UniqueConstraint("entity_ip", "source", "evidence_type", "evidence_ref", name="_evidence_link_uc"),
    )


class EndpointIdentity(Base):
    """Versioned endpoint identity projection scoped to one capture source."""
    __tablename__ = "endpoint_identities"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, default="live", index=True)
    capture_interface = Column(String, index=True)
    capture_session_id = Column(String, index=True)
    sensor_node_id = Column(String, index=True)
    model_version = Column(String, nullable=False, index=True)
    identity_type = Column(String, nullable=False, index=True)
    identity_label = Column(String, nullable=False)
    identity_state = Column(String, nullable=False, default="address_only", index=True)
    evidence_completeness = Column(Float, nullable=False, default=0.0)
    next_action = Column(Text)
    observation_count = Column(Integer, nullable=False, default=0)
    confidence = Column(Float, nullable=False, default=0.0)
    verification = Column(String, nullable=False, default="observed")
    evidence_json = Column(Text, nullable=False, default="[]")
    first_seen = Column(Float)
    last_seen = Column(Float)
    updated_at = Column(Float, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "entity_ip", "source", "capture_interface", "capture_session_id", "model_version",
            name="_endpoint_identity_scope_uc",
        ),
    )


class IdentityObservation(Base):
    """Immutable evidence observations used to build endpoint identity cards."""
    __tablename__ = "identity_observations"
    id = Column(String, primary_key=True)
    subject_ip = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, default="live", index=True)
    capture_interface = Column(String, index=True)
    capture_session_id = Column(String, index=True)
    sensor_node_id = Column(String, index=True)
    observation_type = Column(String, nullable=False, index=True)
    value_json = Column(Text, nullable=False, default="{}")
    confidence = Column(Float, nullable=False, default=0.0)
    evidence_ref = Column(String, nullable=False)
    first_seen = Column(Float)
    last_seen = Column(Float)
    occurrence_count = Column(Integer, nullable=False, default=1)
    fresh_until = Column(Float)
    fingerprint = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(Float, nullable=False)


class SystemMetadata(Base):
    __tablename__ = "system_metadata"
    key = Column(String, primary_key=True)
    value = Column(String)


class CaptureSession(Base):
    __tablename__ = "capture_sessions"
    id = Column(String, primary_key=True)
    source_type = Column(String, nullable=False, default="network")
    device_id = Column(String, nullable=False)
    interface = Column(String, index=True)
    backend = Column(String, nullable=False, default="python")
    link_type = Column(String, default="ethernet")
    source = Column(String, index=True)
    sensor_node_id = Column(String, index=True)
    started_at = Column(Float, nullable=False)
    ended_at = Column(Float)
    status = Column(String, default="RUNNING")
    received_packets = Column(Integer, default=0)
    emitted_packets = Column(Integer, default=0)
    dropped_packets = Column(Integer, default=0)
    queue_full_events = Column(Integer, default=0)
    processed_packets = Column(Integer, default=0)
    detector_errors = Column(Integer, default=0)
    evidence_dropped = Column(Integer, default=0)
    snapshot_dropped = Column(Integer, default=0)
    pending_packets = Column(Integer, default=0)
    queue_depth_high_watermark = Column(Integer, default=0)
    queue_lag_ms = Column(Float, default=0.0)
    queue_lag_max_ms = Column(Float, default=0.0)
    processing_state = Column(String, default="running", index=True)
    complete = Column(Boolean, default=False)
    completion_reason = Column(Text)
    error = Column(Text)
    metadata_json = Column(Text)
    daemon_instance_id = Column(String, index=True)
    last_heartbeat_at = Column(Float)
    shutdown_stage = Column(String, default="capturing")
    worker_acknowledged = Column(Boolean, default=False)
    evidence_acknowledged = Column(Boolean, default=False)
    persisted_generation = Column(Integer, default=0)
    process_exit_outcome = Column(Text)


class HardwareObservation(Base):
    __tablename__ = "hardware_observations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    capture_session_id = Column(String, ForeignKey("capture_sessions.id"), index=True)
    timestamp = Column(Float, nullable=False)
    source_type = Column(String, nullable=False)
    device_id = Column(String)
    sensor_node_id = Column(String, index=True)
    observation_type = Column(String, index=True)
    subject = Column(String, index=True)
    peer = Column(String)
    metadata_json = Column(Text)
    ingest_token = Column(String)


class EndpointProcessObservation(Base):
    """Redacted endpoint telemetry, normally sourced from Sysmon."""

    __tablename__ = "endpoint_process_observations"
    id = Column(String, primary_key=True)
    sensor_node_id = Column(String, nullable=False, index=True)
    event_record_id = Column(String, index=True)
    event_type = Column(String, nullable=False, index=True)
    observed_at = Column(Float, nullable=False, index=True)
    process_guid = Column(String, index=True)
    pid = Column(Integer, index=True)
    parent_pid = Column(Integer)
    image = Column(Text)
    command_line_hash = Column(String)
    user_name = Column(String)
    hashes_json = Column(Text, default="{}")
    service_names_json = Column(Text, default="[]")
    protocol = Column(String, index=True)
    local_ip = Column(String, index=True)
    local_port = Column(Integer, index=True)
    remote_ip = Column(String, index=True)
    remote_port = Column(Integer, index=True)
    initiated = Column(Boolean)
    evidence_ref = Column(String, nullable=False)
    details_json = Column(Text, default="{}")
    created_at = Column(Float, nullable=False)

    __table_args__ = (
        UniqueConstraint("sensor_node_id", "event_record_id", "event_type", name="_endpoint_observation_event_uc"),
    )


class SensorNode(Base):
    __tablename__ = "sensor_nodes"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True, index=True)
    certificate_fingerprint = Column(String, unique=True, index=True)
    status = Column(String, nullable=False, default="enrolled", index=True)
    platform = Column(String)
    agent_version = Column(String)
    capabilities_json = Column(Text, nullable=False, default="{}")
    health_json = Column(Text, nullable=False, default="{}")
    created_at = Column(Float, nullable=False)
    last_seen_at = Column(Float, index=True)
    revoked_at = Column(Float)
    revoke_reason = Column(Text)


class MeshEnrollment(Base):
    __tablename__ = "mesh_enrollments"
    id = Column(String, primary_key=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    requested_name = Column(String)
    expires_at = Column(Float, nullable=False, index=True)
    max_uses = Column(Integer, nullable=False, default=1)
    used_count = Column(Integer, nullable=False, default=0)
    created_at = Column(Float, nullable=False)
    created_by = Column(String, nullable=False, default="local-operator")
    revoked_at = Column(Float)


class MeshIngestReceipt(Base):
    __tablename__ = "mesh_ingest_receipts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    sensor_node_id = Column(String, nullable=False, index=True)
    sequence = Column(Integer, nullable=False)
    envelope_type = Column(String, nullable=False, index=True)
    payload_hash = Column(String, nullable=False)
    received_at = Column(Float, nullable=False, index=True)
    status = Column(String, nullable=False, default="accepted")
    detail = Column(Text)

    __table_args__ = (
        UniqueConstraint("sensor_node_id", "sequence", name="_mesh_receipt_sequence_uc"),
    )


class MeshCommand(Base):
    __tablename__ = "mesh_commands"
    id = Column(String, primary_key=True)
    sensor_node_id = Column(String, nullable=False, index=True)
    action = Column(String, nullable=False, index=True)
    arguments_json = Column(Text, nullable=False, default="{}")
    status = Column(String, nullable=False, default="queued", index=True)
    requested_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)
    requested_by = Column(String, nullable=False, default="local-operator")
    idempotency_key = Column(String, nullable=False, unique=True)
    result_json = Column(Text)
    completed_at = Column(Float)


class GraphOutbox(Base):
    __tablename__ = "graph_outbox"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_key = Column(String, nullable=False, unique=True, index=True)
    operation = Column(String, nullable=False, index=True)
    payload_json = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False, index=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_attempt_at = Column(Float)
    next_attempt_at = Column(Float, index=True)
    lease_owner = Column(String, index=True)
    lease_expires_at = Column(Float, index=True)
    dead_lettered_at = Column(Float, index=True)
    delivered_at = Column(Float, index=True)
    error = Column(Text)

# --- AI 2.0 Models ---

class BehavioralBaseline(Base):
    __tablename__ = "behavioral_baselines"
    id = Column(Integer, primary_key=True, autoincrement=True)
    entity_ip = Column(String, ForeignKey("entities.ip"))
    pattern_key = Column(String, index=True) # e.g. "port_usage", "comm_pair"
    pattern_data = Column(Text) # JSON string
    confidence = Column(Float, default=0.0)
    last_updated = Column(Float)
    source = Column(String, default="live")

class InvestigationStep(Base):
    __tablename__ = "investigation_steps"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    timestamp = Column(Float)
    thought = Column(Text)
    action = Column(String)
    observation = Column(Text)

class AIUserFeedback(Base):
    """Stores user's confirmation or rejection of AI verdicts to prevent redundant re-investigation."""
    __tablename__ = "ai_user_feedback"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String, index=True)
    entity_ip = Column(String, index=True)
    user_verdict = Column(String) # AGREE, DISAGREE
    timestamp = Column(Float)


# --- Agentic analyst audit records ----------------------------------------

class AIConversation(Base):
    __tablename__ = "ai_conversations"
    id = Column(String, primary_key=True)
    title = Column(String, nullable=False, default="New investigation")
    provider = Column(String)
    scope_json = Column(Text, nullable=False, default="{}")
    created_at = Column(Float, nullable=False, index=True)
    updated_at = Column(Float, nullable=False, index=True)
    archived = Column(Boolean, nullable=False, default=False, index=True)


class AIMessage(Base):
    __tablename__ = "ai_messages"
    id = Column(String, primary_key=True)
    conversation_id = Column(String, ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(String, index=True)
    role = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    citations_json = Column(Text, nullable=False, default="[]")
    created_at = Column(Float, nullable=False, index=True)


class AIRun(Base):
    __tablename__ = "ai_runs"
    id = Column(String, primary_key=True)
    conversation_id = Column(String, ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String, nullable=False)
    status = Column(String, nullable=False, index=True)
    prompt_hash = Column(String, nullable=False)
    scope_json = Column(Text, nullable=False, default="{}")
    policy_json = Column(Text, nullable=False, default="{}")
    final_text = Column(Text)
    analyst_version = Column(String, default="agentic-v2")
    rounds = Column(Integer, default=0)
    tool_call_count = Column(Integer, default=0)
    redundant_tool_calls = Column(Integer, default=0)
    context_chars = Column(Integer, default=0)
    citation_coverage = Column(Float, default=0.0)
    mode = Column(String, nullable=False, default="investigate")
    validation_status = Column(String, nullable=False, default="not_run")
    supported_claims = Column(Integer, default=0)
    inferred_claims = Column(Integer, default=0)
    blocked_claims = Column(Integer, default=0)
    numeric_accuracy = Column(Float, default=1.0)
    error = Column(Text)
    created_at = Column(Float, nullable=False, index=True)
    updated_at = Column(Float, nullable=False)


class AIToolInvocation(Base):
    __tablename__ = "ai_tool_invocations"
    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("ai_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String, nullable=False, index=True)
    risk_tier = Column(String, nullable=False)
    status = Column(String, nullable=False, index=True)
    arguments_json = Column(Text, nullable=False, default="{}")
    result_json = Column(Text)
    result_hash = Column(String)
    created_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=False)


class AIApproval(Base):
    __tablename__ = "ai_approvals"
    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("ai_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    invocation_id = Column(String, ForeignKey("ai_tool_invocations.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_name = Column(String, nullable=False)
    risk_tier = Column(String, nullable=False)
    arguments_hash = Column(String, nullable=False)
    scope_json = Column(Text, nullable=False, default="{}")
    status = Column(String, nullable=False, index=True)
    requester = Column(String, nullable=False, default="local-operator")
    confirmation_phrase = Column(String)
    idempotency_key = Column(String, nullable=False, unique=True)
    requested_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)
    resolved_at = Column(Float)
    result_json = Column(Text)


class AICitation(Base):
    __tablename__ = "ai_citations"
    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("ai_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String, nullable=False, index=True)
    reference = Column(String, nullable=False)
    source = Column(String, nullable=False)
    url = Column(Text)
    summary = Column(Text, nullable=False)
    observed_at = Column(Float)
    retrieved_at = Column(Float)
    content_hash = Column(String)
    scope_json = Column(Text, nullable=False, default="{}")


class AIResearchDocument(Base):
    __tablename__ = "ai_research_documents"
    id = Column(String, primary_key=True)
    source_kind = Column(String, nullable=False, index=True)
    canonical_url = Column(Text, nullable=False, unique=True)
    title = Column(Text)
    summary = Column(Text, nullable=False)
    content_hash = Column(String, nullable=False, index=True)
    retrieved_at = Column(Float, nullable=False, index=True)
    expires_at = Column(Float, nullable=False, index=True)


class AIEvidenceFact(Base):
    """Normalized, cited scalar facts collected during one analyst run."""
    __tablename__ = "ai_evidence_facts"
    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("ai_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    fact_id = Column(String, nullable=False, index=True)
    subject = Column(String, nullable=False, index=True)
    predicate = Column(String, nullable=False, index=True)
    value_json = Column(Text, nullable=False, default="null")
    confidence = Column(Float, nullable=False, default=1.0)
    completeness = Column(String, nullable=False, default="complete")
    freshness = Column(Float)
    scope_json = Column(Text, nullable=False, default="{}")
    citations_json = Column(Text, nullable=False, default="[]")
    created_at = Column(Float, nullable=False, index=True)


# --- Local operator trust boundary -----------------------------------------

class OperatorAccount(Base):
    __tablename__ = "operator_accounts"
    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False, default="Local Operator")
    auth_enabled = Column(Boolean, nullable=False, default=True)
    setup_completed = Column(Boolean, nullable=False, default=False)
    pin_hash = Column(Text)
    recovery_hash = Column(Text)
    failed_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(Float)
    created_at = Column(Float, nullable=False)
    updated_at = Column(Float, nullable=False)


class OperatorCredential(Base):
    __tablename__ = "operator_credentials"
    id = Column(String, primary_key=True)
    operator_id = Column(String, ForeignKey("operator_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = Column(Text, nullable=False, unique=True, index=True)
    public_key = Column(Text, nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    transports_json = Column(Text, nullable=False, default="[]")
    nickname = Column(String, nullable=False, default="Windows Hello")
    created_at = Column(Float, nullable=False)
    last_used_at = Column(Float)


class OperatorSession(Base):
    __tablename__ = "operator_sessions"
    id = Column(String, primary_key=True)
    operator_id = Column(String, ForeignKey("operator_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    client_type = Column(String, nullable=False, default="browser", index=True)
    installation_id = Column(String, nullable=False, index=True)
    created_at = Column(Float, nullable=False)
    authenticated_at = Column(Float, nullable=False)
    step_up_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)
    revoked_at = Column(Float, index=True)
    revoke_reason = Column(String)


class OperatorChallenge(Base):
    __tablename__ = "operator_challenges"
    id = Column(String, primary_key=True)
    operator_id = Column(String, ForeignKey("operator_accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String, nullable=False, index=True)
    challenge = Column(Text, nullable=False)
    origin = Column(String, nullable=False)
    rp_id = Column(String, nullable=False)
    created_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)
    consumed_at = Column(Float)


class SecurityAuditEvent(Base):
    __tablename__ = "security_audit_events"
    id = Column(String, primary_key=True)
    operator_id = Column(String, index=True)
    event_type = Column(String, nullable=False, index=True)
    outcome = Column(String, nullable=False, index=True)
    client_type = Column(String, nullable=False)
    request_id = Column(String, index=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(Float, nullable=False, index=True)


class ServicePrincipal(Base):
    """Installation-bound non-operator identity for headless local services."""
    __tablename__ = "service_principals"
    id = Column(String, primary_key=True)
    role = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=False)
    scopes_json = Column(Text, nullable=False, default="[]")
    created_at = Column(Float, nullable=False)
    last_used_at = Column(Float)
    revoked_at = Column(Float, index=True)


class AIPrivateScopeConsent(Base):
    __tablename__ = "ai_private_scope_consents"
    id = Column(String, primary_key=True)
    operator_session_id = Column(String, ForeignKey("operator_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    scope_hash = Column(String, nullable=False, index=True)
    scope_json = Column(Text, nullable=False)
    created_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("operator_session_id", "provider", "scope_hash", name="_ai_private_scope_session_uc"),
    )


class AIProviderModelCache(Base):
    __tablename__ = "ai_provider_model_cache"
    provider = Column(String, primary_key=True)
    models_json = Column(Text, nullable=False, default="[]")
    fetched_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False, index=True)
    error = Column(Text)


class PcapAnalysisJob(Base):
    __tablename__ = "pcap_analysis_jobs"
    id = Column(String, primary_key=True)
    filename = Column(String, nullable=False)
    file_size = Column(Integer, nullable=False)
    mode = Column(String, nullable=False)
    backend = Column(String, nullable=False)
    source = Column(String, nullable=False, unique=True, index=True)
    status = Column(String, nullable=False, index=True)
    report_id = Column(Integer, ForeignKey("forensic_reports.id"))
    created_at = Column(Float, nullable=False, index=True)
    started_at = Column(Float)
    completed_at = Column(Float)
    bytes_processed = Column(Integer, nullable=False, default=0)
    progress = Column(Float, nullable=False, default=0.0)
    summary_json = Column(Text, nullable=False, default="{}")
    error = Column(Text)
    retained_input = Column(Boolean, nullable=False, default=False)
    input_path = Column(Text)
    keylog_path = Column(Text)
    case_id = Column(String, index=True)
    analysis_id = Column(String, index=True)
    pcap_sha256 = Column(String, index=True)
    capture_started_at = Column(Float)
    capture_ended_at = Column(Float)
    link_type = Column(String)
    parser_version = Column(String)
    backend_version = Column(String)
    configuration_hash = Column(String, index=True)
    pipeline_version = Column(String)
    retention_mode = Column(String, nullable=False, default="discard")
    encryption_format = Column(String)


# --- Behavioral Scoring V2 -------------------------------------------------

class ScoringModel(Base):
    __tablename__ = "scoring_models"
    version = Column(String, primary_key=True)
    config_hash = Column(String, nullable=False, index=True)
    mode = Column(String, default="dual")
    activated_at = Column(Float)
    config_json = Column(Text, nullable=False)


class DetectionFinding(Base):
    __tablename__ = "detection_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String, nullable=False, index=True)
    model_version = Column(String, nullable=False, index=True)
    detector_id = Column(String, nullable=False, index=True)
    detector_version = Column(String, nullable=False)
    finding_type = Column(String, nullable=False, index=True)
    legacy_type = Column(String)
    category = Column(String, nullable=False, index=True)
    impact = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    evidence_quality = Column(Float, nullable=False)
    calibration_state = Column(String, nullable=False)
    signal_family = Column(String, nullable=False)
    correlation_group = Column(String, nullable=False, index=True)
    subject = Column(String, nullable=False, index=True)
    target = Column(String, index=True)
    flow_ref = Column(String)
    source = Column(String, nullable=False, default="live", index=True)
    capture_interface = Column(String, index=True)
    capture_session_id = Column(String, index=True)
    capture_backend = Column(String)
    sensor_node_id = Column(String, index=True)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False, index=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    explanation = Column(Text, nullable=False)
    recommended_action = Column(Text)
    mitre_technique = Column(String)
    evidence_json = Column(Text, nullable=False, default="{}")
    evidence_refs_json = Column(Text, nullable=False, default="[]")
    disposition = Column(String, default="unknown", index=True)
    is_suppressed = Column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint(
            "model_version", "fingerprint", "source", "capture_interface", "capture_session_id",
            name="_finding_scope_uc",
        ),
    )


class FindingWindow(Base):
    __tablename__ = "finding_windows"
    finding_id = Column(Integer, ForeignKey("detection_findings.id", ondelete="CASCADE"), primary_key=True)
    bucket_start = Column(Integer, primary_key=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    max_confidence = Column(Float, nullable=False, default=0.0)
    max_evidence_quality = Column(Float, nullable=False, default=0.0)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    evidence_ref = Column(String)


class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"
    id = Column(Integer, primary_key=True, autoincrement=True)
    model_version = Column(String, nullable=False, index=True)
    config_hash = Column(String, nullable=False)
    subject = Column(String, nullable=False, index=True)
    scope_type = Column(String, nullable=False, index=True)
    scope_id = Column(String, nullable=False, index=True)
    source = Column(String)
    capture_interface = Column(String)
    capture_session_id = Column(String)
    sensor_node_id = Column(String, index=True)
    priority_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    assessment_confidence = Column(Float, nullable=False)
    computed_at = Column(Float, nullable=False, index=True)
    contributors_json = Column(Text, nullable=False, default="[]")

    __table_args__ = (
        UniqueConstraint("model_version", "subject", "scope_type", "scope_id", name="_risk_snapshot_scope_uc"),
    )


class FeatureBaseline(Base):
    __tablename__ = "feature_baselines_v2"
    id = Column(Integer, primary_key=True, autoincrement=True)
    subject = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, default="live", index=True)
    capture_interface = Column(String, index=True)
    feature = Column(String, nullable=False, index=True)
    dimension = Column(String, nullable=False, default="")
    sample_count = Column(Integer, nullable=False, default=0)
    first_sample_at = Column(Float)
    last_sample_at = Column(Float, index=True)
    mean = Column(Float, default=0.0)
    m2 = Column(Float, default=0.0)
    ewma = Column(Float, default=0.0)
    ewma_variance = Column(Float, default=0.0)
    p50 = Column(Float, default=0.0)
    p95 = Column(Float, default=0.0)
    p99 = Column(Float, default=0.0)
    state_json = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint("subject", "source", "capture_interface", "feature", "dimension", name="_feature_baseline_scope_uc"),
    )


class AnalystDisposition(Base):
    __tablename__ = "analyst_dispositions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("detection_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    verdict = Column(String, nullable=False, index=True)
    reason = Column(Text)
    actor = Column(String, nullable=False, default="local-analyst")
    created_at = Column(Float, nullable=False)
    scope = Column(String, nullable=False, default="finding")
    expires_at = Column(Float)


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    version = Column(String, primary_key=True)
    applied_at = Column(Float, nullable=False)
    checksum = Column(String, nullable=False)

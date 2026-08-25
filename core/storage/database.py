import os
import base64
import platform
import threading
from contextlib import contextmanager
from contextvars import ContextVar
import json
import time
import uuid
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import date

from sqlalchemy import Integer, and_, create_engine, select, update, insert, delete, func, or_, case
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import QueuePool
from core.storage.models import (
    Base, Entity, Alert, Flow, CarvedFile, DailyStats, Timeline, ForensicReport,
    ForensicCase, ForensicAnalysisRevision, ForensicPacketIndex, ForensicConversation,
    ForensicDeepDissectionRecord, ForensicEvidenceComponent, ForensicEvidenceEnvelope,
    ForensicCaseCustodyEvent, ForensicCaseEntity, ForensicTriageFlag,
    SystemMetadata, AssetProfile, EvidenceLink, EndpointIdentity, IdentityObservation, CaptureSession, HardwareObservation,
    EndpointProcessObservation,
    SensorNode, MeshEnrollment, MeshIngestReceipt, MeshCommand, GraphOutbox,
    BehavioralBaseline, InvestigationStep, AIUserFeedback,
    DetectionFinding, FindingWindow, RiskSnapshot, FeatureBaseline,
    AnalystDisposition, ScoringModel, SchemaMigration, AIConversation, AIMessage,
    AIRun, AIToolInvocation, AIApproval, AICitation, AIResearchDocument, AIEvidenceFact,
    OperatorAccount, OperatorCredential, OperatorSession, OperatorChallenge,
    SecurityAuditEvent, ServicePrincipal, AIPrivateScopeConsent, AIProviderModelCache, PcapAnalysisJob,
)
from core.constants import FORENSIC_TERMINAL_STATES
from core.utils.logger import setup_logger
from core.detection.policy import DetectionPolicy
from core.utils.network import format_flow_id
import os

logger = setup_logger("database")
_database_scope = ContextVar("watchtower_database_scope", default=None)


def _session_scope_key():
    return _database_scope.get() or ("thread", threading.get_ident())

class WatchtowerDB:
    """Thread-safe database manager using SQLAlchemy."""

    _local_sensor_cache_lock = threading.RLock()
    _local_sensor_ids: Dict[str, str] = {}

    def __init__(self, data_dir: str = None):
        from core.context import context
        self.data_dir = Path(data_dir or context.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "watchtower.db"

        # SQLITE_URL = f"sqlite:///{self.db_path}"
        # On Windows, need 3 slashes if absolute path, but relative is fine with 2 or 3
        # We'll use absolute path with 4 slashes for reliability
        abs_path = os.path.abspath(self.db_path).replace("\\", "/")
        self.engine = create_engine(
            f"sqlite:///{abs_path}", 
            connect_args={"check_same_thread": False, "timeout": 10.0},
            poolclass=QueuePool,
            pool_size=16,
            max_overflow=16,
            pool_timeout=10.0,
            pool_recycle=1800,
            pool_pre_ping=True,
        )
        self._pool_metrics = {
            "checkouts": 0,
            "checkins": 0,
            "peak_checked_out": 0,
            "wait_time_ms_total": 0.0,
            "wait_time_ms_max": 0.0,
            "timeouts": 0,
            "sqlite_lock_contention": 0,
        }
        
        # Enable WAL mode for better concurrency on Windows
        from sqlalchemy import event
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

        @event.listens_for(self.engine, "checkout")
        def record_checkout(dbapi_connection, connection_record, connection_proxy):
            self._pool_metrics["checkouts"] += 1
            self._pool_metrics["peak_checked_out"] = max(
                self._pool_metrics["peak_checked_out"],
                int(self.engine.pool.checkedout()),
            )

        @event.listens_for(self.engine, "checkin")
        def record_checkin(dbapi_connection, connection_record):
            self._pool_metrics["checkins"] += 1

        @event.listens_for(self.engine, "handle_error")
        def record_database_error(exception_context):
            message = str(exception_context.original_exception or "").lower()
            if "database is locked" in message or "database table is locked" in message:
                self._pool_metrics["sqlite_lock_contention"] += 1
        
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.Session = scoped_session(self.session_factory, scopefunc=_session_scope_key)
        
        self.alert_callback = None
        self.alert_policy = DetectionPolicy()
        self._scoring_config_cache = None
        self._scoring_config_signature = None
        self._registered_scoring_hash = None
        self._init_schema()

    def _init_schema(self):
        """Create all tables and ensure schema is up-to-date."""
        Base.metadata.create_all(self.engine)
        # Inspect the schema once. Reopening a SQLite connection and issuing
        # PRAGMA table_info for every additive column dominated short PCAP
        # analysis and calibration jobs even when the schema was current.
        from sqlalchemy import inspect
        inspector = inspect(self.engine)
        self._schema_columns_cache = {
            table: {str(column["name"]) for column in inspector.get_columns(table)}
            for table in Base.metadata.tables
            if inspector.has_table(table)
        }
        self._schema_indexes_cache = {
            table: {str(index["name"]) for index in inspector.get_indexes(table)}
            for table in Base.metadata.tables
            if inspector.has_table(table)
        }
        
        # Ensure new Identity and AI 2.0 columns exist (Safe for existing DBs)
        self._ensure_column_exists("entities", "reverse_dns", "TEXT")
        self._ensure_column_exists("entities", "confidence_score", "REAL DEFAULT 0.0")
        self._ensure_column_exists("entities", "vendor", "TEXT")
        self._ensure_column_exists("entities", "device_type", "TEXT")
        self._ensure_column_exists("entities", "asset_role", "TEXT")
        self._ensure_column_exists("alerts", "ai_verdict", "TEXT")
        self._ensure_column_exists("alerts", "ai_status", "TEXT DEFAULT 'PENDING'")
        self._ensure_column_exists("alerts", "is_hidden", "BOOLEAN DEFAULT 0")
        self._ensure_column_exists("alerts", "fingerprint", "TEXT")
        self._ensure_column_exists("alerts", "occurrence_count", "INTEGER DEFAULT 1")
        self._ensure_column_exists("alerts", "first_seen", "REAL")
        self._ensure_column_exists("alerts", "last_seen", "REAL")
        self._ensure_column_exists("alerts", "suppression_reason", "TEXT")
        self._ensure_column_exists("alerts", "policy_context", "TEXT")
        self._ensure_column_exists("ai_approvals", "requester", "TEXT DEFAULT 'local-operator'")
        for table in ("alerts", "flows"):
            self._ensure_column_exists(table, "capture_session_id", "TEXT")
            self._ensure_column_exists(table, "capture_interface", "TEXT")
            self._ensure_column_exists(table, "capture_backend", "TEXT")
            self._ensure_column_exists(table, "capture_type", "TEXT DEFAULT 'network'")
            self._ensure_column_exists(table, "sensor_node_id", "TEXT")
        self._ensure_column_exists("capture_sessions", "sensor_node_id", "TEXT")
        self._ensure_column_exists("endpoint_identities", "sensor_node_id", "TEXT")
        self._ensure_column_exists("endpoint_identities", "identity_state", "TEXT DEFAULT 'address_only'")
        self._ensure_column_exists("endpoint_identities", "evidence_completeness", "REAL DEFAULT 0.0")
        self._ensure_column_exists("endpoint_identities", "next_action", "TEXT")
        self._ensure_column_exists("endpoint_identities", "observation_count", "INTEGER DEFAULT 0")
        for column, col_type in {
            "analyst_version": "TEXT DEFAULT 'agentic-v2'",
            "rounds": "INTEGER DEFAULT 0",
            "tool_call_count": "INTEGER DEFAULT 0",
            "context_chars": "INTEGER DEFAULT 0",
            "citation_coverage": "REAL DEFAULT 0.0",
            "redundant_tool_calls": "INTEGER DEFAULT 0",
            "mode": "TEXT DEFAULT 'investigate'",
            "validation_status": "TEXT DEFAULT 'not_run'",
            "supported_claims": "INTEGER DEFAULT 0",
            "inferred_claims": "INTEGER DEFAULT 0",
            "blocked_claims": "INTEGER DEFAULT 0",
            "numeric_accuracy": "REAL DEFAULT 1.0",
        }.items():
            self._ensure_column_exists("ai_runs", column, col_type)
        self._ensure_column_exists("hardware_observations", "sensor_node_id", "TEXT")
        self._ensure_column_exists("hardware_observations", "ingest_token", "TEXT")
        for column, col_type in {
            "next_attempt_at": "REAL",
            "lease_owner": "TEXT",
            "lease_expires_at": "REAL",
            "dead_lettered_at": "REAL",
        }.items():
            self._ensure_column_exists("graph_outbox", column, col_type)
        self._ensure_column_exists("detection_findings", "sensor_node_id", "TEXT")
        self._ensure_column_exists("risk_snapshots", "sensor_node_id", "TEXT")
        self._ensure_column_exists("carved_files", "capture_session_id", "TEXT")
        self._ensure_column_exists("carved_files", "sensor_node_id", "TEXT")
        self._ensure_column_exists("forensic_reports", "status", "TEXT DEFAULT 'RUNNING'")
        self._ensure_column_exists("forensic_reports", "analysis_mode", "TEXT DEFAULT 'memory'")
        self._ensure_column_exists("forensic_reports", "backend", "TEXT DEFAULT 'python'")
        self._ensure_column_exists("forensic_reports", "bytes_processed", "INTEGER DEFAULT 0")
        self._ensure_column_exists("forensic_reports", "total_bytes", "INTEGER DEFAULT 0")
        self._ensure_column_exists("forensic_reports", "error", "TEXT")
        self._ensure_column_exists("forensic_reports", "completed_at", "REAL")
        self._ensure_column_exists("forensic_reports", "spool_path", "TEXT")
        forensic_case_columns = {
            "filename": "TEXT",
            "byte_count": "INTEGER DEFAULT 0",
            "capture_started_at": "REAL",
            "capture_ended_at": "REAL",
            "link_type": "TEXT",
            "parser_version": "TEXT",
            "backend": "TEXT",
            "backend_version": "TEXT",
            "state": "TEXT DEFAULT 'created'",
            "progress": "REAL DEFAULT 0.0",
            "warnings_json": "TEXT DEFAULT '[]'",
            "visibility_limitations_json": "TEXT DEFAULT '[]'",
            "report_hash": "TEXT",
            "retained_input": "BOOLEAN DEFAULT 0",
            "retention_mode": "TEXT DEFAULT 'discard'",
            "encryption_format": "TEXT",
            "configuration_hash": "TEXT",
            "pipeline_version": "TEXT",
            "created_at": "REAL DEFAULT 0",
            "completed_at": "REAL",
        }
        for column, column_type in forensic_case_columns.items():
            self._ensure_column_exists("forensic_cases", column, column_type)
        self._ensure_column_exists(
            "forensic_analysis_revisions",
            "visibility_limitations_json",
            "TEXT DEFAULT '[]'",
        )
        self._ensure_column_exists(
            "forensic_analysis_revisions",
            "evidence_components_json",
            "TEXT DEFAULT '{}'",
        )
        pcap_job_columns = {
            "filename": "TEXT",
            "file_size": "INTEGER DEFAULT 0",
            "mode": "TEXT DEFAULT 'auto'",
            "backend": "TEXT DEFAULT 'python'",
            "source": "TEXT",
            "status": "TEXT DEFAULT 'queued'",
            "report_id": "INTEGER",
            "created_at": "REAL DEFAULT 0",
            "started_at": "REAL",
            "completed_at": "REAL",
            "bytes_processed": "INTEGER DEFAULT 0",
            "progress": "REAL DEFAULT 0.0",
            "summary_json": "TEXT DEFAULT '{}'",
            "error": "TEXT",
            "retained_input": "BOOLEAN DEFAULT 0",
            "input_path": "TEXT",
            "keylog_path": "TEXT",
            "case_id": "TEXT",
            "analysis_id": "TEXT",
            "pcap_sha256": "TEXT",
            "capture_started_at": "REAL",
            "capture_ended_at": "REAL",
            "link_type": "TEXT",
            "parser_version": "TEXT",
            "backend_version": "TEXT",
            "configuration_hash": "TEXT",
            "pipeline_version": "TEXT",
            "retention_mode": "TEXT DEFAULT 'discard'",
            "encryption_format": "TEXT",
        }
        for column, column_type in pcap_job_columns.items():
            self._ensure_column_exists("pcap_analysis_jobs", column, column_type)
        self._ensure_column_exists("detection_findings", "evidence_refs_json", "TEXT DEFAULT '[]'")
        self._sanitize_existing_entity_identities()
        self._sanitize_existing_flow_metadata()
        capture_columns = {
            "processed_packets": "INTEGER DEFAULT 0",
            "detector_errors": "INTEGER DEFAULT 0",
            "evidence_dropped": "INTEGER DEFAULT 0",
            "snapshot_dropped": "INTEGER DEFAULT 0",
            "pending_packets": "INTEGER DEFAULT 0",
            "queue_depth_high_watermark": "INTEGER DEFAULT 0",
            "queue_lag_ms": "REAL DEFAULT 0.0",
            "queue_lag_max_ms": "REAL DEFAULT 0.0",
            "processing_state": "TEXT DEFAULT 'running'",
            "complete": "BOOLEAN DEFAULT 0",
            "completion_reason": "TEXT",
            "daemon_instance_id": "TEXT",
            "last_heartbeat_at": "REAL",
            "shutdown_stage": "TEXT DEFAULT 'capturing'",
            "worker_acknowledged": "BOOLEAN DEFAULT 0",
            "evidence_acknowledged": "BOOLEAN DEFAULT 0",
            "persisted_generation": "INTEGER DEFAULT 0",
            "process_exit_outcome": "TEXT",
        }
        for column, column_type in capture_columns.items():
            self._ensure_column_exists("capture_sessions", column, column_type)
        self._normalize_legacy_capture_sessions()
        self._publish_local_sensor_node_id(
            self._ensure_local_sensor_node_id()
        )

        # Create the missing unique constraint on flows if it doesn't exist
        # SQLite doesn't support ADD CONSTRAINT well, so we use a UNIQUE INDEX
        self._ensure_unique_index("flows", "idx_flow_unique", ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "source"])
        self._record_schema_migration("behavioral-v2-001", "contracts-findings-windows-snapshots-baselines-dispositions")
        self._record_schema_migration("behavioral-v2-002", "structured-evidence-references-and-central-redaction")
        self._record_schema_migration("pipeline-v2-001", "capture-processing-stage-telemetry-and-completeness")
        self._record_schema_migration("identity-v2-001", "versioned-endpoint-identity-projections")
        self._record_schema_migration("identity-v2-002", "identity-observation-ledger-and-truth-states")
        self._record_schema_migration("ai-v2-002", "bounded-iterative-evidence-runs")
        self._record_schema_migration("ai-v2-003", "scoped-modes-native-transcripts-and-claim-validation")
        self._record_schema_migration("endpoint-v1-001", "durable-sysmon-process-service-observations")
        self._record_schema_migration("mesh-v1-001", "sensor-nodes-enrollment-idempotent-telemetry-and-commands")
        self._record_schema_migration("graph-v1-001", "durable-neo4j-evidence-graph-outbox")
        self._record_schema_migration("trust-v1-001", "operator-webauthn-pin-absolute-sessions-and-audit")
        self._record_schema_migration("ai-provider-v2-001", "provider-model-cache-and-session-scoped-private-consent")
        self._record_schema_migration("pcap-v2-001", "durable-pcap-analysis-jobs")
        self._record_schema_migration("offline-case-v1-001", "case-scoped offline forensic storage contracts")
        self._record_schema_migration(
            "forensic-retention-v2-001",
            "content-addressed analysis revisions and AES-GCM evidence metadata",
        )
        self._record_schema_migration(
            "offline-index-v1-001",
            "immutable rust-origin parquet packet indexes and manifests",
        )
        self._backfill_forensic_packet_index_components()
        self._rebuild_v21_snapshots()

    def _ensure_local_sensor_node_id(self) -> str:
        """Give historical local records an immutable node boundary without rewriting data."""
        session = self._get_session()
        row = session.query(SystemMetadata).filter_by(key="mesh.local_node_id").first()
        if row is None:
            row = SystemMetadata(key="mesh.local_node_id", value=f"local-{uuid.uuid4()}")
            session.add(row)
            session.commit()
        node_id = row.value
        if session.query(SensorNode).filter_by(id=node_id).first() is None:
            import socket
            session.add(SensorNode(
                id=node_id, name=f"local-{socket.gethostname() or 'watchtower'}",
                status="local", platform=platform.platform(), agent_version="local",
                capabilities_json=json.dumps({"capture": True, "endpoint_telemetry": os.name == "nt"}, sort_keys=True),
                health_json="{}", created_at=time.time(), last_seen_at=time.time(),
            ))
        for table in (Flow, Alert, CaptureSession, EndpointIdentity, HardwareObservation, DetectionFinding, RiskSnapshot, CarvedFile):
            session.query(table).filter(getattr(table, "sensor_node_id").is_(None)).update(
                {"sensor_node_id": node_id}, synchronize_session=False,
            )
        session.commit()
        return node_id

    def _local_sensor_cache_key(self) -> str:
        return os.path.normcase(str(self.db_path.resolve()))

    def _publish_local_sensor_node_id(self, node_id: str) -> str:
        node_id = str(node_id)
        with self._local_sensor_cache_lock:
            self._local_sensor_ids[self._local_sensor_cache_key()] = node_id
        self._local_sensor_node_id = node_id
        return node_id

    def local_sensor_node_id(self) -> str:
        with self._local_sensor_cache_lock:
            node_id = self._local_sensor_ids.get(
                self._local_sensor_cache_key()
            )
        if node_id:
            self._local_sensor_node_id = node_id
            return node_id
        return self._publish_local_sensor_node_id(
            self.get_metadata("mesh.local_node_id")
            or self._ensure_local_sensor_node_id()
        )

    def _rebuild_v21_snapshots(self) -> None:
        """Materialize V2.1 snapshots once so existing databases remain visible after upgrade."""
        version = "behavioral-v2.1-001"
        session = self._get_session()
        if session.query(SchemaMigration).filter_by(version=version).first() is not None:
            return
        subjects = [value for (value,) in session.query(DetectionFinding.subject).distinct().all() if value]
        try:
            for subject in subjects:
                entity = session.query(Entity).filter_by(ip=subject).first()
                asset_role = getattr(entity, "asset_role", None)
                rows = session.query(
                    DetectionFinding.source, DetectionFinding.capture_interface,
                    DetectionFinding.capture_session_id,
                ).filter(DetectionFinding.subject == subject).distinct().all()
                self.recompute_risk(subject, asset_role=asset_role, persist=True)
                for source in sorted({row.source for row in rows if row.source}):
                    self.recompute_risk(subject, source=source, asset_role=asset_role, persist=True)
                if any(str(row.source or "").startswith("live") for row in rows):
                    self.recompute_risk(subject, source="live", asset_role=asset_role, persist=True)
                for interface in sorted({row.capture_interface for row in rows if row.capture_interface}):
                    self.recompute_risk(subject, interface=interface, asset_role=asset_role, persist=True)
                for row in rows:
                    if row.capture_session_id:
                        self.recompute_risk(
                            subject, source=row.source, interface=row.capture_interface,
                            capture_session_id=row.capture_session_id,
                            asset_role=asset_role, persist=True,
                        )
        except Exception:
            logger.exception("Unable to rebuild behavioral-v2.1 risk snapshots")
            return
        self._record_schema_migration(version, "recompute-existing-findings-with-reviewed-per-finding-calibration")

    def _normalize_legacy_capture_sessions(self) -> None:
        """Make pre-telemetry stopped sessions explicitly partial instead of apparently live."""
        session = self._get_session()
        rows = session.query(CaptureSession).filter(
            CaptureSession.status != "RUNNING",
            CaptureSession.processing_state == "running",
        ).all()
        for row in rows:
            row.processing_state = "partial"
            row.complete = False
            row.pending_packets = max(
                int(row.pending_packets or 0),
                max(0, int(row.emitted_packets or 0) - int(row.processed_packets or 0)),
            )
            row.completion_reason = row.completion_reason or "legacy_session_without_processing_ack"
        if rows:
            session.commit()

    def _sanitize_existing_entity_identities(self) -> None:
        from core.forensics.identity import sanitize_identity_value

        session = self._get_session()
        changed = False
        for row in session.query(Entity).filter(
            or_(Entity.username.is_not(None), Entity.full_name.is_not(None))
        ).all():
            for field in ("username", "full_name"):
                current = getattr(row, field)
                sanitized = sanitize_identity_value(field, current)
                if sanitized != current:
                    setattr(row, field, sanitized)
                    changed = True
        if changed:
            session.commit()

    def _sanitize_existing_flow_metadata(self) -> None:
        """Apply central redaction once to flow metadata created before V2."""
        version = "behavioral-v2-003"
        session = self._get_session()
        if session.query(SchemaMigration).filter_by(version=version).first() is not None:
            return
        changed = False
        for row in session.query(Flow).filter(Flow.l7_metadata.is_not(None)).all():
            try:
                current = json.loads(row.l7_metadata) if isinstance(row.l7_metadata, str) else row.l7_metadata
            except (TypeError, ValueError):
                current = {}
            encoded = json.dumps(self._sanitize_flow_metadata(current), sort_keys=True)
            if encoded != row.l7_metadata:
                row.l7_metadata = encoded
                changed = True
        if changed:
            session.commit()
        self._record_schema_migration(version, "redact-legacy-flow-identities-and-sensitive-fields")

    @staticmethod
    def _sanitize_flow_metadata(metadata: Dict) -> Dict:
        from core.detection.contracts import sanitize_evidence
        from core.forensics.identity import sanitize_identity_value

        sanitized = sanitize_evidence(metadata if isinstance(metadata, dict) else {})
        for field in ("username", "full_name", "local_hostname", "netbios_name"):
            if field in sanitized and isinstance(sanitized[field], str):
                sanitized[field] = sanitize_identity_value(field, sanitized[field])
        return sanitized

    def _record_schema_migration(self, version: str, description: str) -> None:
        session = self._get_session()
        if session.query(SchemaMigration).filter_by(version=version).first() is None:
            session.add(SchemaMigration(
                version=version, applied_at=time.time(),
                checksum=sha256(description.encode("utf-8")).hexdigest(),
            ))
            session.commit()

    def _ensure_unique_index(self, table: str, index_name: str, columns: list[str]):
        """Ensure a unique index exists on the specified columns."""
        from sqlalchemy import text
        cached = getattr(self, "_schema_indexes_cache", {}).get(table)
        if cached is not None and index_name in cached:
            return
        cols_str = ", ".join(columns)
        try:
            with self.engine.connect() as conn:
                # Check if index exists
                cursor = conn.execute(text(f"PRAGMA index_list({table})"))
                indices = [row[1] for row in cursor]
                if index_name not in indices:
                    logger.info(f"Schema update: creating unique index {index_name} on {table}")
                    conn.execute(text(f"CREATE UNIQUE INDEX {index_name} ON {table} ({cols_str})"))
                    conn.commit()
                    if cached is not None:
                        cached.add(index_name)
        except Exception as e:
            logger.debug(f"Index creation failed for {table}.{index_name}: {e}")

    def _ensure_column_exists(self, table: str, column: str, col_type: str):
        """Safe utility to add a column if it doesn't exist."""
        from sqlalchemy import text
        cached = getattr(self, "_schema_columns_cache", {}).get(table)
        if cached is not None and column in cached:
            return
        try:
            with self.engine.connect() as conn:
                cursor = conn.execute(text(f"PRAGMA table_info({table})"))
                existing = [row[1] for row in cursor]
                if column not in existing:
                    logger.info(f"Schema update: adding {column} to {table}")
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                    conn.commit()
                    if cached is not None:
                        cached.add(column)
        except Exception as e:
            logger.debug(f"Column check skipped for {table}.{column}: {e}")

    def _get_session(self):
        """Get the current scoped session."""
        return self.Session()

    @contextmanager
    def session_scope(self, *, write: bool = False):
        """Yield a short-lived session for direct repository operations."""
        session = self.session_factory()
        try:
            yield session
            if write:
                session.commit()
        except Exception:
            if write:
                session.rollback()
            raise
        finally:
            session.close()

    def pool_status(self) -> Dict[str, Any]:
        pool = self.engine.pool
        checked_out = int(pool.checkedout())
        return {
            **self._pool_metrics,
            "size": int(pool.size()),
            "checked_out": checked_out,
            "checked_in": int(pool.checkedin()),
            "overflow": int(pool.overflow()),
            "capacity": int(pool.size()) + 16,
        }

    def begin_scope(self, scope_id: str):
        """Bind operations in the current request to one removable session."""
        return _database_scope.set((id(self), str(scope_id)))

    def end_scope(self, token) -> None:
        """Rollback unfinished work and release the scoped connection."""
        try:
            session = self.Session()
            if session.in_transaction():
                session.rollback()
        finally:
            self.Session.remove()
            _database_scope.reset(token)

    def commit(self):
        """Commit the current session transaction."""
        self.Session.commit()

    def rollback(self):
        """Rollback the current session transaction."""
        self.Session.rollback()

    def remove(self):
        """Remove the current scoped session."""
        self.Session.remove()

    # ----------------------------------------------------------------
    # Entity Operations
    # ----------------------------------------------------------------

    def upsert_entity(self, ip: str = None, **kwargs):
        """Deprecated: Use bulk_upsert_entities for performance."""
        if ip: kwargs["ip"] = ip
        return self.bulk_upsert_entities([kwargs])

    # ----------------------------------------------------------------
    # Capture Session Operations
    # ----------------------------------------------------------------

    def create_capture_session(self, session_id: str, source_type: str, device_id: str,
                               backend: str, link_type: str = "ethernet",
                               source: str = None, metadata: Dict = None,
                               sensor_node_id: str = None,
                               daemon_instance_id: str = None) -> Dict:
        session = self._get_session()
        row = CaptureSession(
            id=session_id,
            source_type=source_type,
            device_id=device_id,
            interface=device_id if source_type == "network" else None,
            backend=backend,
            link_type=link_type,
            source=source or f"live_{device_id}",
            sensor_node_id=sensor_node_id or self.local_sensor_node_id(),
            started_at=time.time(),
            status="RUNNING",
            processing_state="running",
            complete=False,
            metadata_json=json.dumps(metadata or {}, sort_keys=True),
            daemon_instance_id=daemon_instance_id,
            last_heartbeat_at=time.time(),
            shutdown_stage="capturing",
            completion_reason=None,
            error=None,
            worker_acknowledged=False,
            evidence_acknowledged=False,
            persisted_generation=0,
            process_exit_outcome=None,
        )
        session.add(row)
        session.commit()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    def update_capture_session_state(self, session_id: str, processing_state: str,
                                     metrics: Dict = None, reason: str = None) -> None:
        session = self._get_session()
        row = session.query(CaptureSession).filter_by(id=session_id).first()
        if not row:
            return
        row.processing_state = processing_state
        row.completion_reason = reason
        row.last_heartbeat_at = time.time()
        row.shutdown_stage = processing_state
        for key in (
            "received_packets", "emitted_packets", "dropped_packets", "queue_full_events",
            "processed_packets", "detector_errors", "evidence_dropped", "snapshot_dropped",
            "pending_packets", "queue_depth_high_watermark", "queue_lag_ms", "queue_lag_max_ms",
        ):
            if metrics and key in metrics:
                converter = float if key in {"queue_lag_ms", "queue_lag_max_ms"} else int
                setattr(row, key, converter(metrics[key]))
        session.commit()

    def finish_capture_session(self, session_id: str, status: str = "STOPPED",
                               metrics: Dict = None, error: str = None,
                               processing_state: str = None,
                               completion_reason: str = None) -> None:
        session = self._get_session()
        row = session.query(CaptureSession).filter_by(id=session_id).first()
        if not row:
            return
        metrics = metrics or {}
        row.ended_at = time.time()
        row.status = status
        row.received_packets = int(metrics.get("received_packets", row.received_packets or 0))
        row.emitted_packets = int(metrics.get("emitted_packets", row.emitted_packets or 0))
        row.dropped_packets = int(metrics.get("dropped_packets", row.dropped_packets or 0))
        row.queue_full_events = int(metrics.get("queue_full_events", row.queue_full_events or 0))
        row.processed_packets = int(metrics.get("processed_packets", row.processed_packets or 0))
        row.detector_errors = int(metrics.get("detector_errors", row.detector_errors or 0))
        row.evidence_dropped = int(metrics.get("evidence_dropped", row.evidence_dropped or 0))
        row.snapshot_dropped = int(metrics.get("snapshot_dropped", row.snapshot_dropped or 0))
        row.pending_packets = int(metrics.get("pending_packets", max(0, row.emitted_packets - row.processed_packets)))
        row.queue_depth_high_watermark = int(metrics.get("queue_depth_high_watermark", row.queue_depth_high_watermark or 0))
        row.queue_lag_ms = float(metrics.get("queue_lag_ms", row.queue_lag_ms or 0.0))
        row.queue_lag_max_ms = float(metrics.get("queue_lag_max_ms", row.queue_lag_max_ms or 0.0))
        completed = row.pending_packets == 0 and error is None and processing_state not in {"partial", "failed"}
        row.processing_state = processing_state or ("complete" if completed else "partial")
        row.complete = bool(completed and row.processing_state == "complete")
        row.completion_reason = completion_reason or ("drained" if row.complete else "unprocessed_packets")
        row.error = error
        row.shutdown_stage = "finished"
        session.commit()

    def acknowledge_capture_stage(self, session_id: str, stage: str, *,
                                  persisted_generation: int = None,
                                  process_exit_outcome: str = None) -> Optional[Dict]:
        session = self._get_session()
        row = session.query(CaptureSession).filter_by(id=session_id).first()
        if row is None:
            return None
        if stage == "worker":
            row.worker_acknowledged = True
            row.shutdown_stage = "worker_persisted"
        elif stage == "evidence":
            row.evidence_acknowledged = True
            row.shutdown_stage = "evidence_persisted"
        else:
            row.shutdown_stage = str(stage)
        if persisted_generation is not None:
            row.persisted_generation = max(
                int(row.persisted_generation or 0), int(persisted_generation),
            )
        if process_exit_outcome is not None:
            row.process_exit_outcome = str(process_exit_outcome)
        row.last_heartbeat_at = time.time()
        session.commit()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    def reconcile_orphaned_capture_sessions(self, daemon_instance_id: str) -> int:
        session = self._get_session()
        rows = session.query(CaptureSession).filter(
            CaptureSession.processing_state.in_(("running", "draining")),
            or_(
                CaptureSession.daemon_instance_id.is_(None),
                CaptureSession.daemon_instance_id != daemon_instance_id,
            ),
        ).all()
        now = time.time()
        for row in rows:
            row.status = "STOPPED"
            row.processing_state = "partial"
            row.complete = False
            row.ended_at = row.ended_at or now
            row.pending_packets = max(
                int(row.pending_packets or 0),
                max(0, int(row.emitted_packets or 0) - int(row.processed_packets or 0)),
            )
            row.completion_reason = "daemon_restart_before_processing_ack"
            row.error = row.completion_reason
            row.shutdown_stage = "orphan_reconciled"
            row.process_exit_outcome = "previous_daemon_unavailable"
        if rows:
            session.commit()
        return len(rows)

    def get_capture_sessions(self, interface: str = None, limit: int = 100,
                             sensor_node_id: str = None) -> List[Dict]:
        session = self._get_session()
        query = session.query(CaptureSession)
        if interface:
            query = query.filter_by(interface=interface)
        if sensor_node_id:
            query = query.filter(CaptureSession.sensor_node_id == sensor_node_id)
        rows = query.order_by(CaptureSession.started_at.desc()).limit(limit).all()
        return [{column.name: getattr(row, column.name) for column in row.__table__.columns} for row in rows]

    def get_capture_session(self, session_id: str) -> Optional[Dict]:
        session = self._get_session()
        row = session.query(CaptureSession).filter_by(id=session_id).first()
        if row is None:
            return None
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    def upsert_mesh_capture_sessions(self, sessions: List[Dict], sensor_node_id: str) -> int:
        """Upsert immutable remote session metadata before its flow telemetry arrives."""
        if not sessions:
            return 0
        session = self._get_session()
        count = 0
        for item in sessions[:500]:
            value = dict(item)
            session_id = str(value.get("id") or "")
            if not session_id:
                continue
            row = session.query(CaptureSession).filter_by(id=session_id).first()
            source = str(value.get("source") or "live")
            source = source if source.startswith(f"mesh:{sensor_node_id}:") else f"mesh:{sensor_node_id}:{source}"
            fields = {
                "source_type": str(value.get("source_type") or "network"),
                "device_id": str(value.get("device_id") or value.get("interface") or "remote"),
                "interface": value.get("interface"), "backend": str(value.get("backend") or "python"),
                "link_type": str(value.get("link_type") or "ethernet"), "source": source,
                "sensor_node_id": sensor_node_id, "started_at": float(value.get("started_at") or time.time()),
                "ended_at": value.get("ended_at"), "status": str(value.get("status") or "RUNNING"),
                "processing_state": str(value.get("processing_state") or "running"),
                "complete": bool(value.get("complete") or False), "completion_reason": value.get("completion_reason"),
                "error": value.get("error"), "metadata_json": json.dumps(value.get("metadata") or {}, sort_keys=True),
            }
            for name in ("received_packets", "emitted_packets", "dropped_packets", "queue_full_events", "processed_packets", "detector_errors", "evidence_dropped", "snapshot_dropped", "pending_packets", "queue_depth_high_watermark"):
                fields[name] = int(value.get(name) or 0)
            for name in ("queue_lag_ms", "queue_lag_max_ms"):
                fields[name] = float(value.get(name) or 0.0)
            if row is None:
                row = CaptureSession(id=session_id, **fields)
                session.add(row)
            else:
                for name, field_value in fields.items():
                    setattr(row, name, field_value)
            count += 1
        session.commit()
        return count

    # ------------------------------------------------------------------
    # Agentic analyst audit persistence. Records are redacted by callers
    # before reaching this layer; these helpers never retain packet data.
    # ------------------------------------------------------------------

    @staticmethod
    def _row_dict(row) -> Dict:
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    @staticmethod
    def _json_field(value: Any, fallback: Any) -> Any:
        empty = dict(fallback) if isinstance(fallback, dict) else list(fallback) if isinstance(fallback, list) else fallback
        if value in (None, ""):
            return empty
        if isinstance(value, (dict, list)):
            return value
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, type(fallback)) else empty
        except (TypeError, ValueError, json.JSONDecodeError):
            return empty

    @staticmethod
    def _encode_storage_cursor(payload: Dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_storage_cursor(cursor: Any) -> Dict[str, Any]:
        if cursor in (None, "", 0, "0"):
            return {}
        try:
            padding = "=" * (-len(str(cursor)) % 4)
            value = json.loads(base64.urlsafe_b64decode(str(cursor) + padding).decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("invalid case storage cursor")

    def _forensic_case_dict(self, row: ForensicCase) -> Dict[str, Any]:
        item = self._row_dict(row)
        item["warnings"] = self._json_field(item.pop("warnings_json", None), [])
        item["visibility_limitations"] = self._json_field(item.pop("visibility_limitations_json", None), [])
        return item

    def _forensic_revision_dict(self, row: ForensicAnalysisRevision) -> Dict[str, Any]:
        item = self._row_dict(row)
        item["visibility_limitations"] = self._json_field(
            item.pop("visibility_limitations_json", None),
            [],
        )
        item["evidence_components"] = self._json_field(
            item.pop("evidence_components_json", None),
            {},
        )
        return item

    def _forensic_envelope_dict(self, row: ForensicEvidenceEnvelope) -> Dict[str, Any]:
        return self._row_dict(row)

    def _forensic_case_entity_dict(self, row: ForensicCaseEntity) -> Dict[str, Any]:
        item = self._row_dict(row)
        item["provenance"] = self._json_field(item.pop("provenance_json", None), {})
        return item

    def _forensic_custody_dict(self, row: ForensicCaseCustodyEvent) -> Dict[str, Any]:
        item = self._row_dict(row)
        item["metadata"] = self._json_field(item.pop("metadata_json", None), {})
        return item

    def _forensic_triage_flag_dict(self, row: ForensicTriageFlag) -> Dict[str, Any]:
        item = self._row_dict(row)
        item["finding_ids"] = self._json_field(item.pop("finding_ids_json", None), [])
        item["evidence_refs"] = self._json_field(item.pop("evidence_refs_json", None), [])
        item["observed_values"] = self._json_field(item.pop("observed_values_json", None), {})
        return item

    @staticmethod
    def _triage_status_rank(status: str) -> int:
        return {
            "open": 0,
            "confirmed": 1,
            "benign": 2,
            "dismissed": 3,
        }.get(str(status or "").lower(), 4)

    def create_ai_conversation(self, conversation_id: str, title: str, provider: str, scope: Dict) -> Dict:
        session = self._get_session()
        now = time.time()
        row = AIConversation(id=conversation_id, title=title[:256] or "New investigation", provider=provider,
                             scope_json=json.dumps(scope or {}, sort_keys=True), created_at=now, updated_at=now)
        try:
            session.add(row)
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def list_ai_conversations(self, limit: int = 100, include_archived: bool = False) -> List[Dict]:
        session = self._get_session()
        try:
            query = session.query(AIConversation)
            if not include_archived:
                query = query.filter_by(archived=False)
            return [self._row_dict(row) for row in query.order_by(AIConversation.updated_at.desc()).limit(limit).all()]
        finally:
            self.Session.remove()

    def get_ai_conversation(self, conversation_id: str, include_messages: bool = True) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIConversation).filter_by(id=conversation_id).first()
            if not row:
                return None
            result = self._row_dict(row)
            result["scope"] = json.loads(result.pop("scope_json") or "{}")
            if include_messages:
                messages = session.query(AIMessage).filter_by(conversation_id=conversation_id).order_by(AIMessage.created_at.asc()).all()
                result["messages"] = [self._row_dict(item) for item in messages]
                for item in result["messages"]:
                    item["citations"] = json.loads(item.pop("citations_json") or "[]")
            return result
        finally:
            self.Session.remove()

    def delete_ai_conversation(self, conversation_id: str) -> bool:
        session = self._get_session()
        try:
            row = session.query(AIConversation).filter_by(id=conversation_id).first()
            if not row:
                return False
            run_ids = [item[0] for item in session.query(AIRun.id).filter_by(conversation_id=conversation_id).all()]
            if run_ids:
                invocation_ids = [item[0] for item in session.query(AIToolInvocation.id)
                                  .filter(AIToolInvocation.run_id.in_(run_ids)).all()]
                session.query(AICitation).filter(AICitation.run_id.in_(run_ids)).delete(synchronize_session=False)
                session.query(AIApproval).filter(AIApproval.run_id.in_(run_ids)).delete(synchronize_session=False)
                if invocation_ids:
                    session.query(AIApproval).filter(AIApproval.invocation_id.in_(invocation_ids)).delete(synchronize_session=False)
                session.query(AIToolInvocation).filter(AIToolInvocation.run_id.in_(run_ids)).delete(synchronize_session=False)
                session.query(AIEvidenceFact).filter(AIEvidenceFact.run_id.in_(run_ids)).delete(synchronize_session=False)
                session.query(AIRun).filter(AIRun.id.in_(run_ids)).delete(synchronize_session=False)
            session.query(AIMessage).filter_by(conversation_id=conversation_id).delete(synchronize_session=False)
            session.delete(row)
            session.commit()
            return True
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def append_ai_message(self, message_id: str, conversation_id: str, role: str, content: str,
                          citations: List[Dict] = None, run_id: str = None) -> Dict:
        session = self._get_session()
        try:
            row = AIMessage(id=message_id, conversation_id=conversation_id, run_id=run_id, role=role,
                            content=content, citations_json=json.dumps(citations or [], sort_keys=True), created_at=time.time())
            session.add(row)
            session.query(AIConversation).filter_by(id=conversation_id).update({"updated_at": time.time()})
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def create_ai_run(self, run_id: str, conversation_id: str, provider: str, prompt_hash: str,
                      scope: Dict, policy: Dict) -> Dict:
        session = self._get_session()
        now = time.time()
        try:
            row = AIRun(id=run_id, conversation_id=conversation_id, provider=provider, status="QUEUED",
                        prompt_hash=prompt_hash, scope_json=json.dumps(scope or {}, sort_keys=True),
                        policy_json=json.dumps(policy or {}, sort_keys=True), mode=str((policy or {}).get("mode") or "investigate"),
                        created_at=now, updated_at=now)
            session.add(row)
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def update_ai_run(self, run_id: str, status: str, final_text: str = None, error: str = None,
                      metrics: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIRun).filter_by(id=run_id).first()
            if not row:
                return None
            row.status, row.updated_at = status, time.time()
            if final_text is not None:
                row.final_text = final_text
            if error is not None:
                row.error = error
            for field in ("analyst_version", "rounds", "tool_call_count", "redundant_tool_calls", "context_chars", "citation_coverage",
                          "mode", "validation_status", "supported_claims", "inferred_claims", "blocked_claims", "numeric_accuracy"):
                if metrics and field in metrics and hasattr(row, field):
                    setattr(row, field, metrics[field])
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def get_ai_run(self, run_id: str) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIRun).filter_by(id=run_id).first()
            if not row:
                return None
            result = self._row_dict(row)
            result["scope"] = json.loads(result.pop("scope_json") or "{}")
            result["policy"] = json.loads(result.pop("policy_json") or "{}")
            result["tool_calls"] = [self._row_dict(item) for item in session.query(AIToolInvocation).filter_by(run_id=run_id).order_by(AIToolInvocation.created_at.asc()).all()]
            result["approvals"] = [self._row_dict(item) for item in session.query(AIApproval).filter_by(run_id=run_id).all()]
            result["citations"] = [self._row_dict(item) for item in session.query(AICitation).filter_by(run_id=run_id).all()]
            result["facts"] = [self._ai_fact_dict(item) for item in session.query(AIEvidenceFact).filter_by(run_id=run_id).order_by(AIEvidenceFact.created_at.asc()).all()]
            return result
        finally:
            self.Session.remove()

    def create_ai_tool_invocation(self, invocation_id: str, run_id: str, tool_name: str, risk_tier: str,
                                  arguments: Dict, status: str = "REQUESTED") -> Dict:
        session = self._get_session()
        now = time.time()
        try:
            row = AIToolInvocation(id=invocation_id, run_id=run_id, tool_name=tool_name, risk_tier=risk_tier,
                                   status=status, arguments_json=json.dumps(arguments or {}, sort_keys=True), created_at=now, updated_at=now)
            session.add(row)
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def complete_ai_tool_invocation(self, invocation_id: str, status: str, result: Dict = None) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIToolInvocation).filter_by(id=invocation_id).first()
            if not row:
                return None
            payload = json.dumps(result or {}, sort_keys=True, default=str)
            row.status, row.result_json, row.result_hash, row.updated_at = status, payload, sha256(payload.encode("utf-8")).hexdigest(), time.time()
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    @staticmethod
    def _ai_fact_dict(row: AIEvidenceFact) -> Dict[str, Any]:
        item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        for field, default in (("value_json", None), ("scope_json", {}), ("citations_json", [])):
            target = field[:-5] if field.endswith("_json") else field
            try:
                item[target] = json.loads(item.pop(field) or json.dumps(default))
            except (TypeError, ValueError, json.JSONDecodeError):
                item[target] = default
        return item

    def add_ai_facts(self, run_id: str, facts: List[Dict]) -> None:
        """Persist normalized facts idempotently for a run."""
        if not facts:
            return
        session = self._get_session()
        try:
            for fact in facts[:2000]:
                fact_id = str(fact.get("fact_id") or "")
                if not fact_id:
                    continue
                row = session.query(AIEvidenceFact).filter_by(run_id=run_id, fact_id=fact_id).first()
                if row is None:
                    row = AIEvidenceFact(id=str(uuid.uuid4()), run_id=run_id, fact_id=fact_id,
                                         subject=str(fact.get("subject") or "unknown"),
                                         predicate=str(fact.get("predicate") or "unknown"),
                                         value_json=json.dumps(fact.get("value"), sort_keys=True, default=str),
                                         confidence=float(fact.get("confidence", 1.0) or 0.0),
                                         completeness=str(fact.get("completeness") or "complete"),
                                         freshness=fact.get("freshness"),
                                         scope_json=json.dumps(fact.get("scope") or {}, sort_keys=True),
                                         citations_json=json.dumps(fact.get("citations") or [], sort_keys=True, default=str),
                                         created_at=time.time())
                    session.add(row)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def create_ai_approval(self, approval_id: str, run_id: str, invocation_id: str, tool_name: str, risk_tier: str,
                           arguments_hash: str, scope: Dict, confirmation_phrase: str, idempotency_key: str,
                           expires_at: float, requester: str = "local-operator") -> Dict:
        session = self._get_session()
        try:
            row = AIApproval(id=approval_id, run_id=run_id, invocation_id=invocation_id, tool_name=tool_name,
                             risk_tier=risk_tier, arguments_hash=arguments_hash, scope_json=json.dumps(scope or {}, sort_keys=True),
                             status="PENDING", requester=requester[:128] or "local-operator", confirmation_phrase=confirmation_phrase,
                             idempotency_key=idempotency_key,
                             requested_at=time.time(), expires_at=expires_at)
            session.add(row)
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def resolve_ai_approval(self, approval_id: str, status: str, result: Dict = None) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIApproval).filter_by(id=approval_id).first()
            if not row:
                return None
            row.status, row.resolved_at, row.result_json = status, time.time(), json.dumps(result or {}, sort_keys=True, default=str)
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def claim_ai_approval(self, approval_id: str) -> Optional[Dict]:
        """Atomically claim a pending approval before an action is executed."""
        session = self._get_session()
        try:
            claimed = session.query(AIApproval).filter_by(id=approval_id, status="PENDING").update(
                {"status": "APPROVING", "resolved_at": time.time()}, synchronize_session=False,
            )
            if not claimed:
                session.rollback()
                return None
            session.commit()
            row = session.query(AIApproval).filter_by(id=approval_id).first()
            return self._row_dict(row) if row else None
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def get_ai_approval(self, approval_id: str) -> Optional[Dict]:
        session = self._get_session()
        try:
            row = session.query(AIApproval).filter_by(id=approval_id).first()
            return self._row_dict(row) if row else None
        finally:
            self.Session.remove()

    def add_ai_citations(self, run_id: str, citations: List[Dict]) -> None:
        if not citations:
            return
        session = self._get_session()
        try:
            for item in citations:
                session.add(AICitation(id=item["id"], run_id=run_id, kind=item.get("kind", "watchtower"),
                                       reference=item.get("reference", ""), source=item.get("source", ""), url=item.get("url"),
                                       summary=item.get("summary", ""), observed_at=item.get("timestamp"),
                                       retrieved_at=item.get("retrieved_at"), content_hash=item.get("content_hash"),
                                       scope_json=json.dumps(item.get("scope") or {}, sort_keys=True)))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def cache_ai_research_document(self, document: Dict) -> Dict:
        session = self._get_session()
        try:
            row = session.query(AIResearchDocument).filter_by(canonical_url=document["canonical_url"]).first()
            if row is None:
                row = AIResearchDocument(id=document["id"], source_kind=document["source_kind"], canonical_url=document["canonical_url"],
                                         title=document.get("title"), summary=document["summary"], content_hash=document["content_hash"],
                                         retrieved_at=document["retrieved_at"], expires_at=document["expires_at"])
                session.add(row)
            else:
                for key in ("source_kind", "title", "summary", "content_hash", "retrieved_at", "expires_at"):
                    setattr(row, key, document.get(key, getattr(row, key)))
            session.commit()
            return self._row_dict(row)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def insert_hardware_observation(self, observation: Dict) -> int:
        session = self._get_session()
        try:
            row = HardwareObservation(
                capture_session_id=observation.get("capture_session_id"),
                timestamp=float(observation.get("timestamp") or time.time()),
                source_type=observation.get("source_type", "unknown"),
                device_id=observation.get("device_id"),
                sensor_node_id=observation.get("sensor_node_id") or self.local_sensor_node_id(),
                observation_type=observation.get("observation_type", "unknown"),
                subject=observation.get("subject", "unknown"),
                peer=observation.get("peer"),
                metadata_json=json.dumps(observation.get("metadata") or {}, sort_keys=True),
            )
            session.add(row)
            session.flush()
            self._enqueue_graph_events_in_session(
                session,
                [{
                    "event_key": f"hardware:{row.sensor_node_id}:{row.id}",
                    "operation": "hardware_observation",
                    "payload": {**observation, "id": row.id, "sensor_node_id": row.sensor_node_id},
                }],
            )
            session.commit()
            return row.id
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def bulk_insert_hardware_observations(
        self, observations: List[Dict]
    ) -> int:
        if not observations:
            return 0
        session = self._get_session()
        node_id = self.local_sensor_node_id()
        rows = []
        observations_by_token = {}
        for observation in observations:
            ingest_token = str(uuid.uuid4())
            observations_by_token[ingest_token] = observation
            rows.append({
                "capture_session_id": observation.get("capture_session_id"),
                "timestamp": float(
                    observation.get("timestamp") or time.time()
                ),
                "source_type": observation.get("source_type", "unknown"),
                "device_id": observation.get("device_id"),
                "sensor_node_id": (
                    observation.get("sensor_node_id") or node_id
                ),
                "observation_type": observation.get(
                    "observation_type", "unknown"
                ),
                "subject": observation.get("subject", "unknown"),
                "peer": observation.get("peer"),
                "metadata_json": json.dumps(
                    observation.get("metadata") or {}, sort_keys=True
                ),
                "ingest_token": ingest_token,
            })
        try:
            statement = insert(HardwareObservation).returning(
                HardwareObservation.id,
                HardwareObservation.sensor_node_id,
                HardwareObservation.ingest_token,
            )
            inserted = list(session.execute(statement, rows))
            self._enqueue_graph_events_in_session(
                session,
                [
                    {
                        "event_key": f"hardware:{sensor_node_id}:{row_id}",
                        "operation": "hardware_observation",
                        "payload": {
                            **observation,
                            "id": row_id,
                            "sensor_node_id": sensor_node_id,
                        },
                    }
                    for row_id, sensor_node_id, ingest_token in inserted
                    for observation in [observations_by_token[ingest_token]]
                ],
            )
            session.execute(
                update(HardwareObservation)
                .where(
                    HardwareObservation.ingest_token.in_(
                        observations_by_token
                    )
                )
                .values(ingest_token=None)
            )
            session.commit()
            return len(inserted)
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def bulk_upsert_entities(self, entities: List[Dict]):
        """Perform high-performance bulk upsert for entities using SQLite ON CONFLICT."""
        if not entities: return []
        
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        
        # Column mapping for backward compatibility
        MAPPING = {
            "packets": "total_packets",
            "bytes_count": "total_bytes",
            "timestamp": "last_seen",
            "confidence": "confidence_score",
            "os_info": "os"
        }
        
        # Get valid column names
        valid_cols = {c.name for c in Entity.__table__.columns}
        
        try:
            rows_by_shape = {}
            from core.forensics.identity import sanitize_identity_value
            for entity_data in entities:
                # Sanitize and map input data
                sanitized = {}
                for k, v in entity_data.items():
                    target_k = MAPPING.get(k, k)
                    if target_k in valid_cols:
                        if target_k in {"username", "full_name", "hostname", "netbios_name"}:
                            v = sanitize_identity_value(target_k, v)
                        sanitized[target_k] = v

                if sanitized.get("last_seen") is not None and "first_seen" not in sanitized:
                    sanitized["first_seen"] = sanitized["last_seen"]
                
                ip = sanitized.get("ip")
                if not ip: continue

                rows_by_shape.setdefault(tuple(sorted(sanitized)), []).append(sanitized)

            # SQLAlchemy can batch an upsert only when the parameter shape is
            # consistent.  Grouping retains backwards-compatible sparse input
            # while compiling and executing each shape once rather than once
            # per observed entity.
            for rows in rows_by_shape.values():
                stmt = sqlite_insert(Entity)

                # Preserve stronger identity evidence while still filling empty fields.
                incoming_confidence = func.coalesce(stmt.excluded.confidence_score, 0.0)
                existing_confidence = func.coalesce(Entity.confidence_score, 0.0)

                def stronger_value(column):
                    incoming = getattr(stmt.excluded, column.name)
                    return case(
                        (
                            incoming.is_not(None) & (
                                column.is_(None) | (incoming_confidence >= existing_confidence)
                            ),
                            incoming,
                        ),
                        else_=column,
                    )

                update_cols = {
                    "mac": stronger_value(Entity.mac),
                    "hostname": stronger_value(Entity.hostname),
                    "netbios_name": stronger_value(Entity.netbios_name),
                    "username": stronger_value(Entity.username),
                    "full_name": stronger_value(Entity.full_name),
                    "os": stronger_value(Entity.os),
                    "vendor": stronger_value(Entity.vendor),
                    "device_type": stronger_value(Entity.device_type),
                    "asset_role": stronger_value(Entity.asset_role),
                    "confidence_score": func.max(existing_confidence, incoming_confidence),
                    "identity_source": stronger_value(Entity.identity_source),
                    "ja3_hash": func.coalesce(stmt.excluded.ja3_hash, Entity.ja3_hash),
                    "ja4_string": func.coalesce(stmt.excluded.ja4_string, Entity.ja4_string),
                    "tls_library": func.coalesce(stmt.excluded.tls_library, Entity.tls_library),
                    "reverse_dns": func.coalesce(stmt.excluded.reverse_dns, Entity.reverse_dns),
                    "total_packets": func.coalesce(Entity.total_packets, 0) + func.coalesce(stmt.excluded.total_packets, 0),
                    "total_bytes": func.coalesce(Entity.total_bytes, 0) + func.coalesce(stmt.excluded.total_bytes, 0),
                    "risk_score": func.coalesce(Entity.risk_score, 0.0) + func.coalesce(stmt.excluded.risk_score, 0.0),
                    "first_seen": func.coalesce(Entity.first_seen, stmt.excluded.first_seen, stmt.excluded.last_seen),
                    "last_seen": func.max(func.coalesce(Entity.last_seen, 0.0), func.coalesce(stmt.excluded.last_seen, 0.0)),
                }
                upsert_stmt = stmt.on_conflict_do_update(
                    index_elements=['ip'], set_=update_cols,
                )
                session.execute(upsert_stmt, rows)
            
            session.commit()
            return []
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk entity upsert failed: {e}")
            raise e

    def get_entity(self, ip: str) -> Optional[Dict]:
        """Get a single entity by IP."""
        session = self._get_session()
        entity = session.query(Entity).filter_by(ip=ip).first()
        if entity:
            # Convert to dict for backward compatibility
            result = {c.name: getattr(entity, c.name) for c in entity.__table__.columns}
            if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
                snapshot = self.get_risk_snapshot(ip)
                if snapshot:
                    result["risk_score"] = snapshot["priority_score"]
                    result["confidence_score"] = snapshot["assessment_confidence"]
            return result
        return None

    def get_all_entities(self, source: str = None) -> List[Dict]:
        """Get all entities, optionally filtered by source, with counts."""
        session = self._get_session()
        
        # Optimized query to get entities + alert counts + carved file counts in one go
        from sqlalchemy import select, func, outerjoin
        
        # Subqueries for counts
        alert_counts = session.query(
            Alert.entity_ip, func.count(Alert.id).label("alert_count")
        ).group_by(Alert.entity_ip).subquery()
        
        carved_counts = session.query(
            CarvedFile.entity_ip, func.count(CarvedFile.id).label("carved_count")
        ).group_by(CarvedFile.entity_ip).subquery()

        flow_endpoints = session.query(
            Flow.src_ip.label("entity_ip"), Flow.id.label("flow_id")
        ).union_all(
            session.query(Flow.dst_ip.label("entity_ip"), Flow.id.label("flow_id"))
        ).subquery()
        flow_counts = session.query(
            flow_endpoints.c.entity_ip,
            func.count(func.distinct(flow_endpoints.c.flow_id)).label("flow_count"),
        ).group_by(flow_endpoints.c.entity_ip).subquery()
        
        query = session.query(
            Entity, 
            func.coalesce(alert_counts.c.alert_count, 0).label("alert_count"),
            func.coalesce(carved_counts.c.carved_count, 0).label("carved_file_count"),
            func.coalesce(flow_counts.c.flow_count, 0).label("flow_count"),
        ).outerjoin(alert_counts, Entity.ip == alert_counts.c.entity_ip)\
         .outerjoin(carved_counts, Entity.ip == carved_counts.c.entity_ip)\
         .outerjoin(flow_counts, Entity.ip == flow_counts.c.entity_ip)
        
        if source:
            query = query.filter(Entity.source == source)
            
        entities = query.order_by(Entity.risk_score.desc()).all()
        
        result = []
        for e, alert_count, carved_count, flow_count in entities:
            d = {c.name: getattr(e, c.name) for c in e.__table__.columns}
            d["alert_count"] = alert_count
            d["carved_file_count"] = carved_count
            d["flow_count"] = flow_count
            # active_risk still needs to be computed or fetched
            d["active_risk"] = e.risk_score # Fallback
            if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
                snapshot = self.get_risk_snapshot(e.ip)
                if snapshot:
                    d["risk_score"] = snapshot["priority_score"]
                    d["active_risk"] = snapshot["priority_score"]
                    d["confidence_score"] = snapshot["assessment_confidence"]
            result.append(d)
            
        return result

    def get_window_stats(self, source: str = "live", interface: str = None,
                         window_seconds: int = 86400) -> Dict:
        """Aggregate a bounded rolling traffic window directly in SQLite."""
        from sqlalchemy import Integer, cast, func

        session = self._get_session()
        window_end = time.time()
        window_start = window_end - max(60, int(window_seconds))

        def scoped(query):
            if source:
                query = query.filter(Flow.source.like("live%")) if source == "live" else query.filter(Flow.source == source)
            if interface:
                query = query.filter(Flow.capture_interface == interface)
            return query.filter(Flow.last_seen >= window_start)

        totals = scoped(session.query(
            func.count(Flow.id),
            func.coalesce(func.sum(Flow.packet_count), 0),
            func.coalesce(func.sum(Flow.byte_count), 0),
        )).one()

        protocols = {
            str(protocol or "UNKNOWN"): int(count or 0)
            for protocol, count in scoped(session.query(
                Flow.protocol, func.coalesce(func.sum(Flow.packet_count), 0),
            )).group_by(Flow.protocol).all()
        }
        ports = {
            str(port): int(count or 0)
            for port, count in scoped(session.query(
                Flow.dst_port, func.coalesce(func.sum(Flow.packet_count), 0),
            )).filter(Flow.dst_port.isnot(None)).group_by(Flow.dst_port).all()
        }

        endpoint_rows = scoped(session.query(
            Flow.src_ip.label("ip"), Flow.byte_count.label("bytes"), Flow.id.label("flow_id"),
        )).union_all(scoped(session.query(
            Flow.dst_ip.label("ip"), Flow.byte_count.label("bytes"), Flow.id.label("flow_id"),
        ))).subquery()
        top_talkers = {
            str(ip): int(byte_count or 0)
            for ip, byte_count in session.query(
                endpoint_rows.c.ip, func.sum(endpoint_rows.c.bytes),
            ).filter(endpoint_rows.c.ip.isnot(None)).group_by(endpoint_rows.c.ip)\
             .order_by(func.sum(endpoint_rows.c.bytes).desc()).limit(25).all()
        }
        active_hosts = session.query(func.count(func.distinct(endpoint_rows.c.ip))).scalar() or 0

        bucket = cast(Flow.last_seen / 300, Integer) * 300
        timeline = {
            str(int(timestamp)): {
                "time": int(timestamp), "packets": int(packets or 0), "bytes": int(byte_count or 0),
            }
            for timestamp, packets, byte_count in scoped(session.query(
                bucket.label("bucket"),
                func.coalesce(func.sum(Flow.packet_count), 0),
                func.coalesce(func.sum(Flow.byte_count), 0),
            )).group_by(bucket).order_by(bucket).all()
        }
        return {
            "window_start": window_start,
            "window_end": window_end,
            "total_packets": int(totals[1] or 0),
            "total_bytes": int(totals[2] or 0),
            "total_flows": int(totals[0] or 0),
            "active_hosts": int(active_hosts),
            "protocol_distribution": protocols,
            "port_distribution": ports,
            "top_talkers": top_talkers,
            "traffic_timeline": timeline,
        }

    def update_entity_asset_role(self, ip: str, role: str):
        """Update role inference without changing identity confidence/provenance."""
        session = self._get_session()
        entity = session.query(Entity).filter_by(ip=ip).first()
        if entity:
            entity.asset_role = role
            session.commit()

    # ----------------------------------------------------------------
    # Alert Operations
    # ----------------------------------------------------------------

    def insert_alert(self, entity_ip: str, timestamp: float, alert_type: str,
                     severity: str, score: float, explanation: str,
                     evidence: Dict = None, source: str = "live", commit: bool = True,
                     capture_session_id: str = None, capture_interface: str = None,
                     capture_backend: str = None, capture_type: str = "network",
                     sensor_node_id: str = None):
        """Apply policy, deduplicate, and persist an auditable alert."""
        session = self._get_session()
        decision = self.alert_policy.evaluate(
            entity_ip, alert_type, severity, score, explanation, evidence, timestamp
        )
        timestamp = float(timestamp or 0.0)
        evidence_with_context = dict(evidence or {})
        evidence_with_context["_policy"] = decision.context

        existing = session.query(Alert).filter(
            Alert.fingerprint == decision.fingerprint,
            Alert.source == source,
            Alert.sensor_node_id == (sensor_node_id or self.local_sensor_node_id()),
            func.coalesce(Alert.last_seen, Alert.timestamp) >= timestamp - self.alert_policy.dedup_window,
        ).order_by(Alert.timestamp.desc()).first()
        if existing:
            existing.occurrence_count = (existing.occurrence_count or 1) + 1
            existing.last_seen = max(float(existing.last_seen or existing.timestamp or 0.0), timestamp)
            existing.timestamp = existing.last_seen
            existing.evidence = json.dumps(evidence_with_context, sort_keys=True)
            if commit:
                session.commit()
            return {"id": existing.id, "created": False, "suppressed": bool(existing.is_hidden),
                    "suppression_reason": existing.suppression_reason or "policy suppression",
                    "score": existing.score, "severity": existing.severity}

        alert = Alert(
            entity_ip=entity_ip, timestamp=timestamp, type=alert_type,
            severity=decision.severity, score=decision.score, explanation=explanation,
            evidence=json.dumps(evidence_with_context, sort_keys=True), source=source,
            fingerprint=decision.fingerprint, occurrence_count=1,
            first_seen=timestamp, last_seen=timestamp,
            is_hidden=decision.suppressed,
            suppression_reason=decision.suppression_reason,
            policy_context=json.dumps(decision.context, sort_keys=True),
            capture_session_id=capture_session_id,
            capture_interface=capture_interface,
            capture_backend=capture_backend,
            capture_type=capture_type,
            sensor_node_id=sensor_node_id or self.local_sensor_node_id(),
        )
        session.add(alert)
        
        from core.storage.models import Entity
        # Also bump entity risk score (ensure entity exists first)
        entity = session.query(Entity).filter_by(ip=entity_ip).first()
        if not entity:
            # Create a placeholder entity if it doesn't exist
            entity = Entity(ip=entity_ip, risk_score=0.0, source=source)
            session.add(entity)
            session.flush()
        
        if not decision.suppressed:
            entity.risk_score = (entity.risk_score or 0.0) + decision.score
            
        if commit:
            session.commit()
            
        if self.alert_callback and not decision.suppressed:
            try:
                self.alert_callback({
                    "id": alert.id,
                    "entity_ip": entity_ip, "timestamp": timestamp,
                    "type": alert_type, "severity": decision.severity,
                    "score": decision.score, "explanation": explanation,
                    "evidence": evidence_with_context, "source": source
                })
            except Exception:
                pass
        return {"id": alert.id, "created": True, "suppressed": decision.suppressed,
                "suppression_reason": decision.suppression_reason or "policy suppression",
                "score": decision.score, "severity": decision.severity}

    # ----------------------------------------------------------------
    # Behavioral Scoring V2
    # ----------------------------------------------------------------

    def register_scoring_model(self, scoring_config, mode: str = "dual") -> Dict:
        """Register the exact normalized scoring configuration in use."""
        session = self._get_session()
        row = session.query(ScoringModel).filter_by(version=scoring_config.model_version).first()
        config_json = json.dumps(scoring_config.raw, sort_keys=True, separators=(",", ":"), default=str)
        if row is None:
            row = ScoringModel(
                version=scoring_config.model_version,
                config_hash=scoring_config.config_hash,
                mode=mode,
                activated_at=time.time(),
                config_json=config_json,
            )
            session.add(row)
        else:
            row.config_hash = scoring_config.config_hash
            row.config_json = config_json
            row.mode = mode
        session.commit()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns}

    def upsert_detection_finding(self, finding, commit: bool = True) -> Dict:
        """Persist a validated finding and its stable five-minute occurrence bucket."""
        from core.detection.contracts import DetectionFindingV2

        if not isinstance(finding, DetectionFindingV2):
            raise TypeError("finding must be DetectionFindingV2")
        errors = finding.validate()
        if errors:
            raise ValueError("Invalid detection finding: " + "; ".join(errors))
        session = self._get_session()
        interface = finding.capture_interface or ""
        capture_session = finding.capture_session_id or ""
        row = session.query(DetectionFinding).filter_by(
            model_version=finding.model_version,
            fingerprint=finding.fingerprint,
            source=finding.source,
            capture_interface=interface,
            capture_session_id=capture_session,
        ).first()
        created = row is None
        if row is None:
            row = DetectionFinding(
                fingerprint=finding.fingerprint,
                model_version=finding.model_version,
                detector_id=finding.detector_id,
                detector_version=finding.detector_version,
                finding_type=finding.finding_type,
                legacy_type=finding.legacy_type,
                category=finding.category,
                impact=finding.impact,
                confidence=finding.confidence,
                evidence_quality=finding.evidence_quality,
                calibration_state=finding.calibration_state,
                signal_family=finding.signal_family,
                correlation_group=finding.correlation_group,
                subject=finding.subject,
                target=finding.target,
                flow_ref=finding.flow_ref,
                source=finding.source,
                sensor_node_id=finding.sensor_node_id or self.local_sensor_node_id(),
                capture_interface=interface,
                capture_session_id=capture_session,
                capture_backend=finding.capture_backend,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                occurrence_count=finding.occurrence_count,
                explanation=finding.explanation,
                recommended_action=finding.recommended_action,
                mitre_technique=finding.mitre_technique,
                evidence_json=json.dumps(finding.evidence or {}, sort_keys=True, default=str),
                evidence_refs_json=json.dumps(list(finding.evidence_refs), sort_keys=True),
                disposition="unknown",
            )
            session.add(row)
            session.flush()
        else:
            row.first_seen = min(float(row.first_seen), float(finding.first_seen))
            row.last_seen = max(float(row.last_seen), float(finding.last_seen))
            row.occurrence_count = int(row.occurrence_count or 0) + finding.occurrence_count
            row.confidence = max(float(row.confidence or 0), finding.confidence)
            row.evidence_quality = max(float(row.evidence_quality or 0), finding.evidence_quality)
            row.evidence_json = json.dumps(finding.evidence or {}, sort_keys=True, default=str)
            row.evidence_refs_json = json.dumps(list(finding.evidence_refs), sort_keys=True)

        bucket_start = int(float(finding.last_seen) // 300) * 300
        bucket = session.query(FindingWindow).filter_by(finding_id=row.id, bucket_start=bucket_start).first()
        if bucket is None:
            bucket = FindingWindow(
                finding_id=row.id,
                bucket_start=bucket_start,
                occurrence_count=finding.occurrence_count,
                max_confidence=finding.confidence,
                max_evidence_quality=finding.evidence_quality,
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                evidence_ref=f"finding:{row.id}",
            )
            session.add(bucket)
        elif not created:
            bucket.occurrence_count = int(bucket.occurrence_count or 0) + finding.occurrence_count
            bucket.max_confidence = max(float(bucket.max_confidence or 0), finding.confidence)
            bucket.max_evidence_quality = max(float(bucket.max_evidence_quality or 0), finding.evidence_quality)
            bucket.first_seen = min(float(bucket.first_seen), float(finding.first_seen))
            bucket.last_seen = max(float(bucket.last_seen), float(finding.last_seen))
        if commit:
            session.commit()
            try:
                self.enqueue_graph_events([{
                    "event_key": f"finding:{row.sensor_node_id}:{row.id}", "operation": "finding",
                    "payload": self._finding_dict(row),
                }])
            except Exception:
                logger.exception("Unable to enqueue finding graph projection event")
        return {"id": row.id, "created": created, "fingerprint": row.fingerprint}

    @staticmethod
    def _finding_dict(row: DetectionFinding) -> Dict:
        result = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        try:
            result["evidence"] = json.loads(result.pop("evidence_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            result["evidence"] = {}
        try:
            result["evidence_refs"] = json.loads(result.pop("evidence_refs_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            result["evidence_refs"] = []
        result["capture_interface"] = result.get("capture_interface") or None
        result["capture_session_id"] = result.get("capture_session_id") or None
        return result

    def get_detection_findings(
        self, subject: str = None, source: str = None, interface: str = None,
        capture_session_id: str = None, finding_type: str = None,
        include_suppressed: bool = False, limit: int = 1000,
        sensor_node_id: str = None, after_last_seen: float = None,
        after_id: int = None, offset: int = 0,
    ) -> List[Dict]:
        session = self._get_session()
        query = session.query(DetectionFinding)
        if subject:
            query = query.filter(DetectionFinding.subject == subject)
        if source:
            query = query.filter(DetectionFinding.source.like("live%")) if source == "live" else query.filter_by(source=source)
        if interface:
            query = query.filter(DetectionFinding.capture_interface == interface)
        if capture_session_id:
            query = query.filter(DetectionFinding.capture_session_id == capture_session_id)
        if sensor_node_id:
            query = query.filter(DetectionFinding.sensor_node_id == sensor_node_id)
        if finding_type:
            query = query.filter(DetectionFinding.finding_type == finding_type)
        if not include_suppressed:
            query = query.filter(DetectionFinding.is_suppressed.is_(False))
        if after_last_seen is not None and after_id is not None:
            query = query.filter(or_(
                DetectionFinding.last_seen < float(after_last_seen),
                and_(
                    DetectionFinding.last_seen == float(after_last_seen),
                    DetectionFinding.id < int(after_id),
                ),
            ))
        rows = (
            query.order_by(DetectionFinding.last_seen.desc(), DetectionFinding.id.desc())
            .offset(max(0, int(offset)))
            .limit(max(1, min(int(limit), 100000)))
            .all()
        )
        return [self._finding_dict(row) for row in rows]

    def get_detection_finding(self, finding_id: int) -> Optional[Dict]:
        with self.session_scope() as session:
            row = session.query(DetectionFinding).filter_by(id=int(finding_id)).first()
            return self._finding_dict(row) if row else None

    def recompute_risk(
        self, subject: str, source: str = None, interface: str = None,
        capture_session_id: str = None, as_of: float = None, asset_role: str = None,
        persist: bool = True, sensor_node_id: str = None,
    ) -> Dict:
        from core.detection.scoring import PriorityScorer, ScoringConfig

        as_of = float(as_of if as_of is not None else time.time())
        override = self.data_dir / "config" / "scoring.yaml"
        shipped = Path(__file__).resolve().parents[1] / "detection" / "scoring_profiles.yaml"
        from core.calibration.attestations import ATTESTATION_DIR

        watched = [shipped]
        if override.exists():
            watched.append(override)
        if ATTESTATION_DIR.exists():
            watched.extend(sorted(ATTESTATION_DIR.glob("*.json")))
        signature = tuple(
            (str(path), path.stat().st_mtime_ns, path.stat().st_size)
            for path in watched if path.exists()
        )
        if self._scoring_config_cache is None or signature != self._scoring_config_signature:
            self._scoring_config_cache = ScoringConfig(
                override_path=str(override) if override.exists() else None,
            )
            self._scoring_config_signature = signature
        config = self._scoring_config_cache
        if self._registered_scoring_hash != config.config_hash:
            self.register_scoring_model(config, mode=os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower())
            self._registered_scoring_hash = config.config_hash
        scorer = PriorityScorer(config)
        findings = self.get_detection_findings(
            subject=subject, source=source, interface=interface,
            capture_session_id=capture_session_id, include_suppressed=False, limit=100000,
            sensor_node_id=sensor_node_id,
        )
        scope_type, scope_id = self._risk_scope(source, interface, capture_session_id, sensor_node_id)
        assessment = scorer.score(
            findings, as_of=as_of, asset_role=asset_role,
            scope={"type": scope_type, "id": scope_id, "source": source,
                   "interface": interface, "session": capture_session_id, "node": sensor_node_id},
        )
        result = assessment.to_dict()
        if persist:
            session = self._get_session()
            row = session.query(RiskSnapshot).filter_by(
                model_version=assessment.model_version,
                subject=subject,
                scope_type=scope_type,
                scope_id=scope_id,
            ).first()
            values = {
                "config_hash": assessment.config_hash,
                "source": source,
                "capture_interface": interface,
                "capture_session_id": capture_session_id,
                "sensor_node_id": sensor_node_id,
                "priority_score": assessment.priority_score,
                "risk_level": assessment.risk_level,
                "assessment_confidence": assessment.assessment_confidence,
                "computed_at": assessment.as_of,
                "contributors_json": json.dumps([item.__dict__ for item in assessment.contributors], sort_keys=True),
            }
            if row is None:
                row = RiskSnapshot(
                    model_version=assessment.model_version, subject=subject,
                    scope_type=scope_type, scope_id=scope_id, **values,
                )
                session.add(row)
            else:
                for key, value in values.items():
                    setattr(row, key, value)
            session.commit()
        return result

    def recompute_risk_rollups(self, subject: str, source: str = None, interface: str = None,
                               capture_session_id: str = None, as_of: float = None,
                               asset_role: str = None) -> Dict[str, Dict]:
        """Materialize exact, interface, source, live, and deduplicated global scopes."""
        scopes = []
        if capture_session_id:
            scopes.append(("session", source, interface, capture_session_id))
        if interface:
            scopes.append(("interface", None, interface, None))
        if source:
            scopes.append(("source", source, None, None))
        if str(source or "").startswith("live"):
            scopes.append(("live", "live", None, None))
        scopes.append(("global", None, None, None))
        result = {}
        seen = set()
        for name, scoped_source, scoped_interface, scoped_session in scopes:
            key = (scoped_source, scoped_interface, scoped_session)
            if key in seen:
                continue
            seen.add(key)
            result[name] = self.recompute_risk(
                subject, source=scoped_source, interface=scoped_interface,
                capture_session_id=scoped_session, as_of=as_of,
                asset_role=asset_role, persist=True,
            )
        return result

    @staticmethod
    def _risk_scope(source=None, interface=None, capture_session_id=None, sensor_node_id=None):
        prefix = f"node:{sensor_node_id}:" if sensor_node_id else ""
        if capture_session_id:
            return ("node_session" if sensor_node_id else "session"), f"{prefix}{capture_session_id}"
        if interface:
            return ("node_interface" if sensor_node_id else "interface"), f"{prefix}{source or 'live'}:{interface}"
        if source:
            return ("node_source" if sensor_node_id else "source"), f"{prefix}{source}"
        if sensor_node_id:
            return "node", sensor_node_id
        return "global", "all"

    def get_risk_snapshot(self, subject: str, source: str = None, interface: str = None,
                          capture_session_id: str = None, sensor_node_id: str = None) -> Optional[Dict]:
        from core.detection.scoring import ScoringConfig

        scope_type, scope_id = self._risk_scope(source, interface, capture_session_id, sensor_node_id)
        session = self._get_session()
        row = session.query(RiskSnapshot).filter_by(
            model_version=ScoringConfig.model_version, subject=subject,
            scope_type=scope_type, scope_id=scope_id,
        ).first()
        if not row:
            return None
        result = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        result["contributors"] = json.loads(result.pop("contributors_json") or "[]")
        return result

    def get_risk_snapshots(self, source: str = None, interface: str = None,
                           capture_session_id: str = None, limit: int = 100,
                           offset: int = 0, sensor_node_id: str = None,
                           after_priority: float = None, after_subject: str = None) -> List[Dict]:
        """Return one page of authoritative V2 snapshots for an exact rollup scope."""
        from core.detection.scoring import ScoringConfig

        scope_type, scope_id = self._risk_scope(source, interface, capture_session_id, sensor_node_id)
        query = self._get_session().query(RiskSnapshot).filter_by(
            model_version=ScoringConfig.model_version, scope_type=scope_type, scope_id=scope_id,
        )
        if after_priority is not None and after_subject is not None:
            query = query.filter(or_(
                RiskSnapshot.priority_score < float(after_priority),
                and_(
                    RiskSnapshot.priority_score == float(after_priority),
                    RiskSnapshot.subject > str(after_subject),
                ),
            ))
        rows = (
            query.order_by(RiskSnapshot.priority_score.desc(), RiskSnapshot.subject.asc())
            .offset(max(0, int(offset)))
            .limit(max(1, min(500, int(limit))))
            .all()
        )
        result = []
        for row in rows:
            item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
            item["contributors"] = json.loads(item.pop("contributors_json") or "[]")
            result.append(item)
        return result

    def update_feature_baseline(self, subject: str, feature: str, value: float, timestamp: float,
                                source: str = "live", interface: str = None,
                                dimension: str = "") -> Dict:
        from core.detection.baseline import OnlineFeatureStats, baseline_maturity

        session = self._get_session()
        normalized_interface = interface or ""
        row = session.query(FeatureBaseline).filter_by(
            subject=subject, source=source, capture_interface=normalized_interface,
            feature=feature, dimension=dimension or "",
        ).first()
        if row is None:
            row = FeatureBaseline(
                subject=subject, source=source, capture_interface=normalized_interface,
                feature=feature, dimension=dimension or "", first_sample_at=float(timestamp),
            )
            session.add(row)
            state = OnlineFeatureStats()
        else:
            try:
                state = OnlineFeatureStats.from_state(json.loads(row.state_json or "{}"))
            except (TypeError, json.JSONDecodeError, ValueError):
                state = OnlineFeatureStats()
        state.update(value)
        row.sample_count = state.count
        row.first_sample_at = float(row.first_sample_at if row.first_sample_at is not None else timestamp)
        row.last_sample_at = float(timestamp)
        row.mean, row.m2 = state.mean, state.m2
        row.ewma, row.ewma_variance = state.ewma, state.ewma_variance
        row.p50, row.p95, row.p99 = state.percentile(0.50), state.percentile(0.95), state.percentile(0.99)
        row.state_json = json.dumps(state.to_state(), separators=(",", ":"))
        session.commit()
        result = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        result["capture_interface"] = result.get("capture_interface") or None
        result["maturity"] = baseline_maturity(row.sample_count, row.first_sample_at, row.last_sample_at)
        result.pop("state_json", None)
        return result

    def get_feature_baselines(self, subject: str = None, source: str = None,
                              interface: str = None, feature: str = None) -> List[Dict]:
        from core.detection.baseline import baseline_maturity

        query = self._get_session().query(FeatureBaseline)
        if subject:
            query = query.filter_by(subject=subject)
        if source:
            query = query.filter_by(source=source)
        if interface:
            query = query.filter_by(capture_interface=interface)
        if feature:
            query = query.filter_by(feature=feature)
        result = []
        for row in query.order_by(FeatureBaseline.last_sample_at.desc()).all():
            item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
            item["capture_interface"] = item.get("capture_interface") or None
            item["maturity"] = baseline_maturity(row.sample_count, row.first_sample_at, row.last_sample_at)
            item.pop("state_json", None)
            result.append(item)
        return result

    def purge_inactive_feature_baselines(self, as_of: float = None, max_age_days: int = 90) -> int:
        cutoff = float(as_of if as_of is not None else time.time()) - int(max_age_days) * 86400
        session = self._get_session()
        count = session.query(FeatureBaseline).filter(FeatureBaseline.last_sample_at < cutoff).delete(synchronize_session=False)
        session.commit()
        return int(count)

    def set_finding_disposition(self, finding_id: int, verdict: str, reason: str = "",
                                actor: str = "local-analyst", scope: str = "finding",
                                expires_at: float = None) -> Dict:
        verdict = str(verdict).lower()
        if verdict not in {"true_positive", "false_positive", "benign_expected", "unknown"}:
            raise ValueError("verdict must be true_positive, false_positive, benign_expected, or unknown")
        if verdict != "unknown" and not str(reason).strip():
            raise ValueError("reason is required for non-unknown dispositions")
        session = self._get_session()
        finding = session.query(DetectionFinding).filter_by(id=int(finding_id)).first()
        if not finding:
            raise ValueError(f"finding {finding_id} does not exist")
        disposition = AnalystDisposition(
            finding_id=finding.id, verdict=verdict, reason=str(reason).strip(), actor=actor,
            created_at=time.time(), scope=scope, expires_at=expires_at,
        )
        session.add(disposition)
        finding.disposition = verdict
        finding.is_suppressed = verdict in {"false_positive", "benign_expected"}
        session.commit()
        assessment = self.recompute_risk(
            finding.subject, source=finding.source,
            interface=finding.capture_interface or None,
            capture_session_id=finding.capture_session_id or None,
            sensor_node_id=finding.sensor_node_id or None,
        )
        return {"finding_id": finding.id, "verdict": verdict, "assessment": assessment}

    def get_alerts(self, entity_ip: str = None, source: str = None, limit: int = 100,
                   include_hidden: bool = False, interface: str = None,
                   capture_session_id: str = None, offset: int = 0,
                   sensor_node_id: str = None) -> List[Dict]:
        """Get alerts, optionally filtered."""
        if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
            from core.detection.contracts import LEGACY_TYPE_MAP
            from core.detection.scoring import BASE_IMPACT

            aliases = {}
            for legacy_type, canonical_type in LEGACY_TYPE_MAP.items():
                aliases.setdefault(canonical_type, legacy_type)
            findings = self.get_detection_findings(
                subject=entity_ip, source=source, interface=interface,
                capture_session_id=capture_session_id,
                include_suppressed=include_hidden, limit=limit,
            )
            if sensor_node_id:
                findings = [item for item in findings if item.get("sensor_node_id") == sensor_node_id]
            projected = []
            for item in findings:
                severity = item.get("impact") or "LOW"
                projected.append({
                    "id": item["id"], "entity_ip": item["subject"],
                    "timestamp": item["last_seen"],
                    "type": item.get("legacy_type") or aliases.get(item["finding_type"], item["finding_type"]),
                    "severity": "LOW" if severity == "INFORMATIONAL" else severity,
                    "score": BASE_IMPACT.get(severity, 10.0),
                    "explanation": item["explanation"], "evidence": item["evidence"],
                    "source": item["source"], "capture_session_id": item.get("capture_session_id"),
                    "capture_interface": item.get("capture_interface"),
                    "capture_backend": item.get("capture_backend"), "capture_type": "network",
                    "sensor_node_id": item.get("sensor_node_id"),
                    "ai_verdict": None, "occurrence_count": item["occurrence_count"],
                    "is_hidden": item.get("is_suppressed", False),
                })
            return projected
        session = self._get_session()
        query = session.query(Alert)
        if entity_ip:
            query = query.filter_by(entity_ip=entity_ip)
        if not include_hidden:
            query = query.filter(Alert.is_hidden.is_(False))
        if source:
            if source == "live":
                from sqlalchemy import or_
                query = query.filter(Alert.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        if interface:
            query = query.filter(Alert.capture_interface == interface)
        if capture_session_id:
            query = query.filter(Alert.capture_session_id == capture_session_id)
        if sensor_node_id:
            query = query.filter(Alert.sensor_node_id == sensor_node_id)

        alerts = query.order_by(Alert.timestamp.desc(), Alert.id.desc()).offset(max(0, int(offset))).limit(limit).all()
        result = []
        for a in alerts:
            d = {c.name: getattr(a, c.name) for c in a.__table__.columns}
            if d.get("evidence"):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    def update_alert_ai(self, alert_id: int, verdict: str = None, reasoning: str = None,
                        status: str = None, cycle: int = None, is_hidden: bool = None):
        """Update AI metadata for an alert."""
        session = self._get_session()
        alert = session.query(Alert).filter_by(id=alert_id).first()
        if alert:
            if verdict: alert.ai_verdict = verdict
            if reasoning: alert.ai_reasoning = reasoning
            if status: alert.ai_status = status
            if cycle is not None: alert.ai_cycle = cycle
            if is_hidden is not None: alert.is_hidden = is_hidden
            session.commit()

    def recalibrate_risk_from_alert(self, alert_id: int, multiplier: float = -1.0):
        """
        Adjust entity risk score based on an alert (usually to subtract for FPs).
        multiplier: -1.0 to completely undo the score, or 0.5 to halve it, etc.
        """
        session = self._get_session()
        alert = session.query(Alert).filter_by(id=alert_id).first()
        if alert and alert.entity_ip:
            entity = session.query(Entity).filter_by(ip=alert.entity_ip).first()
            if entity:
                adjustment = (alert.score or 0.0) * multiplier
                entity.risk_score = max(0.0, (entity.risk_score or 0.0) + adjustment)
                session.commit()
                logger.info(f"Recalibrated risk for {alert.entity_ip}: {adjustment:+.1f} (Alert ID: {alert_id})")

    # ----------------------------------------------------------------
    # AI Feedback & Baselines
    # ----------------------------------------------------------------

    def log_investigation_step(self, alert_id: int, thought: str, action: str, observation: str):
        """Log a single step of the AI investigation for transparency."""
        from core.storage.models import InvestigationStep
        session = self._get_session()
        step = InvestigationStep(
            alert_id=alert_id, timestamp=time.time(),
            thought=thought, action=action, observation=observation
        )
        session.add(step)
        session.commit()

    def check_user_feedback(self, alert_type: str, entity_ip: str) -> Optional[str]:
        """Check if the user has already approved/rejected this type of alert for this entity."""
        from core.storage.models import AIUserFeedback
        session = self._get_session()
        fb = session.query(AIUserFeedback).filter_by(
            alert_type=alert_type, entity_ip=entity_ip
        ).order_by(AIUserFeedback.timestamp.desc()).first()
        return fb.user_verdict if fb else None

    def upsert_user_feedback(self, alert_type: str, entity_ip: str, verdict: str):
        from core.storage.models import AIUserFeedback
        session = self._get_session()
        fb = AIUserFeedback(
            alert_type=alert_type, entity_ip=entity_ip,
            user_verdict=verdict, timestamp=time.time()
        )
        session.add(fb)
        session.commit()

    def get_investigation_steps(self, alert_id: int) -> List[Dict]:
        from core.storage.models import InvestigationStep
        session = self._get_session()
        steps = session.query(InvestigationStep).filter_by(alert_id=alert_id).order_by(InvestigationStep.timestamp.asc()).all()
        return [{c.name: getattr(s, c.name) for c in s.__table__.columns} for s in steps]

    # ----------------------------------------------------------------
    # Flow Operations
    # ----------------------------------------------------------------

    def upsert_flow(self, **kwargs):
        """Deprecated: Use bulk_upsert_flows for high-performance capture."""
        return self.bulk_upsert_flows([kwargs])

    def bulk_upsert_flows(self, flows: List[Dict]):
        """Perform high-performance bulk upsert using SQLite ON CONFLICT."""
        if not flows: return []
        
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        today_str = date.today().isoformat()
        
        # Get valid column names
        valid_cols = {c.name for c in Flow.__table__.columns}
        
        try:
            rows = []
            for flow_data in flows:
                # Sanitize and handle defaults
                sanitized = {}
                for k, v in flow_data.items():
                    if k in valid_cols:
                        sanitized[k] = v
                
                if "session_date" not in sanitized:
                    sanitized["session_date"] = today_str
                sanitized.setdefault("sensor_node_id", self.local_sensor_node_id())
                
                # Handle JSON serialization for l7_metadata
                if "l7_metadata" in sanitized and isinstance(sanitized["l7_metadata"], dict):
                    sanitized["l7_metadata"] = json.dumps(
                        self._sanitize_flow_metadata(sanitized["l7_metadata"]), sort_keys=True,
                    )

                rows.append(sanitized)

            # Let the SQLite driver execute one prepared upsert statement for
            # the complete batch.  Calling ``session.execute`` inside the
            # loop made offline PCAP finalization pay Python/SQL compilation
            # overhead once per flow even though the work is one transaction.
            stmt = sqlite_insert(Flow)
            update_cols = {
                "last_seen": stmt.excluded.last_seen,
                "packet_count": stmt.excluded.packet_count,
                "byte_count": stmt.excluded.byte_count,
                "tcp_syn_count": stmt.excluded.tcp_syn_count,
                "tcp_rst_count": stmt.excluded.tcp_rst_count,
                "avg_packet_size": stmt.excluded.avg_packet_size,
                "duration": stmt.excluded.duration,
                "interarrival_mean": stmt.excluded.interarrival_mean,
                "interarrival_std": stmt.excluded.interarrival_std,
                "packet_size_variance": stmt.excluded.packet_size_variance,
                "l7_metadata": stmt.excluded.l7_metadata,
            }
            upsert_stmt = stmt.on_conflict_do_update(
                index_elements=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'source'],
                set_=update_cols,
            )
            session.execute(upsert_stmt, rows)

            session.commit()
            try:
                graph_events = []
                for row in rows:
                    metadata = row.get("l7_metadata") or {}
                    if isinstance(metadata, str):
                        try:
                            metadata = json.loads(metadata)
                        except (TypeError, ValueError):
                            metadata = {}
                    graph_payload = {**row, "l7_metadata": metadata}
                    graph_key = sha256(json.dumps({
                        "node": row.get("sensor_node_id"), "source": row.get("source"),
                        "src": row.get("src_ip"), "sport": row.get("src_port"), "dst": row.get("dst_ip"),
                        "dport": row.get("dst_port"), "protocol": row.get("protocol"),
                    }, sort_keys=True).encode("utf-8")).hexdigest()
                    graph_events.append({"event_key": f"flow:{graph_key}", "operation": "flow", "payload": graph_payload})
                self.enqueue_graph_events(graph_events)
            except Exception:
                logger.exception("Unable to enqueue flow graph projection events")
            return []
        except Exception as e:
            session.rollback()
            logger.error(f"Bulk flow upsert failed: {e}")
            raise e

    def get_flows(self, source: str = None, limit: int = 50, interface: str = None,
                  capture_session_id: str = None, offset: int = 0,
                  sensor_node_id: str = None, protocol: str = None, port: int = None,
                  after_packet_count: int = None, after_id: int = None) -> List[Dict]:
        """Get flow records."""
        session = self._get_session()
        query = session.query(Flow)
        if source:
            if source == "live":
                query = query.filter(Flow.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        if interface:
            query = query.filter(Flow.capture_interface == interface)
        if capture_session_id:
            query = query.filter(Flow.capture_session_id == capture_session_id)
        if sensor_node_id:
            query = query.filter(Flow.sensor_node_id == sensor_node_id)
        if protocol:
            query = query.filter(func.upper(Flow.protocol) == str(protocol).upper())
        if port is not None:
            query = query.filter(or_(Flow.src_port == int(port), Flow.dst_port == int(port)))
        if after_packet_count is not None and after_id is not None:
            query = query.filter(or_(
                Flow.packet_count < int(after_packet_count),
                and_(Flow.packet_count == int(after_packet_count), Flow.id < int(after_id)),
            ))

        flows = query.order_by(Flow.packet_count.desc(), Flow.id.desc()).offset(max(0, int(offset))).limit(limit).all()
        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try:
                    d["l7_metadata"] = json.loads(d["l7_metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            d["flow_id"] = format_flow_id(
                d["src_ip"], d["src_port"], d["dst_ip"], d["dst_port"], d["protocol"]
            )
            result.append(d)
        return result

    def summarize_flows(self, source: str = None, interface: str = None,
                        capture_session_id: str = None, sensor_node_id: str = None) -> Dict[str, Any]:
        """Return exact aggregate flow facts without loading every row."""
        with self.session_scope() as session:
            query = session.query(Flow)
            if source:
                query = query.filter(Flow.source.like("live%")) if source == "live" else query.filter(Flow.source == source)
            if interface:
                query = query.filter(Flow.capture_interface == interface)
            if capture_session_id:
                query = query.filter(Flow.capture_session_id == capture_session_id)
            if sensor_node_id:
                query = query.filter(Flow.sensor_node_id == sensor_node_id)
            aggregate = query.with_entities(
                func.count(Flow.id),
                func.coalesce(func.sum(Flow.packet_count), 0),
                func.coalesce(func.sum(Flow.byte_count), 0),
                func.min(Flow.start_time),
                func.max(Flow.last_seen),
            ).one()
            protocols = query.with_entities(
                func.upper(Flow.protocol), func.count(Flow.id)
            ).group_by(func.upper(Flow.protocol)).all()
            return {
                "flow_count": int(aggregate[0] or 0), "packet_count": int(aggregate[1] or 0),
                "byte_count": int(aggregate[2] or 0), "first_seen": aggregate[3],
                "last_seen": aggregate[4], "partial_flows": 0,
                "protocols": {str(protocol or "OTHER"): int(count) for protocol, count in protocols},
            }

    def get_flow(self, flow_id: int) -> Optional[Dict]:
        with self.session_scope() as session:
            row = session.query(Flow).filter_by(id=int(flow_id)).first()
            if not row:
                return None
            result = {column.name: getattr(row, column.name) for column in row.__table__.columns}
            try:
                result["l7_metadata"] = json.loads(result.get("l7_metadata") or "{}")
            except (TypeError, json.JSONDecodeError):
                result["l7_metadata"] = {}
            result["flow_id"] = format_flow_id(
                result["src_ip"], result["src_port"], result["dst_ip"],
                result["dst_port"], result["protocol"],
            )
            return result

    def get_source_flows(self, source: str) -> List[Dict]:
        """Return a complete source-scoped flow set for offline enrichment."""
        session = self._get_session()
        query = session.query(Flow).filter_by(source=source).order_by(Flow.id.asc())
        result = []
        for flow in query.all():
            row = {column.name: getattr(flow, column.name) for column in flow.__table__.columns}
            if row.get("l7_metadata"):
                try:
                    row["l7_metadata"] = json.loads(row["l7_metadata"])
                except (json.JSONDecodeError, TypeError):
                    row["l7_metadata"] = {}
            result.append(row)
        return result

    def get_entities_by_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """Fetch entity evidence for a batch of local profile rebuilds."""
        values = sorted({str(ip) for ip in ips if ip})
        if not values:
            return {}
        session = self._get_session()
        rows = session.query(Entity).filter(Entity.ip.in_(values)).all()
        return {
            row.ip: {column.name: getattr(row, column.name) for column in row.__table__.columns}
            for row in rows
        }

    def get_flow_by_key(self, flow_id, source: str) -> Optional[Dict]:
        session = self._get_session()
        row = session.query(Flow).filter_by(
            src_ip=flow_id[0], dst_ip=flow_id[1], src_port=flow_id[2],
            dst_port=flow_id[3], protocol=flow_id[4], source=source,
        ).first()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns} if row else None

    def count_flows(self, source: str) -> int:
        return self._get_session().query(Flow).filter_by(source=source).count()

    def get_filtered_flows(self, src_ip: str = None, dst_ip: str = None,
                           port: int = None, protocol: str = None,
                           source: str = None, limit: int = 100) -> List[Dict]:
        """Powerful flow query tool for AI investigation and CLI parity."""
        session = self._get_session()
        query = session.query(Flow)

        if src_ip: query = query.filter(Flow.src_ip == src_ip)
        if dst_ip: query = query.filter(Flow.dst_ip == dst_ip)
        if port:
            from sqlalchemy import or_
            query = query.filter(or_(Flow.src_port == port, Flow.dst_port == port))
        if protocol: query = query.filter(Flow.protocol == protocol)
        if source: query = query.filter(Flow.source == source)

        flows = query.order_by(Flow.last_seen.desc()).limit(limit).all()
        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try: d["l7_metadata"] = json.loads(d["l7_metadata"])
                except: pass
            result.append(d)
        return result

    def get_entity_flows(self, ip: str, limit: int = 50, source: str = None,
                         interface: str = None, capture_session_id: str = None,
                         offset: int = 0, sensor_node_id: str = None,
                         protocol: str = None, port: int = None,
                         after_packet_count: int = None, after_id: int = None) -> List[Dict]:
        """Get flows involving a specific IP."""
        session = self._get_session()
        query = session.query(Flow).filter(
            or_(Flow.src_ip == ip, Flow.dst_ip == ip)
        )
        if source:
            if source == "live":
                query = query.filter(Flow.source.like("live%"))
            else:
                query = query.filter(Flow.source == source)
        if interface:
            query = query.filter(Flow.capture_interface == interface)
        if capture_session_id:
            query = query.filter(Flow.capture_session_id == capture_session_id)
        if sensor_node_id:
            query = query.filter(Flow.sensor_node_id == sensor_node_id)
        if protocol:
            query = query.filter(func.upper(Flow.protocol) == str(protocol).upper())
        if port is not None:
            query = query.filter(or_(Flow.src_port == int(port), Flow.dst_port == int(port)))
        if after_packet_count is not None and after_id is not None:
            query = query.filter(or_(
                Flow.packet_count < int(after_packet_count),
                and_(Flow.packet_count == int(after_packet_count), Flow.id < int(after_id)),
            ))
        flows = query.order_by(Flow.packet_count.desc(), Flow.id.desc()).offset(max(0, int(offset))).limit(limit).all()

        result = []
        for f in flows:
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns}
            if d.get("l7_metadata"):
                try:
                    d["l7_metadata"] = json.loads(d["l7_metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            d["flow_id"] = format_flow_id(
                d["src_ip"], d["src_port"], d["dst_ip"], d["dst_port"], d["protocol"]
            )
            result.append(d)
        return result

    # ----------------------------------------------------------------
    # Passive Asset Intelligence
    # ----------------------------------------------------------------

    def upsert_asset_profile(self, profile: Dict):
        """Persist a rebuildable asset profile for an IP and source."""
        session = self._get_session()
        source = profile.get("source") or "live"
        row = session.query(AssetProfile).filter_by(
            entity_ip=profile["ip"], source=source
        ).first()
        if row is None:
            row = AssetProfile(entity_ip=profile["ip"], source=source)
            session.add(row)
        row.scope = profile.get("scope")
        row.subnet = profile.get("subnet")
        row.role = profile.get("role")
        row.role_confidence = profile.get("role_confidence", 0.0)
        row.profile_data = json.dumps(profile, sort_keys=True)
        row.profiled_at = profile.get("profiled_at", time.time())
        session.commit()

    def get_asset_profile(self, ip: str, source: str = None) -> Optional[Dict]:
        session = self._get_session()
        query = session.query(AssetProfile).filter_by(entity_ip=ip)
        if source:
            query = query.filter_by(source=source)
        row = query.order_by(AssetProfile.profiled_at.desc()).first()
        if not row:
            return None
        try:
            return json.loads(row.profile_data)
        except (json.JSONDecodeError, TypeError):
            return None

    def upsert_evidence_links(self, links: List[Dict]):
        """Persist stable references from an investigation without duplicating reruns."""
        if not links:
            return
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        for link in links:
            values = dict(link)
            if isinstance(values.get("details"), (dict, list)):
                values["details"] = json.dumps(values["details"], sort_keys=True)
            stmt = sqlite_insert(EvidenceLink).values(**values)
            stmt = stmt.on_conflict_do_update(
                index_elements=["entity_ip", "source", "evidence_type", "evidence_ref"],
                set_={
                    "timestamp": stmt.excluded.timestamp,
                    "summary": stmt.excluded.summary,
                    "details": stmt.excluded.details,
                    "confidence": stmt.excluded.confidence,
                },
            )
            session.execute(stmt)
        session.commit()

    def get_evidence_links(self, ip: str, source: str = None) -> List[Dict]:
        session = self._get_session()
        query = session.query(EvidenceLink).filter_by(entity_ip=ip)
        if source:
            query = query.filter_by(source=source)
        rows = query.order_by(EvidenceLink.timestamp.desc()).all()
        result = []
        for row in rows:
            item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
            if item.get("details"):
                try:
                    item["details"] = json.loads(item["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(item)
        return result

    # ----------------------------------------------------------------
    # Versioned Endpoint Identity
    # ----------------------------------------------------------------

    @staticmethod
    def _identity_row(row: EndpointIdentity) -> Dict:
        item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        if item.get("evidence_json"):
            try:
                item["evidence"] = json.loads(item["evidence_json"])
            except (json.JSONDecodeError, TypeError):
                item["evidence"] = []
        else:
            item["evidence"] = []
        item.pop("evidence_json", None)
        item["capture_interface"] = item.get("capture_interface") or None
        item["capture_session_id"] = item.get("capture_session_id") or None
        return item

    def upsert_endpoint_identities(self, identities: List[Dict]) -> int:
        """Persist bounded identity projections without changing flow evidence."""
        if not identities:
            return 0
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        now = time.time()
        try:
            for identity in identities:
                values = dict(identity)
                values.setdefault("sensor_node_id", self.local_sensor_node_id())
                values["capture_interface"] = values.get("capture_interface") or ""
                values["capture_session_id"] = values.get("capture_session_id") or ""
                values["evidence_json"] = json.dumps(values.pop("evidence", []), sort_keys=True)
                values.setdefault("identity_state", "address_only")
                values.setdefault("evidence_completeness", 0.0)
                values.setdefault("next_action", None)
                values.setdefault("observation_count", 0)
                values["updated_at"] = float(values.get("updated_at") or now)
                stmt = sqlite_insert(EndpointIdentity).values(**values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[
                        "entity_ip", "source", "capture_interface", "capture_session_id", "model_version",
                    ],
                    set_={
                        "identity_type": stmt.excluded.identity_type,
                        "identity_label": stmt.excluded.identity_label,
                        "confidence": stmt.excluded.confidence,
                        "verification": stmt.excluded.verification,
                        "identity_state": stmt.excluded.identity_state,
                        "evidence_completeness": stmt.excluded.evidence_completeness,
                        "next_action": stmt.excluded.next_action,
                        "observation_count": stmt.excluded.observation_count,
                        "evidence_json": stmt.excluded.evidence_json,
                        "first_seen": stmt.excluded.first_seen,
                        "last_seen": stmt.excluded.last_seen,
                        "updated_at": stmt.excluded.updated_at,
                    },
                )
                session.execute(stmt)
            session.commit()
            try:
                events = []
                for identity in identities:
                    payload = dict(identity)
                    payload.setdefault("sensor_node_id", self.local_sensor_node_id())
                    payload.setdefault("updated_at", now)
                    events.append({
                        "event_key": "identity:{node}:{ip}:{source}:{model}:{interface}:{session}".format(
                            node=payload["sensor_node_id"], ip=payload.get("entity_ip"), source=payload.get("source"),
                            model=payload.get("model_version"), interface=payload.get("capture_interface") or "",
                            session=payload.get("capture_session_id") or "",
                        ),
                        "operation": "identity", "payload": payload,
                    })
                self.enqueue_graph_events(events)
            except Exception:
                logger.exception("Unable to enqueue endpoint identity graph projection events")
            return len(identities)
        except Exception:
            session.rollback()
            raise

    def get_endpoint_identity(self, ip: str, source: str = None, interface: str = None,
                              capture_session_id: str = None, sensor_node_id: str = None) -> Optional[Dict]:
        rows = self.get_endpoint_identities(
            source=source, interface=interface, capture_session_id=capture_session_id, ip=ip, limit=1,
            sensor_node_id=sensor_node_id,
        )
        return rows[0] if rows else None

    def get_endpoint_identities(self, source: str = None, interface: str = None,
                                capture_session_id: str = None, ip: str = None,
                                limit: int = 1000, sensor_node_id: str = None) -> List[Dict]:
        session = self._get_session()
        query = session.query(EndpointIdentity)
        if ip:
            query = query.filter(EndpointIdentity.entity_ip == ip)
        if source:
            if source == "live":
                query = query.filter(EndpointIdentity.source.like("live%"))
            elif source.startswith("live_") and "#" not in source:
                query = query.filter(EndpointIdentity.source.like(f"{source}#%"))
            else:
                query = query.filter(EndpointIdentity.source == source)
        if interface:
            query = query.filter(EndpointIdentity.capture_interface == interface)
        if capture_session_id:
            query = query.filter(EndpointIdentity.capture_session_id == capture_session_id)
        if sensor_node_id:
            query = query.filter(EndpointIdentity.sensor_node_id == sensor_node_id)
        rows = query.order_by(EndpointIdentity.updated_at.desc(), EndpointIdentity.entity_ip.asc()).limit(limit).all()
        return [self._identity_row(row) for row in rows]

    @staticmethod
    def _identity_observation_row(row: IdentityObservation) -> Dict:
        item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        try:
            item["value"] = json.loads(item.pop("value_json") or "{}")
        except (TypeError, ValueError):
            item["value"] = {}
            item.pop("value_json", None)
        return item

    def upsert_identity_observations(self, observations: List[Dict]) -> int:
        """Store deduplicated identity facts; raw packet content is never accepted."""
        if not observations:
            return 0
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        now = time.time()
        try:
            for observation in observations:
                value = dict(observation)
                value.setdefault("id", str(uuid.uuid4()))
                value.setdefault("sensor_node_id", self.local_sensor_node_id())
                value.setdefault("created_at", now)
                value["value_json"] = json.dumps(value.pop("value", {}), sort_keys=True)
                value.setdefault("fingerprint", sha256(json.dumps({
                    "subject_ip": value.get("subject_ip"), "source": value.get("source"),
                    "interface": value.get("capture_interface"), "session": value.get("capture_session_id"),
                    "type": value.get("observation_type"), "ref": value.get("evidence_ref"),
                }, sort_keys=True, default=str).encode("utf-8")).hexdigest())
                statement = sqlite_insert(IdentityObservation).values(**value)
                statement = statement.on_conflict_do_update(
                    index_elements=["fingerprint"],
                    set_={
                        "last_seen": statement.excluded.last_seen,
                        "occurrence_count": IdentityObservation.occurrence_count + statement.excluded.occurrence_count,
                        "confidence": statement.excluded.confidence,
                        "value_json": statement.excluded.value_json,
                        "fresh_until": statement.excluded.fresh_until,
                    },
                )
                session.execute(statement)
            session.commit()
            return len(observations)
        except Exception:
            session.rollback()
            raise

    def get_identity_observations(self, *, subject_ip: str = None, source: str = None,
                                  interface: str = None, capture_session_id: str = None,
                                  observation_type: str = None, limit: int = 500) -> List[Dict]:
        session = self._get_session()
        query = session.query(IdentityObservation)
        if subject_ip:
            query = query.filter(IdentityObservation.subject_ip == subject_ip)
        if source:
            if source == "live":
                query = query.filter(IdentityObservation.source.like("live%"))
            elif source.startswith("live_") and "#" not in source:
                query = query.filter(IdentityObservation.source.like(f"{source}#%"))
            else:
                query = query.filter(IdentityObservation.source == source)
        if interface:
            query = query.filter(IdentityObservation.capture_interface == interface)
        if capture_session_id:
            query = query.filter(IdentityObservation.capture_session_id == capture_session_id)
        if observation_type:
            query = query.filter(IdentityObservation.observation_type == observation_type)
        rows = query.order_by(IdentityObservation.last_seen.desc(), IdentityObservation.subject_ip.asc()).limit(max(1, min(int(limit), 5000))).all()
        return [self._identity_observation_row(row) for row in rows]

    def get_unconfirmed_identity_observations(self, *, source: str = None, interface: str = None,
                                              capture_session_id: str = None, limit: int = 500) -> List[Dict]:
        targets = self.get_identity_observations(
            source=source, interface=interface, capture_session_id=capture_session_id,
            observation_type="arp_target", limit=5000,
        )
        confirmations = self.get_identity_observations(
            source=source, interface=interface, capture_session_id=capture_session_id,
            observation_type="active_arp_confirmation", limit=5000,
        )
        confirmed = {
            (item.get("subject_ip"), item.get("source"), item.get("capture_interface"), item.get("capture_session_id"))
            for item in confirmations
        }
        confirmed_ips = {item.get("subject_ip") for item in confirmations}
        pending = []
        for target in targets:
            key = (target.get("subject_ip"), target.get("source"), target.get("capture_interface"), target.get("capture_session_id"))
            if key in confirmed:
                continue
            # Older confirmations were stored under the aggregate `live` source.
            # Keep them effective for concrete live capture scopes during migration.
            if target.get("source", "").startswith("live") and target.get("subject_ip") in confirmed_ips:
                continue
            pending.append(target)
        return pending[:max(1, min(int(limit), 5000))]

    # ----------------------------------------------------------------
    # Endpoint process and service attribution
    # ----------------------------------------------------------------

    @staticmethod
    def _endpoint_observation_row(row: EndpointProcessObservation) -> Dict:
        item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        for stored, public in (("hashes_json", "hashes"), ("service_names_json", "service_names"), ("details_json", "details")):
            try:
                item[public] = json.loads(item.get(stored) or ("[]" if public == "service_names" else "{}"))
            except (TypeError, ValueError):
                item[public] = [] if public == "service_names" else {}
            item.pop(stored, None)
        return item

    def upsert_endpoint_process_observations(self, observations: List[Dict]) -> int:
        """Store redacted Sysmon/socket observations idempotently."""
        if not observations:
            return 0
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        session = self._get_session()
        now = time.time()
        try:
            for observation in observations:
                value = dict(observation)
                value.setdefault("sensor_node_id", self.local_sensor_node_id())
                value.setdefault("id", str(uuid.uuid4()))
                value.setdefault("created_at", now)
                value["hashes_json"] = json.dumps(value.pop("hashes", {}), sort_keys=True)
                value["service_names_json"] = json.dumps(sorted(set(value.pop("service_names", []) or [])))
                value["details_json"] = json.dumps(value.pop("details", {}), sort_keys=True)
                statement = sqlite_insert(EndpointProcessObservation).values(**value)
                statement = statement.on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "service_names_json": statement.excluded.service_names_json,
                        "details_json": statement.excluded.details_json,
                        "hashes_json": statement.excluded.hashes_json,
                        "created_at": statement.excluded.created_at,
                    },
                )
                session.execute(statement)
            session.commit()
            try:
                self.enqueue_graph_events([
                    {"event_key": f"process:{item.get('sensor_node_id')}:{item.get('id')}", "operation": "process_observation", "payload": item}
                    for item in observations
                ])
            except Exception:
                logger.exception("Unable to enqueue endpoint graph projection events")
            return len(observations)
        except Exception:
            session.rollback()
            raise

    def find_endpoint_process_observations(
        self, *, sensor_node_id: str = None, protocol: str = None,
        local_ip: str = None, local_port: int = None, remote_ip: str = None,
        remote_port: int = None, observed_at: float = None, skew_seconds: float = 15.0,
        limit: int = 16,
    ) -> List[Dict]:
        """Return only exact tuple candidates from a bounded observation window."""
        session = self._get_session()
        query = session.query(EndpointProcessObservation).filter(
            EndpointProcessObservation.sensor_node_id == (sensor_node_id or self.local_sensor_node_id())
        )
        if protocol:
            query = query.filter(EndpointProcessObservation.protocol == str(protocol).upper())
        if local_ip:
            query = query.filter(EndpointProcessObservation.local_ip == local_ip)
        if local_port is not None:
            query = query.filter(EndpointProcessObservation.local_port == int(local_port))
        if remote_ip:
            query = query.filter(EndpointProcessObservation.remote_ip == remote_ip)
        if remote_port is not None:
            query = query.filter(EndpointProcessObservation.remote_port == int(remote_port))
        if observed_at is not None:
            query = query.filter(
                EndpointProcessObservation.observed_at >= float(observed_at) - float(skew_seconds),
                EndpointProcessObservation.observed_at <= float(observed_at) + float(skew_seconds),
            )
        rows = query.order_by(EndpointProcessObservation.observed_at.desc()).limit(max(1, min(int(limit), 64))).all()
        return [self._endpoint_observation_row(row) for row in rows]

    def endpoint_telemetry_status(self, sensor_node_id: str = None) -> Dict:
        node = sensor_node_id or self.local_sensor_node_id()
        with self.session_scope() as session:
            query = session.query(EndpointProcessObservation).filter_by(sensor_node_id=node)
            count = query.count()
            latest = query.order_by(EndpointProcessObservation.observed_at.desc()).first()
            total_flows = session.query(Flow).filter(Flow.sensor_node_id == node).count()
            exact = session.query(Flow).filter(
                Flow.sensor_node_id == node,
                Flow.l7_metadata.like('%"provenance"%sysmon_exact%'),
            ).count()
            fallback = session.query(Flow).filter(
                Flow.sensor_node_id == node,
                Flow.l7_metadata.like('%"provenance"%socket_fallback%'),
            ).count()
            ambiguous = session.query(Flow).filter(
                Flow.sensor_node_id == node,
                Flow.l7_metadata.like('%"provenance"%ambiguous%'),
            ).count()
            latest_at = latest.observed_at if latest else None
        attributed = exact + fallback
        return {
            "sensor_node_id": node,
            "observations": count,
            "latest_observation_at": latest_at,
            "attributed_flows": attributed,
            "sysmon_exact_flows": exact,
            "socket_fallback_flows": fallback,
            "ambiguous_flows": ambiguous,
            "unattributed_flows": max(0, total_flows - attributed - ambiguous),
            "total_flows": total_flows,
            "coverage": attributed / total_flows if total_flows else 0.0,
            "exact_coverage": exact / total_flows if total_flows else 0.0,
        }

    def fleet_node_counters(self, sensor_node_id: str) -> Dict[str, Any]:
        with self.session_scope() as session:
            active_sessions = session.query(CaptureSession).filter(
                CaptureSession.sensor_node_id == sensor_node_id,
                func.lower(CaptureSession.status).in_(("running", "active", "draining")),
                CaptureSession.processing_state.in_(("running", "draining")),
            ).count()
            alert_count = session.query(Alert).filter(Alert.sensor_node_id == sensor_node_id).count()
            urgent_alerts = session.query(Alert).filter(
                Alert.sensor_node_id == sensor_node_id,
                func.upper(Alert.severity).in_(("HIGH", "CRITICAL")),
            ).count()
            finding_count = session.query(
                func.count(func.distinct(DetectionFinding.fingerprint))
            ).filter(
                DetectionFinding.sensor_node_id == sensor_node_id,
                DetectionFinding.is_suppressed.is_(False),
            ).scalar() or 0
            maximum_risk = session.query(func.max(RiskSnapshot.priority_score)).filter(
                RiskSnapshot.sensor_node_id == sensor_node_id,
            ).scalar() or 0.0
        return {
            "active_sessions": int(active_sessions),
            "alert_count": int(alert_count),
            "urgent_alerts": int(urgent_alerts),
            "finding_count": int(finding_count),
            "priority_score": float(maximum_risk),
        }

    def count_detection_fingerprints(self, *, include_suppressed: bool = False) -> int:
        """Count globally deduplicated canonical findings through a short-lived session."""
        with self.session_scope() as session:
            query = session.query(func.count(func.distinct(DetectionFinding.fingerprint)))
            if not include_suppressed:
                query = query.filter(DetectionFinding.is_suppressed.is_(False))
            return int(query.scalar() or 0)

    def get_endpoint_process_observations(
        self, *, ip: str = None, sensor_node_id: str = None, limit: int = 100,
    ) -> List[Dict]:
        session = self._get_session()
        query = session.query(EndpointProcessObservation).filter(
            EndpointProcessObservation.sensor_node_id == (sensor_node_id or self.local_sensor_node_id())
        )
        if ip:
            query = query.filter(or_(
                EndpointProcessObservation.local_ip == ip,
                EndpointProcessObservation.remote_ip == ip,
            ))
        rows = query.order_by(EndpointProcessObservation.observed_at.desc()).limit(max(1, min(int(limit), 500))).all()
        return [self._endpoint_observation_row(row) for row in rows]

    # ----------------------------------------------------------------
    # Sensor mesh controller state
    # ----------------------------------------------------------------

    @staticmethod
    def _mesh_node_row(row: SensorNode) -> Dict:
        item = {column.name: getattr(row, column.name) for column in row.__table__.columns}
        for field in ("capabilities_json", "health_json"):
            try:
                item[field[:-5]] = json.loads(item.get(field) or "{}")
            except (TypeError, ValueError):
                item[field[:-5]] = {}
            item.pop(field, None)
        return item

    def upsert_sensor_node(self, node: Dict) -> Dict:
        session = self._get_session()
        now = time.time()
        node_id = str(node["id"])
        row = session.query(SensorNode).filter_by(id=node_id).first()
        if row is None:
            row = SensorNode(id=node_id, name=str(node.get("name") or node_id), created_at=now)
            session.add(row)
        for field in ("name", "certificate_fingerprint", "status", "platform", "agent_version", "revoked_at", "revoke_reason"):
            if field in node:
                setattr(row, field, node[field])
        if "capabilities" in node:
            row.capabilities_json = json.dumps(node["capabilities"] or {}, sort_keys=True)
        if "health" in node:
            row.health_json = json.dumps(node["health"] or {}, sort_keys=True)
        row.last_seen_at = float(node.get("last_seen_at") or now)
        session.commit()
        return self._mesh_node_row(row)

    def get_sensor_node(self, node_id: str) -> Optional[Dict]:
        row = self._get_session().query(SensorNode).filter_by(id=node_id).first()
        return self._mesh_node_row(row) if row else None

    def list_sensor_nodes(self, limit: int = 100) -> List[Dict]:
        rows = self._get_session().query(SensorNode).order_by(SensorNode.last_seen_at.desc()).limit(max(1, min(int(limit), 500))).all()
        return [self._mesh_node_row(row) for row in rows]

    def create_mesh_enrollment(self, enrollment_id: str, token_hash: str, expires_at: float,
                               requested_name: str = None, max_uses: int = 1,
                               created_by: str = "local-operator") -> Dict:
        session = self._get_session()
        row = MeshEnrollment(
            id=enrollment_id, token_hash=token_hash, requested_name=requested_name,
            expires_at=float(expires_at), max_uses=max(1, int(max_uses)), created_at=time.time(), created_by=created_by,
        )
        session.add(row)
        session.commit()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns if column.name != "token_hash"}

    def consume_mesh_enrollment(self, token_hash: str) -> Optional[Dict]:
        session = self._get_session()
        row = session.query(MeshEnrollment).filter_by(token_hash=token_hash).first()
        if not row or row.revoked_at or row.expires_at <= time.time() or row.used_count >= row.max_uses:
            return None
        row.used_count += 1
        session.commit()
        return {column.name: getattr(row, column.name) for column in row.__table__.columns if column.name != "token_hash"}

    def revoke_sensor_node(self, node_id: str, reason: str) -> bool:
        session = self._get_session()
        row = session.query(SensorNode).filter_by(id=node_id).first()
        if not row:
            return False
        row.status, row.revoked_at, row.revoke_reason = "revoked", time.time(), str(reason)[:1000]
        session.commit()
        return True

    def decommission_sensor_node(self, node_id: str, reason: str) -> bool:
        """Revoke node access and invalidate commands while preserving historical evidence."""
        session = self._get_session()
        row = session.query(SensorNode).filter_by(id=node_id).first()
        if not row:
            return False
        now = time.time()
        row.status = "decommissioned"
        row.revoked_at = now
        row.revoke_reason = str(reason)[:1000]
        queued = session.query(MeshCommand).filter(
            MeshCommand.sensor_node_id == node_id,
            MeshCommand.status == "queued",
        ).all()
        for command in queued:
            command.status = "rejected"
            command.result_json = json.dumps({"reason": "node_decommissioned"}, sort_keys=True)
            command.completed_at = now
        session.commit()
        return True

    def record_mesh_receipt(self, node_id: str, sequence: int, envelope_type: str,
                            payload_hash: str, detail: str = "") -> Dict:
        session = self._get_session()
        existing = session.query(MeshIngestReceipt).filter_by(sensor_node_id=node_id, sequence=int(sequence)).first()
        if existing:
            return {
                "accepted": existing.payload_hash == payload_hash,
                "duplicate": existing.payload_hash == payload_hash,
                "reason": "duplicate" if existing.payload_hash == payload_hash else "sequence_payload_conflict",
            }
        row = MeshIngestReceipt(
            sensor_node_id=node_id, sequence=int(sequence), envelope_type=str(envelope_type),
            payload_hash=payload_hash, received_at=time.time(), detail=str(detail)[:2000],
        )
        session.add(row)
        session.commit()
        return {"accepted": True, "duplicate": False, "reason": "accepted"}

    def update_sensor_node_health(self, node_id: str, health: Dict, capabilities: Dict = None) -> Optional[Dict]:
        row = self.get_sensor_node(node_id)
        if not row:
            return None
        merged_health = dict(row.get("health") or {})
        merged_health.update(health or {})
        return self.upsert_sensor_node({
            "id": node_id, "health": merged_health, "capabilities": capabilities if capabilities is not None else row.get("capabilities"),
            "status": "online", "last_seen_at": time.time(),
        })

    def queue_mesh_command(self, command_id: str, node_id: str, action: str, arguments: Dict,
                           expires_at: float, idempotency_key: str, requested_by: str = "local-operator") -> Dict:
        session = self._get_session()
        existing = session.query(MeshCommand).filter_by(idempotency_key=idempotency_key).first()
        if existing:
            return self._row_dict(existing)
        row = MeshCommand(
            id=command_id, sensor_node_id=node_id, action=action,
            arguments_json=json.dumps(arguments or {}, sort_keys=True), status="queued", requested_at=time.time(),
            expires_at=float(expires_at), requested_by=requested_by, idempotency_key=idempotency_key,
        )
        session.add(row)
        session.commit()
        return self._row_dict(row)

    def pending_mesh_commands(self, node_id: str, limit: int = 20) -> List[Dict]:
        session = self._get_session()
        rows = session.query(MeshCommand).filter(
            MeshCommand.sensor_node_id == node_id, MeshCommand.status == "queued", MeshCommand.expires_at > time.time(),
        ).order_by(MeshCommand.requested_at.asc()).limit(max(1, min(int(limit), 100))).all()
        result = []
        for row in rows:
            item = self._row_dict(row)
            item["arguments"] = json.loads(item.pop("arguments_json") or "{}")
            result.append(item)
        return result

    def get_mesh_command(self, command_id: str, sensor_node_id: str = None) -> Optional[Dict]:
        session = self._get_session()
        query = session.query(MeshCommand).filter(MeshCommand.id == str(command_id))
        if sensor_node_id:
            query = query.filter(MeshCommand.sensor_node_id == sensor_node_id)
        row = query.first()
        if not row:
            return None
        item = self._row_dict(row)
        for stored, public in (("arguments_json", "arguments"), ("result_json", "result")):
            try:
                item[public] = json.loads(item.pop(stored) or "{}")
            except (TypeError, ValueError):
                item[public] = {}
        return item

    def complete_mesh_command(self, command_id: str, status: str, result: Dict = None,
                              sensor_node_id: str = None) -> Optional[Dict]:
        session = self._get_session()
        query = session.query(MeshCommand).filter_by(id=command_id)
        if sensor_node_id:
            query = query.filter(MeshCommand.sensor_node_id == sensor_node_id)
        row = query.first()
        if not row:
            return None
        if row.status != "queued":
            return self._row_dict(row)
        if status not in {"completed", "failed", "rejected"}:
            raise ValueError("Invalid mesh command completion status")
        row.status, row.result_json, row.completed_at = str(status), json.dumps(result or {}, sort_keys=True), time.time()
        session.commit()
        return self._row_dict(row)

    def mesh_export_batch(self, flow_after_id: int = 0, observation_after: float = 0.0,
                          session_after: float = 0.0, limit: int = 250,
                          alert_after_id: int = 0, finding_after_id: int = 0,
                          hardware_after_id: int = 0) -> Dict[str, List[Dict]]:
        """Read a bounded local-node telemetry delta for an outbound agent."""
        session = self._get_session()
        node_id = self.local_sensor_node_id()
        max_rows = max(1, min(int(limit), 1000))
        flows = session.query(Flow).filter(
            Flow.sensor_node_id == node_id, Flow.id > int(flow_after_id),
        ).order_by(Flow.id.asc()).limit(max_rows).all()
        flow_rows = []
        for row in flows:
            item = self._row_dict(row)
            try:
                item["l7_metadata"] = json.loads(item.get("l7_metadata") or "{}")
            except (ValueError, TypeError):
                item["l7_metadata"] = {}
            flow_rows.append(item)
        observations = session.query(EndpointProcessObservation).filter(
            EndpointProcessObservation.sensor_node_id == node_id,
            EndpointProcessObservation.created_at > float(observation_after),
        ).order_by(EndpointProcessObservation.created_at.asc()).limit(max_rows).all()
        capture_sessions = session.query(CaptureSession).filter(
            CaptureSession.sensor_node_id == node_id,
            CaptureSession.started_at > float(session_after),
        ).order_by(CaptureSession.started_at.asc()).limit(max_rows).all()
        alerts = session.query(Alert).filter(
            Alert.sensor_node_id == node_id, Alert.id > int(alert_after_id),
        ).order_by(Alert.id.asc()).limit(max_rows).all()
        findings = session.query(DetectionFinding).filter(
            DetectionFinding.sensor_node_id == node_id, DetectionFinding.id > int(finding_after_id),
        ).order_by(DetectionFinding.id.asc()).limit(max_rows).all()
        hardware = session.query(HardwareObservation).filter(
            HardwareObservation.sensor_node_id == node_id, HardwareObservation.id > int(hardware_after_id),
        ).order_by(HardwareObservation.id.asc()).limit(max_rows).all()
        alert_rows = []
        for row in alerts:
            item = self._row_dict(row)
            try:
                item["evidence"] = json.loads(item.pop("evidence") or "{}")
            except (ValueError, TypeError):
                item["evidence"] = {}
            alert_rows.append(item)
        hardware_rows = []
        for row in hardware:
            item = self._row_dict(row)
            try:
                item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            except (ValueError, TypeError):
                item["metadata"] = {}
            hardware_rows.append(item)
        return {
            "flows": flow_rows,
            "endpoint_observations": [self._endpoint_observation_row(row) for row in observations],
            "sessions": [self._row_dict(row) for row in capture_sessions],
            "alerts": alert_rows,
            "findings": [self._finding_dict(row) for row in findings],
            "hardware_observations": hardware_rows,
        }

    # ----------------------------------------------------------------
    # Evidence graph transactional outbox
    # ----------------------------------------------------------------

    def _enqueue_graph_events_in_session(
        self,
        session,
        events: List[Dict],
    ) -> int:
        if not events:
            return 0
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        rows = []
        for event in events:
            key = str(event.get("event_key") or "")
            operation = str(event.get("operation") or "")
            if not key or not operation:
                continue
            rows.append({
                "event_key": key,
                "operation": operation,
                "payload_json": json.dumps(
                    event.get("payload") or {}, sort_keys=True
                ),
                "created_at": time.time(),
                "attempts": 0,
                "next_attempt_at": time.time(),
            })
        if not rows:
            return 0
        statement = sqlite_insert(GraphOutbox)
        statement = statement.on_conflict_do_update(
            index_elements=["event_key"],
            set_={
                "payload_json": statement.excluded.payload_json,
                "created_at": statement.excluded.created_at,
                "attempts": 0,
                "next_attempt_at": statement.excluded.next_attempt_at,
                "lease_owner": None,
                "lease_expires_at": None,
                "dead_lettered_at": None,
                "delivered_at": None,
                "error": None,
            },
        )
        session.execute(statement, rows)
        return len(rows)

    def enqueue_graph_events(self, events: List[Dict]) -> int:
        if not events:
            return 0
        with self.session_scope(write=True) as session:
            count = self._enqueue_graph_events_in_session(session, events)
            return count

    def pending_graph_events(self, limit: int = 250) -> List[Dict]:
        now = time.time()
        with self.session_scope() as session:
            rows = session.query(GraphOutbox).filter(
                GraphOutbox.delivered_at.is_(None),
                GraphOutbox.dead_lettered_at.is_(None),
                or_(GraphOutbox.next_attempt_at.is_(None), GraphOutbox.next_attempt_at <= now),
            ).order_by(GraphOutbox.id.asc()).limit(max(1, min(int(limit), 1000))).all()
            result = []
            for row in rows:
                item = self._row_dict(row)
                try:
                    item["payload"] = json.loads(item.pop("payload_json") or "{}")
                except (TypeError, ValueError):
                    item["payload"] = {}
                result.append(item)
            return result

    def claim_graph_events(self, owner: str, limit: int = 250, lease_seconds: int = 30) -> List[Dict]:
        now = time.time()
        lease_until = now + max(5, min(int(lease_seconds), 300))
        with self.session_scope(write=True) as session:
            rows = session.query(GraphOutbox).filter(
                GraphOutbox.delivered_at.is_(None),
                GraphOutbox.dead_lettered_at.is_(None),
                or_(GraphOutbox.next_attempt_at.is_(None), GraphOutbox.next_attempt_at <= now),
                or_(GraphOutbox.lease_expires_at.is_(None), GraphOutbox.lease_expires_at < now),
            ).order_by(GraphOutbox.id.asc()).limit(max(1, min(int(limit), 1000))).all()
            for row in rows:
                row.lease_owner = str(owner)
                row.lease_expires_at = lease_until
            result = []
            for row in rows:
                item = self._row_dict(row)
                try:
                    item["payload"] = json.loads(item.pop("payload_json") or "{}")
                except (TypeError, ValueError):
                    item["payload"] = {}
                result.append(item)
            return result

    def mark_graph_event(self, event_id: int, delivered: bool, error: Optional[str] = None) -> None:
        with self.session_scope(write=True) as session:
            row = session.query(GraphOutbox).filter_by(id=int(event_id)).first()
            if not row:
                return
            row.attempts = int(row.attempts or 0) + 1
            row.last_attempt_at = time.time()
            row.delivered_at = time.time() if delivered else None
            row.error = (str(error)[:2000] if error else None)
            row.lease_owner = None
            row.lease_expires_at = None
            if delivered:
                row.next_attempt_at = None
                row.dead_lettered_at = None
            else:
                attempts = int(row.attempts or 0)
                row.next_attempt_at = time.time() + min(60.0, float(2 ** min(attempts, 6)))
                if attempts >= 10:
                    row.dead_lettered_at = time.time()

    def graph_outbox_status(self) -> Dict:
        now = time.time()
        with self.session_scope() as session:
            pending = session.query(GraphOutbox).filter(GraphOutbox.delivered_at.is_(None), GraphOutbox.dead_lettered_at.is_(None)).count()
            latest = session.query(GraphOutbox).filter(GraphOutbox.delivered_at.is_not(None)).order_by(GraphOutbox.delivered_at.desc()).first()
            failed = session.query(GraphOutbox).filter(GraphOutbox.delivered_at.is_(None), GraphOutbox.error.is_not(None), GraphOutbox.dead_lettered_at.is_(None)).count()
            dead = session.query(GraphOutbox).filter(GraphOutbox.dead_lettered_at.is_not(None)).count()
            oldest = session.query(GraphOutbox).filter(GraphOutbox.delivered_at.is_(None), GraphOutbox.dead_lettered_at.is_(None)).order_by(GraphOutbox.created_at.asc()).first()
            return {
                "pending": pending,
                "failed": failed,
                "dead_lettered": dead,
                "oldest_pending_at": oldest.created_at if oldest else None,
                "pending_age_seconds": max(0.0, now - float(oldest.created_at)) if oldest else 0.0,
                "last_materialized_at": latest.delivered_at if latest else None,
            }

    # ----------------------------------------------------------------
    # Carved File Operations
    # ----------------------------------------------------------------

    def insert_carved_file(self, entity_ip: str, filename: str, extension: str,
                           sha256: str, size: int, flow_src: str = None,
                           flow_dst: str = None, timestamp: float = 0.0,
                           vt_results: Dict = None, data: bytes = None,
                           source: str = "live", commit: bool = True,
                           sensor_node_id: str = None):
        """Insert a carved file using SQLAlchemy (deduplicates by sha256)."""
        session = self._get_session()
        existing = session.query(CarvedFile).filter_by(sha256=sha256).first()
        if not existing:
            cf = CarvedFile(
                entity_ip=entity_ip, filename=filename, extension=extension,
                sha256=sha256, size=size, flow_src=flow_src, flow_dst=flow_dst,
                timestamp=timestamp, vt_results=json.dumps(vt_results) if vt_results else None,
                data=data, source=source,
                sensor_node_id=sensor_node_id or self.local_sensor_node_id(),
            )
            session.add(cf)
            if commit:
                session.commit()
                try:
                    self.enqueue_graph_events([{
                        "event_key": f"artifact:{cf.sensor_node_id}:{cf.sha256}", "operation": "artifact",
                        "payload": {
                            "id": cf.id, "entity_ip": cf.entity_ip, "filename": cf.filename,
                            "extension": cf.extension, "sha256": cf.sha256, "size": cf.size,
                            "timestamp": cf.timestamp, "source": cf.source,
                            "capture_session_id": cf.capture_session_id, "sensor_node_id": cf.sensor_node_id,
                        },
                    }])
                except Exception:
                    logger.exception("Unable to enqueue artifact graph projection event")

    def get_carved_files(self, entity_ip: str = None, source: str = None,
                         sensor_node_id: str = None) -> List[Dict]:
        """Get carved files, optionally filtered."""
        session = self._get_session()
        query = session.query(CarvedFile)
        if entity_ip:
            query = query.filter_by(entity_ip=entity_ip)
        if source:
            if source == "live":
                query = query.filter(CarvedFile.source.like("live%"))
            else:
                query = query.filter_by(source=source)
        if sensor_node_id:
            query = query.filter(CarvedFile.sensor_node_id == sensor_node_id)
        
        files = query.order_by(CarvedFile.timestamp.desc()).all()
        result = []
        for f in files:
            # Exclude binary data from list view
            d = {c.name: getattr(f, c.name) for c in f.__table__.columns if c.name != "data"}
            if d.get("vt_results"):
                try:
                    d["vt_results"] = json.loads(d["vt_results"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    # ----------------------------------------------------------------
    # Daily Stats & Timeline Operations
    # ----------------------------------------------------------------

    def merge_daily_stats(self, packets: int, bytes_count: int, flows: int,
                          protocol_dist: Dict, port_dist: Dict, top_talkers: Dict,
                          source: str = "live", commit: bool = True):
        """Merge a snapshot into today's daily stats using SQLAlchemy."""
        session = self._get_session()
        today_str = date.today().isoformat()
        stats = session.query(DailyStats).filter_by(date=today_str, source=source).first()

        if stats:
            old_proto = json.loads(stats.protocol_distribution or "{}")
            old_port = json.loads(stats.port_distribution or "{}")
            old_talkers = json.loads(stats.top_talkers or "{}")

            for k, v in protocol_dist.items():
                old_proto[k] = old_proto.get(k, 0) + v
            for k, v in port_dist.items():
                old_port[str(k)] = old_port.get(str(k), 0) + v
            for k, v in top_talkers.items():
                old_talkers[k] = old_talkers.get(k, 0) + v

            stats.total_packets = (stats.total_packets or 0) + packets
            stats.total_bytes = (stats.total_bytes or 0) + bytes_count
            stats.total_flows = flows
            stats.snapshot_count = (stats.snapshot_count or 0) + 1
            stats.protocol_distribution = json.dumps(old_proto)
            stats.port_distribution = json.dumps(old_port)
            stats.top_talkers = json.dumps(old_talkers)
        else:
            stats = DailyStats(
                date=today_str, source=source, total_packets=packets,
                total_bytes=bytes_count, total_flows=flows, snapshot_count=1,
                protocol_distribution=json.dumps(protocol_dist),
                port_distribution=json.dumps(port_dist),
                top_talkers=json.dumps(top_talkers)
            )
            session.add(stats)

        if commit:
            session.commit()

    def merge_timeline(self, timeline_buckets: Dict, source: str = "live", commit: bool = True):
        """Merge timeline buckets into the timeline table using SQLAlchemy."""
        session = self._get_session()
        today_str = date.today().isoformat()
        for bucket_key, bucket_val in timeline_buckets.items():
            ts = int(bucket_key)
            item = session.query(Timeline).filter_by(timestamp=ts, source=source).first()
            if item:
                item.packets = (item.packets or 0) + bucket_val["packets"]
                item.bytes = (item.bytes or 0) + bucket_val["bytes"]
            else:
                item = Timeline(
                    timestamp=ts, date=today_str, source=source,
                    packets=bucket_val["packets"], bytes=bucket_val["bytes"]
                )
                session.add(item)
        if commit:
            session.commit()

    def get_today_stats(self, source: str = "live") -> Dict:
        """Get today's aggregated stats. Handles generic 'live' source by summing across all interfaces."""
        session = self._get_session()
        today_str = date.today().isoformat()
        
        if source == "live":
            rows = session.query(DailyStats).filter(DailyStats.date == today_str, DailyStats.source.like("live%")).all()
        else:
            rows = session.query(DailyStats).filter_by(date=today_str, source=source).all()

        if not rows:
            return {
                "date": today_str, "total_packets": 0, "total_bytes": 0,
                "total_flows": 0, "snapshot_count": 0,
                "protocol_distribution": {}, "port_distribution": {},
                "top_talkers": {}, "traffic_timeline": {},
                "flow_records": [], "recent_alerts": [],
                "global_threat_map": []
            }

        # Aggregate multiple rows if needed
        stats = {
            "date": today_str, "total_packets": 0, "total_bytes": 0,
            "total_flows": 0, "snapshot_count": 0,
            "protocol_distribution": {}, "port_distribution": {},
            "top_talkers": {}
        }
        
        for row in rows:
            stats["total_packets"] += row.total_packets
            stats["total_bytes"] += row.total_bytes
            stats["total_flows"] += row.total_flows
            stats["snapshot_count"] += row.snapshot_count
            
            for key, target in [("protocol_distribution", "protocol_distribution"), 
                                ("port_distribution", "port_distribution"), 
                                ("top_talkers", "top_talkers")]:
                val = getattr(row, key)
                if val:
                    try:
                        d = json.loads(val)
                        for k, v in d.items():
                            stats[target][k] = stats[target].get(k, 0) + v
                    except: pass

        # Live flow rows are authoritative. Older engines persisted cumulative
        # windows into DailyStats, so derive exact counters here as a repair path
        # as well as a guard against future accumulator drift.
        flow_query = session.query(Flow).filter(Flow.session_date == today_str)
        if source == "live":
            flow_query = flow_query.filter(Flow.source.like("live%"))
        elif source.startswith("live_"):
            flow_query = flow_query.filter(or_(
                Flow.source == source,
                Flow.source.startswith(f"{source}#", autoescape=True),
            ))
        else:
            flow_query = None
        if flow_query is not None:
            live_flows = flow_query.all()
            stats["total_packets"] = sum(int(flow.packet_count or 0) for flow in live_flows)
            stats["total_bytes"] = sum(int(flow.byte_count or 0) for flow in live_flows)
            stats["total_flows"] = len(live_flows)
            stats["protocol_distribution"] = {}
            stats["port_distribution"] = {}
            stats["top_talkers"] = {}
            for flow in live_flows:
                packets = int(flow.packet_count or 0)
                byte_count = int(flow.byte_count or 0)
                stats["protocol_distribution"][flow.protocol] = stats["protocol_distribution"].get(flow.protocol, 0) + packets
                if flow.dst_port:
                    port = str(flow.dst_port)
                    stats["port_distribution"][port] = stats["port_distribution"].get(port, 0) + packets
                stats["top_talkers"][flow.src_ip] = stats["top_talkers"].get(flow.src_ip, 0) + byte_count

        # Fetch aggregated timeline
        if source == "live":
            tl_rows = session.query(Timeline).filter(Timeline.date == today_str, Timeline.source.like("live%")).all()
        else:
            tl_rows = session.query(Timeline).filter_by(date=today_str, source=source).all()
        
        timeline = {}
        for r in tl_rows:
            ts_str = str(r.timestamp)
            if ts_str not in timeline:
                timeline[ts_str] = {"time": r.timestamp, "packets": 0, "bytes": 0}
            timeline[ts_str]["packets"] += r.packets
            timeline[ts_str]["bytes"] += r.bytes
        
        stats["traffic_timeline"] = dict(sorted(timeline.items(), key=lambda x: int(x[0]), reverse=True)[:60])
        stats["flow_records"] = self.get_flows(source=source, limit=50)
        stats["recent_alerts"] = self.get_alerts(source=source, limit=100)
        stats["global_threat_map"] = self._build_threat_map(source=source)

        return stats

    def get_today_live_interfaces(self) -> List[str]:
        """Return interfaces that have persisted live statistics today."""
        session = self._get_session()
        today_str = date.today().isoformat()
        rows = session.query(DailyStats.source).filter(
            DailyStats.date == today_str,
            DailyStats.source.like("live_%"),
        ).distinct().all()
        return sorted({row[0][5:] for row in rows if row[0] and row[0].startswith("live_")})

    def _build_threat_map(self, source: str = "live") -> List[Dict]:
        """Build threat map from today's flows only."""
        session = self._get_session()
        today_str = date.today().isoformat()
        # Filter flows with l7_metadata
        if source == "live":
            flows = session.query(Flow).filter(
                Flow.l7_metadata.isnot(None),
                Flow.session_date == today_str,
                Flow.source.like("live%")
            ).limit(500).all()
        else:
            flows = session.query(Flow).filter(
                Flow.l7_metadata.isnot(None),
                Flow.session_date == today_str,
                Flow.source == source
            ).limit(500).all()
        
        threat_map = {}
        from core.packet_engine.utils import is_internal
        for f in flows:
            try:
                meta = json.loads(f.l7_metadata) if f.l7_metadata else {}
                geo = meta.get("geoip", {})
                if geo and geo.get("lat") is not None:
                    # Identify which IP is the external one
                    ext_ip = f.src_ip if not is_internal(f.src_ip) else f.dst_ip
                    if is_internal(ext_ip): continue # Both internal
                    
                    lat = float(geo.get("lat", 0.0))
                    lng = float(geo.get("lng", 0.0))
                    if lat == 0.0 and lng == 0.0: continue
                    
                    if ext_ip not in threat_map:
                        threat_map[ext_ip] = {
                            "ip": ext_ip, "lat": lat, "lng": lng,
                            "country": geo.get("country", "Unknown"), "count": 1
                        }
                    else:
                        threat_map[ext_ip]["count"] += 1
            except (json.JSONDecodeError, TypeError):
                pass
        return list(threat_map.values())

    def get_timeline(self, limit: int = 60, source: str = "live") -> List[Dict]:
        """Get recent timeline data points."""
        session = self._get_session()
        today_str = date.today().isoformat()
        rows = session.query(Timeline).filter_by(date=today_str, source=source).order_by(Timeline.timestamp.desc()).limit(limit).all()
        result = [{"time": r.timestamp, "packets": r.packets, "bytes": r.bytes} for r in rows]
        result.sort(key=lambda x: x["time"])
        return result

    # ----------------------------------------------------------------
    # System Metadata
    # ----------------------------------------------------------------

    def set_metadata(self, key: str, value: str):
        """Set a system metadata value."""
        session = self._get_session()
        meta = session.query(SystemMetadata).filter_by(key=key).first()
        if meta:
            meta.value = value
        else:
            meta = SystemMetadata(key=key, value=value)
            session.add(meta)
        session.commit()
        if key == "mesh.local_node_id":
            self._publish_local_sensor_node_id(value)

    def get_metadata(self, key: str, default: str = None) -> str:
        """Get a system metadata value."""
        session = self._get_session()
        meta = session.query(SystemMetadata).filter_by(key=key).first()
        return meta.value if meta else default

    # ----------------------------------------------------------------
    # Headless service identities
    # ----------------------------------------------------------------

    def ensure_service_principal(self, principal_id: str, role: str, token_hash: str,
                                 scopes: List[str]) -> Dict[str, Any]:
        now = time.time()
        with self.session_scope(write=True) as session:
            row = session.query(ServicePrincipal).filter_by(id=str(principal_id)).first()
            if row is None:
                row = ServicePrincipal(
                    id=str(principal_id), role=str(role), token_hash=str(token_hash),
                    scopes_json=json.dumps(sorted(set(scopes)), separators=(",", ":")),
                    created_at=now,
                )
                session.add(row)
            elif row.revoked_at is not None:
                raise RuntimeError("The WatchTower service principal has been revoked")
            elif row.token_hash != str(token_hash):
                raise RuntimeError("The WatchTower service credential does not match its installation record")
            row.last_used_at = now
            return {
                "id": row.id, "role": row.role,
                "scopes": self._json_field(row.scopes_json, []),
                "created_at": row.created_at, "last_used_at": row.last_used_at,
                "revoked_at": row.revoked_at,
            }

    def service_principal(self, principal_id: str) -> Optional[Dict[str, Any]]:
        with self.session_scope() as session:
            row = session.query(ServicePrincipal).filter_by(id=str(principal_id)).first()
            if row is None:
                return None
            return {
                "id": row.id, "role": row.role,
                "scopes": self._json_field(row.scopes_json, []),
                "created_at": row.created_at, "last_used_at": row.last_used_at,
                "revoked_at": row.revoked_at,
            }

    # ----------------------------------------------------------------
    # Offline forensic case storage
    # ----------------------------------------------------------------

    def create_forensic_case(self, values: Dict[str, Any]) -> Dict[str, Any]:
        case_id = str(values["id"])
        now = float(values.get("created_at") or time.time())
        with self.session_scope(write=True) as session:
            row = session.query(ForensicCase).filter_by(id=case_id).first()
            if row is None:
                row = ForensicCase(id=case_id, created_at=now)
                session.add(row)
            row.analysis_id = str(values.get("analysis_id") or row.analysis_id or case_id)
            row.sha256 = str(values.get("sha256") or values.get("pcap_sha256") or row.sha256 or "")
            row.filename = values.get("filename", row.filename)
            row.byte_count = int(values.get("byte_count", values.get("file_size", row.byte_count or 0)) or 0)
            row.capture_started_at = values.get("capture_started_at", values.get("capture_start", row.capture_started_at))
            row.capture_ended_at = values.get("capture_ended_at", values.get("capture_end", row.capture_ended_at))
            row.link_type = values.get("link_type", row.link_type)
            row.parser_version = values.get("parser_version", row.parser_version)
            row.backend = values.get("backend", row.backend)
            row.backend_version = values.get("backend_version", row.backend_version)
            row.state = str(values.get("state") or row.state or "created")
            row.progress = float(values.get("progress", row.progress or 0.0) or 0.0)
            row.warnings_json = json.dumps(values.get("warnings", self._json_field(row.warnings_json, [])), sort_keys=True, default=str)
            row.visibility_limitations_json = json.dumps(
                values.get("visibility_limitations", self._json_field(row.visibility_limitations_json, [])),
                sort_keys=True,
                default=str,
            )
            row.report_hash = values.get("report_hash", values.get("report_sha256", row.report_hash))
            row.retained_input = bool(values.get("retained_input", row.retained_input))
            row.retention_mode = str(values.get("retention_mode") or row.retention_mode or "discard")
            row.encryption_format = values.get("encryption_format", row.encryption_format)
            row.configuration_hash = values.get("configuration_hash", row.configuration_hash)
            row.pipeline_version = values.get("pipeline_version", row.pipeline_version)
            row.completed_at = values.get("completed_at", row.completed_at)
            session.flush()
            return self._forensic_case_dict(row)

    def get_forensic_case(self, case_id: str) -> Dict[str, Any] | None:
        with self.session_scope() as session:
            row = session.query(ForensicCase).filter_by(id=str(case_id)).first()
            return self._forensic_case_dict(row) if row else None

    def list_forensic_cases(self, limit: int = 100) -> List[Dict[str, Any]]:
        bounded = max(1, min(int(limit or 100), 500))
        with self.session_scope() as session:
            rows = session.query(ForensicCase).order_by(
                ForensicCase.created_at.desc(), ForensicCase.id.desc(),
            ).limit(bounded).all()
            return [self._forensic_case_dict(row) for row in rows]

    @staticmethod
    def _revision_component_payload(session, analysis_id: str) -> Dict[str, Any]:
        rows = session.query(ForensicEvidenceComponent).filter_by(
            analysis_id=str(analysis_id)
        ).order_by(ForensicEvidenceComponent.component.asc()).all()
        return {
            row.component: {
                "sha256": row.sha256,
                "record_count": int(row.record_count or 0),
                "state": row.state,
            }
            for row in rows
        }

    def save_forensic_case_revision(
        self,
        case_values: Dict[str, Any],
        revision_values: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """Atomically persist a case compatibility row and immutable revision."""
        case_id = str(case_values["id"])
        analysis_id = str(revision_values["analysis_id"])
        now = float(case_values.get("created_at") or time.time())
        with self.session_scope(write=True) as session:
            case_row = session.query(ForensicCase).filter_by(id=case_id).first()
            revision = session.query(ForensicAnalysisRevision).filter_by(
                analysis_id=analysis_id
            ).first()
            if revision is not None and (
                revision.case_id != case_id
                or revision.pcap_sha256 != str(revision_values["pcap_sha256"])
                or revision.pipeline_version != str(revision_values["pipeline_version"])
                or revision.configuration_hash != str(revision_values["configuration_hash"])
                or revision.backend != str(revision_values["backend"])
            ):
                raise ValueError("analysis identity cannot be reassigned")

            if case_row is None:
                case_row = ForensicCase(id=case_id, created_at=now)
                session.add(case_row)

            if revision is not None and revision.state == "complete":
                incoming_hash = revision_values.get("report_hash")
                if incoming_hash and revision.report_hash and incoming_hash != revision.report_hash:
                    raise ValueError("completed analysis report hash cannot be changed")
                case_row.analysis_id = revision.analysis_id
                case_row.sha256 = revision.pcap_sha256
                case_row.configuration_hash = revision.configuration_hash
                case_row.pipeline_version = revision.pipeline_version
                case_row.backend = revision.backend
                case_row.backend_version = revision.backend_version
                case_row.state = "complete"
                case_row.progress = 100.0
                case_row.report_hash = revision.report_hash
                case_row.completed_at = revision.completed_at
                session.flush()
                return {
                    "case": self._forensic_case_dict(case_row),
                    "revision": self._forensic_revision_dict(revision),
                }

            case_row.analysis_id = analysis_id
            case_row.sha256 = str(
                case_values.get("sha256")
                or case_values.get("pcap_sha256")
                or case_row.sha256
                or ""
            )
            case_row.filename = case_values.get("filename", case_row.filename)
            case_row.byte_count = int(
                case_values.get(
                    "byte_count",
                    case_values.get("file_size", case_row.byte_count or 0),
                )
                or 0
            )
            case_row.capture_started_at = case_values.get(
                "capture_started_at",
                case_values.get("capture_start", case_row.capture_started_at),
            )
            case_row.capture_ended_at = case_values.get(
                "capture_ended_at",
                case_values.get("capture_end", case_row.capture_ended_at),
            )
            case_row.link_type = case_values.get("link_type", case_row.link_type)
            case_row.parser_version = case_values.get(
                "parser_version", case_row.parser_version
            )
            case_row.backend = case_values.get("backend", case_row.backend)
            case_row.backend_version = case_values.get(
                "backend_version", case_row.backend_version
            )
            case_row.state = str(case_values.get("state") or case_row.state or "created")
            case_row.progress = float(
                case_values.get("progress", case_row.progress or 0.0) or 0.0
            )
            case_row.warnings_json = json.dumps(
                case_values.get(
                    "warnings", self._json_field(case_row.warnings_json, [])
                ),
                sort_keys=True,
                default=str,
            )
            case_row.visibility_limitations_json = json.dumps(
                case_values.get(
                    "visibility_limitations",
                    self._json_field(case_row.visibility_limitations_json, []),
                ),
                sort_keys=True,
                default=str,
            )
            case_row.report_hash = case_values.get(
                "report_hash",
                case_values.get("report_sha256", case_row.report_hash),
            )
            case_row.retained_input = bool(
                case_values.get("retained_input", case_row.retained_input)
            )
            case_row.retention_mode = str(
                case_values.get("retention_mode")
                or case_row.retention_mode
                or "discard"
            )
            case_row.encryption_format = case_values.get(
                "encryption_format", case_row.encryption_format
            )
            case_row.configuration_hash = str(revision_values["configuration_hash"])
            case_row.pipeline_version = str(revision_values["pipeline_version"])
            case_row.completed_at = case_values.get(
                "completed_at", case_row.completed_at
            )

            if revision is None:
                revision = ForensicAnalysisRevision(
                    analysis_id=analysis_id,
                    case_id=case_id,
                    pcap_sha256=str(revision_values["pcap_sha256"]),
                    pipeline_version=str(revision_values["pipeline_version"]),
                    configuration_hash=str(revision_values["configuration_hash"]),
                    backend=str(revision_values["backend"]),
                    created_at=float(revision_values.get("created_at") or now),
                )
                session.add(revision)
            revision.backend_version = revision_values.get(
                "backend_version", revision.backend_version
            )
            revision.state = str(
                revision_values.get("state") or revision.state or "queued"
            )
            revision.started_at = revision_values.get(
                "started_at", revision.started_at
            )
            revision.completed_at = revision_values.get(
                "completed_at", revision.completed_at
            )
            revision.report_hash = revision_values.get(
                "report_hash", revision.report_hash
            )
            revision.visibility_limitations_json = json.dumps(
                revision_values.get(
                    "visibility_limitations",
                    self._json_field(revision.visibility_limitations_json, []),
                ),
                sort_keys=True,
                default=str,
            )
            if revision.state in FORENSIC_TERMINAL_STATES:
                revision.evidence_components_json = json.dumps(
                    self._revision_component_payload(session, analysis_id),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            session.flush()
            return {
                "case": self._forensic_case_dict(case_row),
                "revision": self._forensic_revision_dict(revision),
            }

    def save_forensic_analysis_revision(self, values: Dict[str, Any]) -> Dict[str, Any]:
        analysis_id = str(values["analysis_id"])
        case_id = str(values["case_id"])
        with self.session_scope(write=True) as session:
            row = session.query(ForensicAnalysisRevision).filter_by(analysis_id=analysis_id).first()
            if row is None:
                row = ForensicAnalysisRevision(
                    analysis_id=analysis_id,
                    case_id=case_id,
                    pcap_sha256=str(values["pcap_sha256"]),
                    pipeline_version=str(values["pipeline_version"]),
                    configuration_hash=str(values["configuration_hash"]),
                    backend=str(values["backend"]),
                    created_at=float(values.get("created_at") or time.time()),
                )
                session.add(row)
            elif (
                row.case_id != case_id
                or row.pcap_sha256 != str(values["pcap_sha256"])
                or row.pipeline_version != str(values["pipeline_version"])
                or row.configuration_hash != str(values["configuration_hash"])
                or row.backend != str(values["backend"])
            ):
                raise ValueError("analysis identity cannot be reassigned")
            if row.state == "complete":
                incoming_hash = values.get("report_hash")
                if incoming_hash and row.report_hash and incoming_hash != row.report_hash:
                    raise ValueError("completed analysis report hash cannot be changed")
                case_row = session.query(ForensicCase).filter_by(id=case_id).first()
                if case_row is not None:
                    case_row.analysis_id = analysis_id
                    case_row.sha256 = row.pcap_sha256
                    case_row.configuration_hash = row.configuration_hash
                    case_row.pipeline_version = row.pipeline_version
                    case_row.backend = row.backend
                    case_row.backend_version = row.backend_version
                    case_row.state = "complete"
                    case_row.progress = 100.0
                    case_row.report_hash = row.report_hash
                    case_row.completed_at = row.completed_at
                session.flush()
                return self._forensic_revision_dict(row)
            row.backend_version = values.get("backend_version", row.backend_version)
            row.state = str(values.get("state") or row.state or "queued")
            row.started_at = values.get("started_at", row.started_at)
            row.completed_at = values.get("completed_at", row.completed_at)
            row.report_hash = values.get("report_hash", row.report_hash)
            row.visibility_limitations_json = json.dumps(
                values.get(
                    "visibility_limitations",
                    self._json_field(row.visibility_limitations_json, []),
                ),
                sort_keys=True,
                default=str,
            )
            if row.state in FORENSIC_TERMINAL_STATES:
                row.evidence_components_json = json.dumps(
                    self._revision_component_payload(session, analysis_id),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            case_row = session.query(ForensicCase).filter_by(id=case_id).first()
            if case_row is not None:
                case_row.analysis_id = analysis_id
                case_row.configuration_hash = row.configuration_hash
                case_row.pipeline_version = row.pipeline_version
            session.flush()
            return self._forensic_revision_dict(row)

    def get_forensic_analysis_revision(self, analysis_id: str) -> Dict[str, Any] | None:
        with self.session_scope() as session:
            row = session.query(ForensicAnalysisRevision).filter_by(analysis_id=str(analysis_id)).first()
            return self._forensic_revision_dict(row) if row else None

    def _publish_packet_index_component(
        self,
        session,
        row: ForensicPacketIndex,
        revision: ForensicAnalysisRevision,
    ) -> ForensicEvidenceComponent:
        now = time.time()
        component = session.query(ForensicEvidenceComponent).filter_by(
            analysis_id=row.analysis_id,
            component="packet_index",
        ).first()
        if component is None:
            component = ForensicEvidenceComponent(
                analysis_id=row.analysis_id,
                component="packet_index",
                case_id=row.case_id,
                created_at=now,
            )
            session.add(component)
        if component.case_id != row.case_id:
            raise ValueError("packet index component scope cannot be reassigned")
        if (
            component.sha256 != row.manifest_sha256
            or component.record_count != int(row.row_count or 0)
            or component.state != row.state
        ):
            component.sha256 = row.manifest_sha256
            component.record_count = int(row.row_count or 0)
            component.state = row.state
            component.updated_at = now
        session.flush()
        if revision.state in FORENSIC_TERMINAL_STATES:
            revision.evidence_components_json = json.dumps(
                self._revision_component_payload(session, row.analysis_id),
                sort_keys=True,
                separators=(",", ":"),
            )
            session.flush()
        return component

    def _backfill_forensic_packet_index_components(self) -> None:
        with self.session_scope(write=True) as session:
            rows = session.query(ForensicPacketIndex).filter_by(
                state="complete"
            ).all()
            for row in rows:
                revision = session.query(ForensicAnalysisRevision).filter_by(
                    analysis_id=row.analysis_id
                ).first()
                case_row = session.query(ForensicCase).filter_by(
                    id=row.case_id
                ).first()
                if (
                    revision is None
                    or case_row is None
                    or revision.case_id != row.case_id
                    or revision.pcap_sha256 != row.pcap_sha256
                    or case_row.sha256 != row.pcap_sha256
                ):
                    logger.warning(
                        "Skipping invalid packet-index component backfill for %s",
                        row.analysis_id,
                    )
                    continue
                self._publish_packet_index_component(session, row, revision)

    def save_forensic_packet_index(self, values: Dict[str, Any]) -> Dict[str, Any]:
        analysis_id = str(values["analysis_id"])
        with self.session_scope(write=True) as session:
            case_id = str(values["case_id"])
            pcap_sha256 = str(values["pcap_sha256"])
            revision = session.query(ForensicAnalysisRevision).filter_by(
                analysis_id=analysis_id
            ).first()
            if revision is None:
                raise ValueError("packet index requires an existing analysis revision")
            case_row = session.query(ForensicCase).filter_by(id=case_id).first()
            if case_row is None:
                raise ValueError("packet index case scope does not exist")
            if (
                revision.case_id != case_id
                or revision.pcap_sha256 != pcap_sha256
                or case_row.sha256 != pcap_sha256
            ):
                raise ValueError(
                    "packet index identity scope does not match revision/case/digest"
                )
            row = session.query(ForensicPacketIndex).filter_by(
                analysis_id=analysis_id
            ).first()
            identity = (
                case_id,
                pcap_sha256,
                int(values["schema_version"]),
            )
            if row is None:
                row = ForensicPacketIndex(
                    analysis_id=analysis_id,
                    case_id=identity[0],
                    pcap_sha256=identity[1],
                    schema_version=identity[2],
                    created_at=float(values.get("created_at") or time.time()),
                )
                session.add(row)
            elif (row.case_id, row.pcap_sha256, row.schema_version) != identity:
                raise ValueError("packet index identity cannot be reassigned")
            immutable = {
                "manifest_path": str(values["manifest_path"]),
                "manifest_sha256": str(values["manifest_sha256"]),
                "row_count": int(values.get("row_count") or 0),
                "partition_count": int(values.get("partition_count") or 0),
                "first_timestamp": values.get("first_timestamp"),
                "last_timestamp": values.get("last_timestamp"),
            }
            if row.state == "complete":
                for name, expected in immutable.items():
                    if getattr(row, name) != expected:
                        raise ValueError("completed packet index cannot be changed")
                requested_state = str(values.get("state") or "complete")
                if requested_state != row.state:
                    raise ValueError("completed packet index state is immutable")
            else:
                for name, value in immutable.items():
                    setattr(row, name, value)
                row.state = str(values.get("state") or "complete")
            self._publish_packet_index_component(session, row, revision)
            return self._row_dict(row)

    def get_forensic_packet_index(self, analysis_id: str) -> Dict[str, Any] | None:
        with self.session_scope() as session:
            row = session.query(ForensicPacketIndex).filter_by(
                analysis_id=str(analysis_id)
            ).first()
            return self._row_dict(row) if row else None

    @staticmethod
    def _bounded_conversation_metadata(value: Any) -> Dict[str, Any]:
        from core.detection.contracts import sanitize_evidence

        def bound(item: Any, depth: int = 0) -> Any:
            if depth >= 4:
                return str(item)[:512]
            if isinstance(item, dict):
                preferred = (
                    "server_name", "domain", "dns_query", "hostname", "remote_hostname",
                    "http_host", "http_method", "http_path", "content_type", "user_agent",
                    "tls_version", "cipher", "alpn", "ja3", "ja4", "authorization",
                )
                ordered_names = [
                    name for name in preferred if name in item
                ] + sorted(
                    (name for name in item if name not in preferred),
                    key=str,
                )
                return {
                    str(name)[:128]: bound(item[name], depth + 1)
                    for name in ordered_names[:32]
                }
            if isinstance(item, (list, tuple)):
                return [bound(child, depth + 1) for child in item[:32]]
            if isinstance(item, str):
                return item[:512]
            if item is None or isinstance(item, (bool, int, float)):
                return item
            return str(item)[:512]

        sanitized = sanitize_evidence(value if isinstance(value, dict) else {})
        return bound(sanitized)

    @staticmethod
    def _forensic_conversation_dict(row: ForensicConversation) -> Dict[str, Any]:
        item = WatchtowerDB._row_dict(row)
        item["application"] = WatchtowerDB._json_field(
            item.pop("application_json", None), {}
        )
        return item

    def save_forensic_conversations(
        self,
        case_id: str,
        analysis_id: str,
        conversations,
        *,
        completeness: str,
        publish_component: bool = True,
    ) -> Dict[str, Any]:
        case_id = str(case_id)
        analysis_id = str(analysis_id)
        completeness = str(completeness or "partial").lower()
        if completeness not in {"complete", "partial"}:
            raise ValueError("conversation completeness must be complete or partial")
        now = time.time()
        with self.session_scope(write=True) as session:
            revision = session.query(ForensicAnalysisRevision).filter_by(
                analysis_id=analysis_id
            ).first()
            case_row = session.query(ForensicCase).filter_by(id=case_id).first()
            if revision is None or case_row is None:
                raise ValueError("conversation scope requires an existing revision and case")
            if revision.case_id != case_id:
                raise ValueError("conversation scope does not match analysis revision")

            for delta in tuple(conversations or ()):
                key = delta.key
                identity = {
                    "case_id": case_id,
                    "analysis_id": analysis_id,
                    "sensor_node_id": str(key.sensor_node_id),
                    "source": str(key.source),
                    "interface": str(key.interface),
                    "session_id": str(key.session_id),
                    "protocol": str(key.protocol).upper(),
                    "endpoint_a": [str(key.endpoint_a[0]), int(key.endpoint_a[1])],
                    "endpoint_b": [str(key.endpoint_b[0]), int(key.endpoint_b[1])],
                }
                conversation_id = sha256(
                    json.dumps(
                        identity, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                application = self._bounded_conversation_metadata(delta.application)
                values = {
                    **identity,
                    "id": conversation_id,
                    "initiator_ip": str(delta.initiator[0]),
                    "initiator_port": int(delta.initiator[1]),
                    "responder_ip": str(delta.responder[0]),
                    "responder_port": int(delta.responder[1]),
                    "first_seen": float(delta.first_seen),
                    "last_seen": float(delta.event_time),
                    "to_responder_packets": int(delta.to_responder_packets),
                    "to_responder_bytes": int(delta.to_responder_bytes),
                    "to_initiator_packets": int(delta.to_initiator_packets),
                    "to_initiator_bytes": int(delta.to_initiator_bytes),
                    "syn_count": int(delta.syn_count),
                    "syn_ack_count": int(delta.syn_ack_count),
                    "rst_count": int(delta.rst_count),
                    "established": bool(delta.established),
                    "application_json": json.dumps(
                        application, sort_keys=True, separators=(",", ":"), default=str
                    ),
                    "generation": int(delta.generation),
                    "backend": str(delta.backend or "unknown"),
                    "source_type": str(delta.source_type or "network"),
                    "completeness": completeness,
                }
                row = session.query(ForensicConversation).filter_by(
                    id=conversation_id
                ).first()
                if revision.state == "complete" and (
                    row is None or row.generation < values["generation"]
                ):
                    raise ValueError(
                        "completed native conversation evidence is immutable"
                    )
                if row is not None and row.generation > values["generation"]:
                    continue
                if row is not None and row.generation == values["generation"]:
                    current = self._forensic_conversation_dict(row)
                    comparable = {
                        name: current.get(name)
                        for name in values
                        if name not in {"endpoint_a", "endpoint_b", "application_json"}
                    }
                    expected = {
                        name: value
                        for name, value in values.items()
                        if name not in {"endpoint_a", "endpoint_b", "application_json"}
                    }
                    if (
                        comparable != expected
                        or current["application"] != application
                    ):
                        raise ValueError("conversation generation cannot be changed")
                    continue
                if row is None:
                    row = ForensicConversation(
                        id=conversation_id,
                        analysis_id=analysis_id,
                        case_id=case_id,
                        sensor_node_id=identity["sensor_node_id"],
                        source=identity["source"],
                        interface=identity["interface"],
                        session_id=identity["session_id"],
                        protocol=identity["protocol"],
                        endpoint_a_ip=identity["endpoint_a"][0],
                        endpoint_a_port=identity["endpoint_a"][1],
                        endpoint_b_ip=identity["endpoint_b"][0],
                        endpoint_b_port=identity["endpoint_b"][1],
                        created_at=now,
                    )
                    session.add(row)
                for name, value in values.items():
                    if name in {
                        "id", "case_id", "analysis_id", "sensor_node_id", "source",
                        "interface", "session_id", "protocol", "endpoint_a", "endpoint_b",
                    }:
                        continue
                    setattr(row, name, value)
                row.updated_at = now

            session.flush()
            if not publish_component:
                return {
                    "analysis_id": analysis_id,
                    "case_id": case_id,
                    "component": "native_conversations",
                    "state": "pending",
                    "record_count": 0,
                    "sha256": None,
                }
            rows = session.query(ForensicConversation).filter_by(
                analysis_id=analysis_id
            ).order_by(ForensicConversation.id.asc()).all()
            canonical = [
                {
                    name: value
                    for name, value in self._forensic_conversation_dict(row).items()
                    if name not in {"created_at", "updated_at"}
                }
                for row in rows
            ]
            component_hash = sha256(
                json.dumps(
                    canonical, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
            ).hexdigest()
            component = session.query(ForensicEvidenceComponent).filter_by(
                analysis_id=analysis_id,
                component="native_conversations",
            ).first()
            if component is None:
                component = ForensicEvidenceComponent(
                    analysis_id=analysis_id,
                    component="native_conversations",
                    case_id=case_id,
                    created_at=now,
                )
                session.add(component)
            component_state = (
                "complete"
                if rows and all(row.completeness == "complete" for row in rows)
                else "partial"
                if rows
                else completeness
            )
            expected_component = {
                "sha256": component_hash,
                "record_count": len(rows),
                "state": component_state,
            }
            if revision.state == "complete":
                terminal_components = self._json_field(
                    revision.evidence_components_json, {}
                )
                stored_component = {
                    "sha256": component.sha256,
                    "record_count": int(component.record_count or 0),
                    "state": component.state,
                }
                if (
                    stored_component != expected_component
                    or terminal_components.get(
                        "native_conversations"
                    ) != expected_component
                ):
                    raise ValueError(
                        "completed native conversation component is immutable"
                    )
                return self._row_dict(component)
            if (
                component.sha256 != component_hash
                or component.record_count != len(rows)
                or component.state != component_state
            ):
                component.sha256 = component_hash
                component.record_count = len(rows)
                component.state = component_state
                component.updated_at = now
            session.flush()
            if revision.state in FORENSIC_TERMINAL_STATES:
                revision.evidence_components_json = json.dumps(
                    self._revision_component_payload(session, analysis_id),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                session.flush()
            return self._row_dict(component)

    def get_forensic_conversations(
        self, analysis_id: str, *, limit: int = 500, offset: int = 0
    ) -> Dict[str, Any]:
        limit = max(1, min(int(limit or 500), 5000))
        offset = max(0, int(offset or 0))
        with self.session_scope() as session:
            query = session.query(ForensicConversation).filter_by(
                analysis_id=str(analysis_id)
            ).order_by(
                ForensicConversation.first_seen.asc(),
                ForensicConversation.id.asc(),
            )
            rows = query.offset(offset).limit(limit + 1).all()
            has_more = len(rows) > limit
            rows = rows[:limit]
            return {
                "items": [self._forensic_conversation_dict(row) for row in rows],
                "next_cursor": offset + limit if has_more else None,
                "limit": limit,
                "mode": "native",
                "legacy_fallback": False,
            }

    @staticmethod
    def _bounded_deep_dissection_record(record: Any) -> Dict[str, Any]:
        from core.forensics.tshark_adapter import TSHARK_FIELD_ALLOWLIST

        if not isinstance(record, dict):
            raise ValueError("deep-dissection record must be an object")
        allowed = set(TSHARK_FIELD_ALLOWLIST)
        if not set(record).issubset(allowed):
            raise ValueError("deep-dissection record contains unsupported fields")
        bounded = {}
        for name in sorted(record):
            value = record[name]
            if isinstance(value, list):
                if not value or len(value) > 32:
                    raise ValueError("deep-dissection field list is invalid")
                bounded[name] = [
                    item[:2048] if isinstance(item, str) else item
                    for item in value
                    if isinstance(item, (str, int, float, bool))
                ]
                if len(bounded[name]) != len(value):
                    raise ValueError("deep-dissection field value is invalid")
            elif isinstance(value, (str, int, float, bool)):
                bounded[name] = value[:2048] if isinstance(value, str) else value
            else:
                raise ValueError("deep-dissection field value is invalid")
        encoded = json.dumps(
            bounded, sort_keys=True, separators=(",", ":"), default=str
        )
        if len(encoded.encode("utf-8")) > 256 * 1024:
            raise ValueError("deep-dissection record is oversized")
        return bounded

    def save_forensic_deep_dissection(
        self,
        case_id: str,
        analysis_id: str,
        records,
        *,
        completeness: str,
    ) -> Dict[str, Any]:
        case_id = str(case_id)
        analysis_id = str(analysis_id)
        completeness = str(completeness or "partial").lower()
        if completeness not in {"complete", "partial"}:
            raise ValueError("deep-dissection completeness must be complete or partial")
        bounded_records = tuple(
            self._bounded_deep_dissection_record(record)
            for record in tuple(records or ())
        )
        if len(bounded_records) > 10_000:
            raise ValueError("deep-dissection record count exceeds the evidence bound")
        now = time.time()
        with self.session_scope(write=True) as session:
            revision = session.query(ForensicAnalysisRevision).filter_by(
                analysis_id=analysis_id
            ).first()
            case_row = session.query(ForensicCase).filter_by(id=case_id).first()
            if revision is None or case_row is None:
                raise ValueError(
                    "deep-dissection scope requires an existing revision and case"
                )
            if revision.case_id != case_id:
                raise ValueError(
                    "deep-dissection scope does not match analysis revision"
                )

            existing_rows = session.query(
                ForensicDeepDissectionRecord
            ).filter_by(analysis_id=analysis_id).order_by(
                ForensicDeepDissectionRecord.ordinal.asc()
            ).all()
            if len(existing_rows) > len(bounded_records):
                raise ValueError("deep-dissection evidence cannot be truncated")
            for ordinal, fields in enumerate(bounded_records):
                fields_json = json.dumps(
                    fields, sort_keys=True, separators=(",", ":"), default=str
                )
                record_hash = sha256(fields_json.encode("utf-8")).hexdigest()
                record_id = sha256(
                    f"{analysis_id}:{ordinal}".encode("utf-8")
                ).hexdigest()
                row = (
                    existing_rows[ordinal]
                    if ordinal < len(existing_rows)
                    else None
                )
                if row is not None and (
                    row.ordinal != ordinal
                    or row.id != record_id
                    or row.case_id != case_id
                    or row.record_sha256 != record_hash
                    or row.fields_json != fields_json
                ):
                    raise ValueError("deep-dissection evidence is immutable")
                if row is None:
                    if revision.state == "complete":
                        raise ValueError(
                            "completed deep-dissection evidence is immutable"
                        )
                    session.add(
                        ForensicDeepDissectionRecord(
                            id=record_id,
                            analysis_id=analysis_id,
                            case_id=case_id,
                            ordinal=ordinal,
                            record_sha256=record_hash,
                            fields_json=fields_json,
                            created_at=now,
                        )
                    )
            session.flush()
            rows = session.query(ForensicDeepDissectionRecord).filter_by(
                analysis_id=analysis_id
            ).order_by(ForensicDeepDissectionRecord.ordinal.asc()).all()
            canonical = [
                {
                    "ordinal": int(row.ordinal),
                    "record_sha256": row.record_sha256,
                    "fields": self._json_field(row.fields_json, {}),
                }
                for row in rows
            ]
            component_hash = sha256(
                json.dumps(
                    canonical, sort_keys=True, separators=(",", ":"), default=str
                ).encode("utf-8")
            ).hexdigest()
            component = session.query(ForensicEvidenceComponent).filter_by(
                analysis_id=analysis_id,
                component="tshark_deep_dissection",
            ).first()
            expected_component = {
                "sha256": component_hash,
                "record_count": len(rows),
                "state": completeness,
            }
            if revision.state in FORENSIC_TERMINAL_STATES:
                terminal_components = self._json_field(
                    revision.evidence_components_json, {}
                )
                stored_component = (
                    {
                        "sha256": component.sha256,
                        "record_count": int(component.record_count or 0),
                        "state": component.state,
                    }
                    if component is not None
                    else None
                )
                if (
                    stored_component != expected_component
                    or terminal_components.get(
                        "tshark_deep_dissection"
                    ) != expected_component
                ):
                    raise ValueError(
                        "completed deep-dissection component is immutable"
                    )
                return self._row_dict(component)
            if component is None:
                component = ForensicEvidenceComponent(
                    analysis_id=analysis_id,
                    component="tshark_deep_dissection",
                    case_id=case_id,
                    created_at=now,
                )
                session.add(component)
            if component.case_id != case_id:
                raise ValueError(
                    "deep-dissection component scope cannot be reassigned"
                )
            if (
                component.sha256 != component_hash
                or component.record_count != len(rows)
                or component.state != completeness
            ):
                component.sha256 = component_hash
                component.record_count = len(rows)
                component.state = completeness
                component.updated_at = now
            session.flush()
            if revision.state in FORENSIC_TERMINAL_STATES:
                revision.evidence_components_json = json.dumps(
                    self._revision_component_payload(session, analysis_id),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                session.flush()
            return self._row_dict(component)

    def get_forensic_deep_dissection(
        self, analysis_id: str, *, limit: int = 100, offset: int = 0
    ) -> Dict[str, Any]:
        limit = max(1, min(int(limit or 100), 1_000))
        offset = max(0, int(offset or 0))
        with self.session_scope() as session:
            rows = session.query(ForensicDeepDissectionRecord).filter_by(
                analysis_id=str(analysis_id)
            ).order_by(
                ForensicDeepDissectionRecord.ordinal.asc()
            ).offset(offset).limit(limit + 1).all()
            has_more = len(rows) > limit
            rows = rows[:limit]
            return {
                "items": [
                    {
                        "ordinal": int(row.ordinal),
                        "record_sha256": row.record_sha256,
                        "fields": self._json_field(row.fields_json, {}),
                    }
                    for row in rows
                ],
                "next_cursor": offset + limit if has_more else None,
                "limit": limit,
                "component": "tshark_deep_dissection",
            }

    def get_forensic_evidence_components(
        self, analysis_id: str
    ) -> List[Dict[str, Any]]:
        with self.session_scope() as session:
            rows = session.query(ForensicEvidenceComponent).filter_by(
                analysis_id=str(analysis_id)
            ).order_by(ForensicEvidenceComponent.component.asc()).all()
            return [self._row_dict(row) for row in rows]

    def list_forensic_analysis_revisions(self, case_id: str) -> List[Dict[str, Any]]:
        with self.session_scope() as session:
            rows = session.query(ForensicAnalysisRevision).filter_by(
                case_id=str(case_id)
            ).order_by(
                ForensicAnalysisRevision.created_at.asc(),
                ForensicAnalysisRevision.analysis_id.asc(),
            ).all()
            return [self._forensic_revision_dict(row) for row in rows]

    def save_forensic_evidence_envelope(self, values: Dict[str, Any]) -> Dict[str, Any]:
        envelope_id = str(values["id"])
        with self.session_scope(write=True) as session:
            row = session.query(ForensicEvidenceEnvelope).filter_by(id=envelope_id).first()
            if row is None:
                row = ForensicEvidenceEnvelope(
                    id=envelope_id,
                    job_id=str(values["job_id"]),
                    case_id=str(values["case_id"]),
                    purpose=str(values["purpose"]),
                    created_at=float(values.get("created_at") or time.time()),
                )
                session.add(row)
            row.credential_reference = str(values["credential_reference"])
            row.nonce = str(values["nonce"])
            row.format_version = str(values["format_version"])
            row.digest = str(values["digest"])
            row.encrypted_path = str(values["encrypted_path"])
            session.flush()
            return self._forensic_envelope_dict(row)

    def get_forensic_evidence_envelope(self, job_id: str, purpose: str) -> Dict[str, Any] | None:
        with self.session_scope() as session:
            row = session.query(ForensicEvidenceEnvelope).filter_by(
                job_id=str(job_id), purpose=str(purpose)
            ).first()
            return self._forensic_envelope_dict(row) if row else None

    def delete_forensic_evidence_envelope(self, job_id: str, purpose: str) -> None:
        with self.session_scope(write=True) as session:
            session.query(ForensicEvidenceEnvelope).filter_by(
                job_id=str(job_id), purpose=str(purpose)
            ).delete(synchronize_session=False)

    def count_forensic_evidence_envelopes(self, case_id: str) -> int:
        with self.session_scope() as session:
            return int(session.query(ForensicEvidenceEnvelope).filter_by(
                case_id=str(case_id)
            ).count())

    def append_case_custody_event(self, case_id: str, event_type: str, digest: str,
                                  metadata: Dict[str, Any] | None = None,
                                  timestamp: float | None = None) -> Dict[str, Any]:
        with self.session_scope(write=True) as session:
            if session.query(ForensicCase.id).filter_by(id=str(case_id)).first() is None:
                raise ValueError(f"unknown forensic case: {case_id}")
            row = ForensicCaseCustodyEvent(
                case_id=str(case_id),
                event_type=str(event_type),
                digest=str(digest),
                metadata_json=json.dumps(metadata or {}, sort_keys=True, default=str),
                timestamp=float(timestamp or time.time()),
            )
            session.add(row)
            session.flush()
            return self._forensic_custody_dict(row)

    def get_case_custody(self, case_id: str, limit: int = 250) -> List[Dict[str, Any]]:
        bounded = max(1, min(int(limit or 250), 1000))
        with self.session_scope() as session:
            rows = session.query(ForensicCaseCustodyEvent).filter_by(
                case_id=str(case_id),
            ).order_by(ForensicCaseCustodyEvent.timestamp.asc(), ForensicCaseCustodyEvent.id.asc()).limit(bounded).all()
            return [self._forensic_custody_dict(row) for row in rows]

    def upsert_case_entity(self, case_id: str, values: Dict[str, Any]) -> Dict[str, Any]:
        entity_ip = str(values["ip"])
        with self.session_scope(write=True) as session:
            if session.query(ForensicCase.id).filter_by(id=str(case_id)).first() is None:
                raise ValueError(f"unknown forensic case: {case_id}")
            row = session.query(ForensicCaseEntity).filter_by(case_id=str(case_id), ip=entity_ip).first()
            if row is None:
                row = ForensicCaseEntity(case_id=str(case_id), ip=entity_ip)
                session.add(row)
            for field in (
                "mac", "hostname", "netbios_name", "username", "full_name", "os",
                "vendor", "device_type", "asset_role", "reverse_dns",
            ):
                if field in values:
                    setattr(row, field, values.get(field))
            row.provenance_json = json.dumps(values.get("provenance", self._json_field(row.provenance_json, {})), sort_keys=True, default=str)
            row.confidence = float(values.get("confidence", row.confidence or 0.0) or 0.0)
            row.total_packets = int(values.get("total_packets", row.total_packets or 0) or 0)
            row.total_bytes = int(values.get("total_bytes", row.total_bytes or 0) or 0)
            row.first_seen = values.get("first_seen", row.first_seen)
            row.last_seen = values.get("last_seen", row.last_seen)
            session.flush()
            return self._forensic_case_entity_dict(row)

    def get_case_entities(self, case_id: str, limit: int, cursor: str | None) -> Dict[str, Any]:
        bounded = max(1, min(int(limit or 100), 500))
        position = self._decode_storage_cursor(cursor)
        with self.session_scope() as session:
            query = session.query(ForensicCaseEntity).filter(ForensicCaseEntity.case_id == str(case_id))
            if position:
                query = query.filter(or_(
                    ForensicCaseEntity.confidence < float(position.get("confidence") or 0.0),
                    and_(
                        ForensicCaseEntity.confidence == float(position.get("confidence") or 0.0),
                        ForensicCaseEntity.total_bytes < int(position.get("total_bytes") or 0),
                    ),
                    and_(
                        ForensicCaseEntity.confidence == float(position.get("confidence") or 0.0),
                        ForensicCaseEntity.total_bytes == int(position.get("total_bytes") or 0),
                        ForensicCaseEntity.ip > str(position.get("ip") or ""),
                    ),
                ))
            rows = query.order_by(
                ForensicCaseEntity.confidence.desc(),
                ForensicCaseEntity.total_bytes.desc(),
                ForensicCaseEntity.ip.asc(),
            ).limit(bounded + 1).all()
            next_cursor = None
            if len(rows) > bounded:
                boundary = rows[bounded - 1]
                next_cursor = self._encode_storage_cursor({
                    "confidence": float(boundary.confidence or 0.0),
                    "total_bytes": int(boundary.total_bytes or 0),
                    "ip": str(boundary.ip or ""),
                })
                rows = rows[:bounded]
            return {
                "items": [self._forensic_case_entity_dict(row) for row in rows],
                "next_cursor": next_cursor,
                "cursor": cursor,
                "limit": bounded,
            }

    def count_case_entities(self, case_id: str) -> int:
        with self.session_scope() as session:
            return int(session.query(ForensicCaseEntity).filter_by(case_id=str(case_id)).count())

    def upsert_triage_flag(self, case_id: str, values: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        fingerprint = str(values["fingerprint"])
        with self.session_scope(write=True) as session:
            if session.query(ForensicCase.id).filter_by(id=str(case_id)).first() is None:
                raise ValueError(f"unknown forensic case: {case_id}")
            row = session.query(ForensicTriageFlag).filter_by(case_id=str(case_id), fingerprint=fingerprint).first()
            if row is None:
                row = ForensicTriageFlag(
                    case_id=str(case_id),
                    fingerprint=fingerprint,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            row.target_type = str(values.get("target_type") or row.target_type or "")
            row.target_id = str(values.get("target_id") or row.target_id or "")
            row.detector = values.get("detector", row.detector)
            row.source = values.get("source", row.source)
            row.finding_ids_json = json.dumps(values.get("finding_ids", self._json_field(row.finding_ids_json, [])), sort_keys=True, default=str)
            row.evidence_refs_json = json.dumps(values.get("evidence_refs", self._json_field(row.evidence_refs_json, [])), sort_keys=True, default=str)
            row.observed_values_json = json.dumps(values.get("observed_values", self._json_field(row.observed_values_json, {})), sort_keys=True, default=str)
            row.reason = str(values.get("reason") or row.reason or "")
            row.confidence = float(values.get("confidence", row.confidence or 0.0) or 0.0)
            row.status = str(values.get("status") or row.status or "open").lower()
            row.actor = str(values.get("actor") or row.actor or "system")
            row.first_seen = values.get("first_seen", row.first_seen)
            row.last_seen = values.get("last_seen", row.last_seen)
            row.updated_at = float(values.get("updated_at") or now)
            row.resolved_at = None if row.status == "open" else values.get("resolved_at", row.resolved_at or now)
            session.flush()
            return self._forensic_triage_flag_dict(row)

    def get_triage_flags(self, case_id: str, status: str = None, limit: int = 100, cursor: str | None = None) -> Dict[str, Any]:
        bounded = max(1, min(int(limit or 100), 500))
        position = self._decode_storage_cursor(cursor)
        status_priority = case(
            (ForensicTriageFlag.status == "open", 0),
            (ForensicTriageFlag.status == "confirmed", 1),
            (ForensicTriageFlag.status == "benign", 2),
            (ForensicTriageFlag.status == "dismissed", 3),
            else_=4,
        )
        last_seen_value = func.coalesce(ForensicTriageFlag.last_seen, 0.0)
        with self.session_scope() as session:
            query = session.query(ForensicTriageFlag).filter(ForensicTriageFlag.case_id == str(case_id))
            if status:
                query = query.filter(ForensicTriageFlag.status == str(status).lower())
            if position:
                query = query.filter(or_(
                    status_priority > int(position.get("status_rank") or 4),
                    and_(
                        status_priority == int(position.get("status_rank") or 4),
                        ForensicTriageFlag.confidence < float(position.get("confidence") or 0.0),
                    ),
                    and_(
                        status_priority == int(position.get("status_rank") or 4),
                        ForensicTriageFlag.confidence == float(position.get("confidence") or 0.0),
                        last_seen_value < float(position.get("last_seen") or 0.0),
                    ),
                    and_(
                        status_priority == int(position.get("status_rank") or 4),
                        ForensicTriageFlag.confidence == float(position.get("confidence") or 0.0),
                        last_seen_value == float(position.get("last_seen") or 0.0),
                        ForensicTriageFlag.id > int(position.get("id") or 0),
                    ),
                ))
            rows = query.order_by(
                status_priority.asc(),
                ForensicTriageFlag.confidence.desc(),
                last_seen_value.desc(),
                ForensicTriageFlag.id.asc(),
            ).limit(bounded + 1).all()
            next_cursor = None
            if len(rows) > bounded:
                boundary = rows[bounded - 1]
                next_cursor = self._encode_storage_cursor({
                    "status_rank": self._triage_status_rank(boundary.status),
                    "confidence": float(boundary.confidence or 0.0),
                    "last_seen": float(boundary.last_seen or 0.0),
                    "id": int(boundary.id or 0),
                })
                rows = rows[:bounded]
            return {
                "items": [self._forensic_triage_flag_dict(row) for row in rows],
                "next_cursor": next_cursor,
                "cursor": cursor,
                "limit": bounded,
            }

    # ----------------------------------------------------------------
    # Forensic Report Operations
    # ----------------------------------------------------------------

    def create_report(self, source: str, timestamp: float, analysis_mode: str = "memory",
                      backend: str = "python", total_bytes: int = 0) -> int:
        """Create a new forensic report and return its ID."""
        session = self._get_session()
        report = ForensicReport(source=source, timestamp=timestamp, status="RUNNING",
                                analysis_mode=analysis_mode, backend=backend, total_bytes=total_bytes)
        session.add(report)
        session.commit()
        return report.id

    def update_report(self, report_id: int, total_flows: int = 0,
                      total_entities: int = 0, total_alerts: int = 0,
                      summary: Dict = None, status: str = None,
                      bytes_processed: int = None, error: str = None,
                      spool_path: str = None):
        """Update a forensic report with final results."""
        session = self._get_session()
        report = session.query(ForensicReport).filter_by(id=report_id).first()
        if report:
            report.total_flows = total_flows
            report.total_entities = total_entities
            report.total_alerts = total_alerts
            report.summary = json.dumps(summary) if summary else None
            if status:
                report.status = status.upper()
                if status.upper() in {"COMPLETE", "PARTIAL", "CANCELLED", "FAILED"}:
                    report.completed_at = time.time()
            if bytes_processed is not None: report.bytes_processed = bytes_processed
            if error is not None: report.error = str(error)[:4000]
            if spool_path is not None: report.spool_path = str(spool_path)
            session.commit()

    def get_reports(self) -> List[Dict]:
        """List all forensic reports."""
        session = self._get_session()
        reports = session.query(ForensicReport).order_by(ForensicReport.timestamp.desc()).all()
        result = []
        for r in reports:
            d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
            if d.get("summary"):
                try:
                    d["summary"] = json.loads(d["summary"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result

    def get_report(self, report_id: int) -> Optional[Dict]:
        """Get a single forensic report."""
        session = self._get_session()
        r = session.query(ForensicReport).filter_by(id=report_id).first()
        if r:
            d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
            if d.get("summary"):
                try:
                    d["summary"] = json.loads(d["summary"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return d
        return None

    # ----------------------------------------------------------------
    # Reliability-safe repository projections
    # ----------------------------------------------------------------

    def save_pcap_analysis_job(self, values: Dict[str, Any], *, clear_paths: bool = False) -> None:
        """Persist one PCAP job without leaking a background-thread session."""
        with self.session_scope(write=True) as session:
            row = session.query(PcapAnalysisJob).filter_by(id=str(values["id"])).first()
            if row is None:
                row = PcapAnalysisJob(
                    id=str(values["id"]),
                    filename=str(values.get("filename") or ""),
                    file_size=int(values.get("file_size") or 0),
                    mode=str(values.get("mode") or "auto"),
                    backend=str(values.get("backend") or "python"),
                    source=str(values.get("source") or ""),
                    status=str(values.get("status") or "queued"),
                    created_at=float(values.get("created_at") or time.time()),
                )
                session.add(row)
            row.status = str(values.get("status") or row.status)
            row.report_id = values.get("report_id")
            row.started_at = values.get("started_at")
            row.completed_at = values.get("completed_at")
            row.bytes_processed = int(values.get("bytes_processed") or 0)
            row.progress = float(values.get("progress") or 0.0)
            row.summary_json = json.dumps(values.get("summary") or {}, sort_keys=True, default=str)
            row.error = values.get("error")
            row.retained_input = bool(values.get("retained_input"))
            row.input_path = None if clear_paths else values.get("path")
            row.keylog_path = None if clear_paths else values.get("keylog_path")
            row.case_id = values.get("case_id")
            row.analysis_id = values.get("analysis_id")
            row.pcap_sha256 = values.get("pcap_sha256")
            row.capture_started_at = values.get("capture_started_at")
            row.capture_ended_at = values.get("capture_ended_at")
            row.link_type = values.get("link_type")
            row.parser_version = values.get("parser_version")
            row.backend_version = values.get("backend_version")
            row.configuration_hash = values.get("configuration_hash")
            row.pipeline_version = values.get("pipeline_version")
            row.retention_mode = str(values.get("retention_mode") or "discard")
            row.encryption_format = values.get("encryption_format")

    def load_pcap_analysis_jobs(self) -> List[Dict[str, Any]]:
        """Return detached durable PCAP job records for restart reconciliation."""
        with self.session_scope() as session:
            rows = session.query(PcapAnalysisJob).order_by(PcapAnalysisJob.created_at.desc()).all()
            result = []
            for row in rows:
                item = self._row_dict(row)
                try:
                    item["summary"] = json.loads(item.pop("summary_json", None) or "{}")
                except (TypeError, ValueError):
                    item["summary"] = {}
                item["path"] = item.pop("input_path", None)
                item["case_id"] = item.get("case_id")
                item["analysis_id"] = item.get("analysis_id") or item.get("id")
                item["pcap_sha256"] = item.get("pcap_sha256")
                result.append(item)
            return result

    def node_endpoint_ips(self, sensor_node_id: str, limit: int = 20000) -> List[str]:
        """List distinct endpoint addresses observed by one sensor node."""
        bounded = max(1, min(int(limit), 100000))
        with self.session_scope() as session:
            source_ips = session.query(Flow.src_ip).filter(
                Flow.sensor_node_id == sensor_node_id,
            ).distinct().limit(bounded).all()
            target_ips = session.query(Flow.dst_ip).filter(
                Flow.sensor_node_id == sensor_node_id,
            ).distinct().limit(bounded).all()
            return sorted({str(item[0]) for item in source_ips + target_ips if item[0]})

    def node_flow_summary(
        self,
        sensor_node_id: str,
        *,
        interface: str = None,
        since: float = None,
    ) -> Dict[str, Any]:
        """Aggregate bounded node statistics using a short-lived read session."""
        cutoff = float(since or (time.time() - 86400))
        with self.session_scope() as session:
            query = session.query(Flow).filter(
                Flow.sensor_node_id == sensor_node_id,
                Flow.last_seen >= cutoff,
            )
            if interface:
                query = query.filter(Flow.capture_interface == interface)
            total_packets, total_bytes, total_flows = query.with_entities(
                func.coalesce(func.sum(Flow.packet_count), 0),
                func.coalesce(func.sum(Flow.byte_count), 0),
                func.count(Flow.id),
            ).one()
            protocol_rows = query.with_entities(
                Flow.protocol, func.coalesce(func.sum(Flow.packet_count), 0),
            ).group_by(Flow.protocol).all()
            port_rows = query.filter(Flow.dst_port > 0).with_entities(
                Flow.dst_port, func.coalesce(func.sum(Flow.packet_count), 0),
            ).group_by(Flow.dst_port).order_by(func.sum(Flow.packet_count).desc()).limit(100).all()
            bucket = func.cast(Flow.last_seen / 300, Integer)
            timeline_rows = query.with_entities(
                bucket,
                func.coalesce(func.sum(Flow.packet_count), 0),
                func.coalesce(func.sum(Flow.byte_count), 0),
                func.count(Flow.id),
            ).group_by(bucket).order_by(bucket.asc()).all()
            talker_rows = query.with_entities(
                Flow.src_ip, func.coalesce(func.sum(Flow.byte_count), 0),
            ).group_by(Flow.src_ip).order_by(func.sum(Flow.byte_count).desc()).limit(20).all()
            source_ips = query.with_entities(Flow.src_ip).distinct().limit(20000).all()
            target_ips = query.with_entities(Flow.dst_ip).distinct().limit(20000).all()
            return {
                "cutoff": cutoff,
                "total_packets": int(total_packets or 0),
                "total_bytes": int(total_bytes or 0),
                "total_flows": int(total_flows or 0),
                "protocol_rows": [(str(name or "OTHER"), int(count or 0)) for name, count in protocol_rows],
                "port_rows": [(int(port or 0), int(count or 0)) for port, count in port_rows],
                "timeline_rows": [
                    (int(value or 0), int(packets or 0), int(byte_count or 0), int(flow_count or 0))
                    for value, packets, byte_count, flow_count in timeline_rows
                ],
                "talker_rows": [(str(ip), int(byte_count or 0)) for ip, byte_count in talker_rows],
                "active_hosts": len({str(row[0]) for row in source_ips + target_ips if row[0]}),
            }

    def source_projection_summary(self, source: str) -> Dict[str, Any]:
        """Return counts and protocol/port aggregates for one forensic source."""
        with self.session_scope() as session:
            protocol_rows = session.query(
                Flow.protocol,
                func.coalesce(func.sum(Flow.packet_count), 0),
            ).filter(Flow.source == source).group_by(Flow.protocol).order_by(
                func.sum(Flow.packet_count).desc(),
            ).all()
            port_rows = session.query(
                Flow.dst_port,
                func.coalesce(func.sum(Flow.packet_count), 0),
            ).filter(Flow.source == source, Flow.dst_port > 0).group_by(Flow.dst_port).order_by(
                func.sum(Flow.packet_count).desc(),
            ).limit(100).all()
            return {
                "packet_count": int(
                    session.query(func.coalesce(func.sum(Flow.packet_count), 0))
                    .filter(Flow.source == source).scalar() or 0
                ),
                "flow_count": session.query(Flow).filter(Flow.source == source).count(),
                "entity_count": session.query(Entity).filter(Entity.source == source).count(),
                "alert_count": session.query(Alert).filter(Alert.source == source).count(),
                "finding_count": session.query(DetectionFinding).filter(
                    DetectionFinding.source == source,
                ).count(),
                "artifact_count": session.query(CarvedFile).filter(CarvedFile.source == source).count(),
                "evidence_count": session.query(EvidenceLink).filter(EvidenceLink.source == source).count(),
                "protocol_rows": [(str(name or "OTHER"), int(count or 0)) for name, count in protocol_rows],
                "port_rows": [(int(port or 0), int(count or 0)) for port, count in port_rows],
            }

    def source_projection_page(
        self,
        source: str,
        kind: str,
        *,
        limit: int,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return a detached bounded PCAP projection page."""
        bounded = max(1, min(int(limit), 501))
        start = max(0, int(offset))
        with self.session_scope() as session:
            if kind == "entities":
                rows = session.query(Entity).filter(Entity.source == source).order_by(
                    Entity.risk_score.desc(), Entity.ip.asc(),
                ).offset(start).limit(bounded).all()
                return [self._row_dict(row) for row in rows]
            if kind == "findings":
                rows = session.query(DetectionFinding).filter(
                    DetectionFinding.source == source,
                ).order_by(DetectionFinding.last_seen.desc(), DetectionFinding.id.desc()).offset(
                    start,
                ).limit(bounded).all()
                return [self._finding_dict(row) for row in rows]
            if kind == "artifacts":
                rows = session.query(CarvedFile).filter(CarvedFile.source == source).order_by(
                    CarvedFile.timestamp.desc(), CarvedFile.id.desc(),
                ).offset(start).limit(bounded).all()
                result = []
                for row in rows:
                    item = {
                        column.name: getattr(row, column.name)
                        for column in row.__table__.columns
                        if column.name != "data"
                    }
                    result.append(item)
                return result
            if kind == "evidence":
                rows = session.query(EvidenceLink).filter(EvidenceLink.source == source).order_by(
                    EvidenceLink.timestamp.desc(), EvidenceLink.id.desc(),
                ).offset(start).limit(bounded).all()
                return [self._row_dict(row) for row in rows]
            if kind == "streams":
                rows = session.query(Flow).filter(
                    Flow.source == source,
                    Flow.protocol.in_(("TCP", "TLS", "HTTP", "HTTPS")),
                ).order_by(Flow.byte_count.desc(), Flow.id.desc()).offset(start).limit(bounded).all()
                return [self._row_dict(row) for row in rows]
        raise ValueError(f"unknown source projection kind: {kind}")

    def source_conversation_rows(self, source: str, *, limit: int) -> List[Dict[str, Any]]:
        """Load the bounded directional rows used to derive PCAP conversations."""
        bounded = max(1, min(int(limit), 100001))
        with self.session_scope() as session:
            rows = session.query(Flow).filter(Flow.source == source).order_by(
                Flow.start_time.asc(), Flow.id.asc(),
            ).limit(bounded).all()
            result = []
            for row in rows:
                item = self._row_dict(row)
                try:
                    item["l7_metadata"] = json.loads(item.get("l7_metadata") or "{}")
                except (TypeError, ValueError):
                    item["l7_metadata"] = {}
                result.append(item)
            return result

    def behavioral_peer_seen(self, entity_ip: str, peer_ip: str) -> bool:
        with self.session_scope() as session:
            return session.query(BehavioralBaseline.id).filter_by(
                entity_ip=entity_ip,
                pattern_key="comm_pair",
                pattern_data=peer_ip,
            ).first() is not None

    def remember_behavioral_peers(self, pairs: List[tuple[str, str]], observed_at: float = None) -> int:
        """Persist unseen communication pairs atomically and return the insert count."""
        inserted = 0
        timestamp = float(observed_at or time.time())
        with self.session_scope(write=True) as session:
            for entity_ip, peer_ip in sorted(set(pairs)):
                exists = session.query(BehavioralBaseline.id).filter_by(
                    entity_ip=entity_ip,
                    pattern_key="comm_pair",
                    pattern_data=peer_ip,
                ).first()
                if exists is not None:
                    continue
                session.add(BehavioralBaseline(
                    entity_ip=entity_ip,
                    pattern_key="comm_pair",
                    pattern_data=peer_ip,
                    last_updated=timestamp,
                ))
                inserted += 1
        return inserted

    def scoring_storage_status(self, model_version: str) -> Dict[str, Any]:
        """Return detached scoring registry and finding counters."""
        with self.session_scope() as session:
            # ScoringModel is keyed by version; it intentionally has no
            # synthetic ``id`` column.  Query the mapped primary key so the
            # status command remains usable after model registration.
            registered = session.query(ScoringModel.version).filter_by(version=model_version).first()
            return {
                "registered": registered is not None,
                "finding_count": session.query(DetectionFinding).count(),
                "active_finding_count": session.query(DetectionFinding).filter(
                    DetectionFinding.is_suppressed.is_(False),
                ).count(),
                "snapshot_count": session.query(RiskSnapshot).count(),
            }

    def purge_legacy_alerts_and_scores(self) -> int:
        """Purge only legacy alert projections after a verified external backup."""
        with self.session_scope(write=True) as session:
            alert_count = session.query(Alert).count()
            session.query(Alert).delete(synchronize_session=False)
            session.query(Entity).update({Entity.risk_score: 0.0}, synchronize_session=False)
            return int(alert_count)

    # ----------------------------------------------------------------
    # Cleanup
    # ----------------------------------------------------------------

    def clear_source(self, source: str):
        """Remove all data from a specific source."""
        session = self._get_session()
        session.query(Alert).filter_by(source=source).delete()
        session.query(CarvedFile).filter_by(source=source).delete()
        session.query(AssetProfile).filter_by(source=source).delete()
        session.query(EvidenceLink).filter_by(source=source).delete()
        session.query(EndpointIdentity).filter_by(source=source).delete()
        session.query(Flow).filter_by(source=source).delete()
        finding_ids = [row[0] for row in session.query(DetectionFinding.id).filter_by(source=source).all()]
        if finding_ids:
            session.query(FindingWindow).filter(FindingWindow.finding_id.in_(finding_ids)).delete(synchronize_session=False)
            session.query(AnalystDisposition).filter(AnalystDisposition.finding_id.in_(finding_ids)).delete(synchronize_session=False)
        session.query(DetectionFinding).filter_by(source=source).delete(synchronize_session=False)
        session.query(RiskSnapshot).filter_by(source=source).delete(synchronize_session=False)
        session.query(Entity).filter_by(source=source).delete()
        session.commit()

    def close(self):
        """Remove the scoped session and dispose the engine."""
        self.Session.remove()
        self.engine.dispose()

    def decay_risk_scores(self, factor: float = 0.9):
        """Reduces all entity risk scores by a decay factor."""
        if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
            return
        session = self._get_session()
        session.query(Entity).update({Entity.risk_score: Entity.risk_score * factor})
        session.query(Entity).filter(Entity.risk_score < 0.1).update({Entity.risk_score: 0.0})
        session.commit()

    def reset_all(self, mode: str = "operational") -> dict:
        """Reset operational data while preserving trust/configuration by default."""
        if mode not in {"operational", "factory"}:
            raise ValueError("reset mode must be operational or factory")
        session = self._get_session()
        try:
            counts = {}
            for model in [
                AICitation,
                AIApproval,
                AIToolInvocation,
                AIRun,
                AIMessage,
                AIConversation,
                AIResearchDocument,
                AIPrivateScopeConsent,
                PcapAnalysisJob,
                ForensicTriageFlag,
                ForensicCaseEntity,
                ForensicCase,
                GraphOutbox,
                MeshCommand,
                MeshIngestReceipt,
                EndpointProcessObservation,
                InvestigationStep,
                AIUserFeedback,
                Alert,
                FindingWindow,
                AnalystDisposition,
                DetectionFinding,
                RiskSnapshot,
                FeatureBaseline,
                CarvedFile,
                Flow,
                EvidenceLink,
                EndpointIdentity,
                AssetProfile,
                Entity,
                DailyStats,
                Timeline,
                ForensicReport,
                HardwareObservation,
                CaptureSession,
            ]:
                counts[model.__tablename__] = session.query(model).count()
                session.query(model).delete(synchronize_session=False)
            session.query(SensorNode).update(
                {
                    SensorNode.health_json: "{}",
                    SensorNode.last_seen_at: time.time(),
                },
                synchronize_session=False,
            )
            if mode == "factory":
                for model in [
                    OperatorChallenge,
                    OperatorSession,
                    OperatorCredential,
                    OperatorAccount,
                    SecurityAuditEvent,
                    AIProviderModelCache,
                    MeshEnrollment,
                    SensorNode,
                    ScoringModel,
                    SchemaMigration,
                    SystemMetadata,
                ]:
                    counts[model.__tablename__] = session.query(model).count()
                    session.query(model).delete(synchronize_session=False)
            session.commit()
            if mode == "factory":
                self._publish_local_sensor_node_id(
                    self._ensure_local_sensor_node_id()
                )
            return counts
        except Exception:
            session.rollback()
            raise
        finally:
            self.Session.remove()

    def get_active_risk(self, ip: str, window_hours: int = 24) -> float:
        """Calculate active risk for an IP within a time window."""
        if os.getenv("WATCHTOWER_SCORING_MODE", "dual").lower() == "v2":
            snapshot = self.get_risk_snapshot(ip)
            return float(snapshot["priority_score"]) if snapshot else 0.0
        session = self._get_session()
        start_ts = time.time() - (window_hours * 3600)
        res = session.query(func.sum(Alert.score)).filter(
            Alert.entity_ip == ip,
            Alert.timestamp > start_ts
        ).scalar()
        return float(res) if res else 0.0

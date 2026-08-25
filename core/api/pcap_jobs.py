"""Bounded background PCAP analysis jobs for the local API."""

import inspect
import json
import logging
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, fields
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.ai.config import CredentialStore
from core.backend_policy import backend_policy
from core.constants import FORENSIC_TERMINAL_STATES
from core.context import context
from core.forensics.analysis_identity import PIPELINE_VERSION, build_analysis_identity
from core.forensics.engine import ForensicsEngine
from core.forensics.evidence_envelope import (
    ENCRYPTION_FORMAT,
    EnvelopeMetadata,
    EvidenceEnvelope,
    EvidenceIntegrityError,
    EvidenceKeyUnavailable,
)
from core.forensics.packet_index import (
    PacketIndexBuilder,
    PacketIndexCancelled,
    PacketIndexError,
    python_record_source,
)
from core.forensics.tshark_adapter import TSharkDissector
from core.packet_engine.backend_provenance import reported_backend_version

TERMINAL_STATES = FORENSIC_TERMINAL_STATES
logger = logging.getLogger("watchtower.pcap_jobs")
_DEFAULT_PACKET_INDEX_BUILDER = object()
_DEFAULT_TSHARK_DISSECTOR = object()


@dataclass
class PcapJob:
    id: str
    filename: str
    path: str
    file_size: int
    mode: str
    backend: str
    source: str
    case_id: Optional[str] = None
    analysis_id: Optional[str] = None
    pcap_sha256: Optional[str] = None
    capture_started_at: Optional[float] = None
    capture_ended_at: Optional[float] = None
    link_type: Optional[str] = None
    parser_version: Optional[str] = None
    backend_version: Optional[str] = None
    configuration_hash: Optional[str] = None
    pipeline_version: str = PIPELINE_VERSION
    retention_mode: str = "encrypted"
    encryption_format: Optional[str] = ENCRYPTION_FORMAT
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    bytes_processed: int = 0
    progress: float = 0.0
    error: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    report_id: Optional[int] = None
    retained_input: bool = True
    evidence_metadata: Optional[EnvelopeMetadata] = field(default=None, repr=False)
    keylog_metadata: Optional[EnvelopeMetadata] = field(default=None, repr=False)
    keylog_path: Optional[str] = field(default=None, repr=False)
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)

    def public(self) -> Dict[str, Any]:
        payload = {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if item.name not in {
                "path", "keylog_path", "evidence_metadata", "keylog_metadata", "cancel_event",
            }
        }
        payload["summary"] = dict(self.summary)
        return payload


class PcapJobManager:
    """Runs one heavy analysis at a time and keeps job state inspectable."""

    def __init__(
        self,
        db,
        engine_factory: Callable[..., ForensicsEngine] = ForensicsEngine,
        credential_store=None,
        evidence_root: str | Path | None = None,
        packet_index_builder=_DEFAULT_PACKET_INDEX_BUILDER,
        tshark_dissector=_DEFAULT_TSHARK_DISSECTOR,
    ):
        self.db = db
        self.engine_factory = engine_factory
        self.credential_store = credential_store or CredentialStore()
        installation_id = None
        if hasattr(db, "get_metadata"):
            installation_id = db.get_metadata("trust.installation_id")
            if not installation_id:
                installation_id = uuid.uuid4().hex
                db.set_metadata("trust.installation_id", installation_id)
        self.evidence_envelope = EvidenceEnvelope(
            self.credential_store,
            installation_id or f"process-{uuid.uuid4().hex}",
        )
        self.evidence_root = Path(evidence_root or context.runtime_paths.cases)
        self.evidence_root.mkdir(parents=True, exist_ok=True)
        self._uses_default_packet_index_builder = (
            packet_index_builder is _DEFAULT_PACKET_INDEX_BUILDER
            and engine_factory is ForensicsEngine
        )
        self.packet_index_builder = (
            PacketIndexBuilder(root=self.evidence_root)
            if self._uses_default_packet_index_builder
            else (
                None
                if packet_index_builder is _DEFAULT_PACKET_INDEX_BUILDER
                else packet_index_builder
            )
        )
        self.tshark_dissector = (
            TSharkDissector(
                configured_executable=os.getenv("WATCHTOWER_TSHARK") or None
            )
            if tshark_dissector is _DEFAULT_TSHARK_DISSECTOR
            and engine_factory is ForensicsEngine
            else (
                None
                if tshark_dissector is _DEFAULT_TSHARK_DISSECTOR
                else tshark_dissector
            )
        )
        self._jobs: Dict[str, PcapJob] = {}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="watchtower-pcap")
        self._last_persist: Dict[str, float] = {}
        # The manager serializes analyses, so one production engine can be
        # warmed during service startup and reused. ``analyze_pcap`` resets
        # source-scoped state for every immutable analysis; keeping this
        # engine avoids paying plugin import/validation cost inside the job's
        # user-visible completion window. Injected test engines stay isolated.
        self._shared_engine = None
        if engine_factory is ForensicsEngine:
            try:
                self._shared_engine = engine_factory(
                    db=self.db,
                    data_dir=str(getattr(self.db, "data_dir", context.data_dir)),
                    silent=True,
                )
            except Exception:
                logger.exception("Unable to pre-warm the forensic analysis engine")
        self._restore()

    def submit(self, path: str, filename: str, mode: str, backend: str = None,
               keylog_path: Optional[str] = None, retain_input: bool = True) -> Dict[str, Any]:
        if mode not in {"auto", "memory", "streaming"}:
            raise ValueError("mode must be auto, memory, or streaming")
        backend = backend_policy.replay_backend(backend)
        if Path(filename).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            raise ValueError("file must use a .pcap, .pcapng, or .cap extension")

        job_id = uuid.uuid4().hex
        safe_name = Path(filename).name
        file_size = os.path.getsize(path)
        pcap_sha256 = self._hash_file(path)
        keylog_digest = self._hash_file(keylog_path) if keylog_path else None
        identity_config = {"backend": backend, "mode": mode}
        if keylog_digest:
            identity_config["tls_keylog_sha256"] = keylog_digest
        identity = build_analysis_identity(pcap_sha256, identity_config)
        case_id = identity.case_id
        case_evidence_root = self.evidence_root / case_id / "evidence"
        case_evidence_root.mkdir(parents=True, exist_ok=True)
        encrypted_path = str(case_evidence_root / f"{job_id}.pcap.wte")
        job = PcapJob(
            id=job_id,
            filename=safe_name,
            path=str(path),
            file_size=file_size,
            mode=mode,
            backend=backend,
            source=f"pcap:{job_id}:{safe_name}",
            case_id=case_id,
            analysis_id=identity.analysis_id,
            pcap_sha256=pcap_sha256,
            link_type="pcap-link-layer",
            parser_version="watchtower-forensics-v2",
            backend_version=reported_backend_version(backend),
            configuration_hash=identity.configuration_hash,
            pipeline_version=identity.pipeline_version,
            retention_mode="encrypted" if retain_input else "discard",
            encryption_format=ENCRYPTION_FORMAT,
            retained_input=bool(retain_input),
        )
        try:
            self._update_case(job, state="queued")
            self._append_case_event(job, "submitted")
            job.evidence_metadata = self.evidence_envelope.encrypt(
                path,
                encrypted_path,
                case_id=case_id,
                digest=pcap_sha256,
                purpose="pcap",
            )
            os.remove(path)
            job.path = encrypted_path
            self._save_envelope(job, job.evidence_metadata)
            if keylog_path:
                encrypted_keylog_path = str(
                    case_evidence_root / f"{job_id}.tls-keylog.wte"
                )
                job.keylog_metadata = self.evidence_envelope.encrypt(
                    keylog_path,
                    encrypted_keylog_path,
                    case_id=case_id,
                    digest=keylog_digest,
                    purpose="tls-keylog",
                )
                os.remove(keylog_path)
                job.keylog_path = encrypted_keylog_path
                self._save_envelope(job, job.keylog_metadata)
            with self._lock:
                self._jobs[job_id] = job
                self._persist(job)
        except Exception as exc:
            with self._lock:
                self._jobs.pop(job_id, None)
            for metadata in (job.evidence_metadata, job.keylog_metadata):
                if metadata:
                    try:
                        os.remove(metadata.encrypted_path)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        logger.exception(
                            "Unable to clean failed submission envelope for job %s",
                            job_id,
                        )
                    try:
                        self._delete_envelope(job_id, metadata.purpose)
                    except Exception:
                        logger.exception(
                            "Unable to clean failed submission metadata for job %s",
                            job_id,
                        )
            try:
                self._delete_case_key_if_unused(case_id)
            except Exception:
                logger.exception("Unable to clean failed submission key for case %s", case_id)
            job.status = "failed"
            job.error = self._public_exception(exc)
            job.completed_at = time.time()
            try:
                self._update_case(job, state="failed", error=job.error)
                self._append_case_event(
                    job,
                    "submission_failed",
                    metadata={"error": job.error},
                )
            except Exception:
                logger.exception("Unable to persist failed submission state for job %s", job_id)
            raise
        self._executor.submit(self._run, job_id)
        return job.public()

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            if job.cancel_event.is_set():
                cancelled_before_start = True
            else:
                cancelled_before_start = False
                job.status = "running"
                job.started_at = time.time()
                self._persist(job)

        if cancelled_before_start:
            self._finish(job_id, "cancelled")
            return

        def progress(processed: float, total: float) -> None:
            with self._lock:
                current = self._jobs[job_id]
                current.bytes_processed = min(current.file_size, max(0, int(processed)))
                current.progress = round(min(100.0, current.bytes_processed * 100 / max(1, int(total))), 2)
                if time.monotonic() - self._last_persist.get(job_id, 0.0) >= 0.5:
                    self._persist(current)
                    self._last_persist[job_id] = time.monotonic()

        terminal_status = "failed"
        terminal_error: Optional[str] = None
        plaintext_pcap = None
        plaintext_keylog = None
        auxiliary_executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix=f"watchtower-pcap-aux-{job_id[:8]}",
        )
        packet_index_future = None
        tshark_future = None
        try:
            with self._lock:
                evidence_metadata = self._jobs[job_id].evidence_metadata
                keylog_metadata = self._jobs[job_id].keylog_metadata
            if evidence_metadata is None:
                raise RuntimeError("encrypted PCAP metadata is unavailable")
            plaintext_pcap = f"{evidence_metadata.encrypted_path}.active"
            self.evidence_envelope.decrypt(evidence_metadata, plaintext_pcap)
            if keylog_metadata:
                plaintext_keylog = f"{keylog_metadata.encrypted_path}.active"
                self.evidence_envelope.decrypt(keylog_metadata, plaintext_keylog)
            # Packet indexing and TShark dissection read the immutable
            # plaintext capture and do not depend on the engine's SQLite
            # projections. Start them while the main forensic pass runs so a
            # small job does not expose a terminal state only after a serial
            # enrichment tail.
            index_builder = self.packet_index_builder
            if self._uses_default_packet_index_builder and job.backend == "python":
                index_builder = PacketIndexBuilder(
                    root=self.evidence_root,
                    record_source=python_record_source,
                )
            if index_builder:
                packet_index_future = auxiliary_executor.submit(
                    index_builder.build,
                    plaintext_pcap,
                    case_id=job.case_id,
                    analysis_id=job.analysis_id,
                    pcap_sha256=job.pcap_sha256,
                    cancel_event=job.cancel_event,
                )
            if self.tshark_dissector:
                tshark_future = auxiliary_executor.submit(
                    self.tshark_dissector.dissect,
                    plaintext_pcap,
                )
            engine = self._shared_engine or self.engine_factory(
                db=self.db,
                data_dir=str(getattr(self.db, "data_dir", context.data_dir)),
                silent=True,
            )
            analyze_options = {
                "progress_callback": progress,
                "source_name": job.source,
                "mode": job.mode,
                "backend": job.backend,
                "cancel_event": job.cancel_event,
            }
            if self._accepts_keyword(engine.analyze_pcap, "case_id"):
                analyze_options["case_id"] = job.case_id
            if self._accepts_keyword(engine.analyze_pcap, "analysis_id"):
                analyze_options["analysis_id"] = job.analysis_id
            if self._accepts_keyword(engine.analyze_pcap, "conversation_source"):
                analyze_options["conversation_source"] = f"pcap:{job.analysis_id}"
            if plaintext_keylog:
                analyze_options["keylog_file"] = plaintext_keylog
            report = engine.analyze_pcap(plaintext_pcap, **analyze_options)
            self._persist_case_entities(job, report)
            triage = self._run_case_triage(job)
            with self._lock:
                job.capture_started_at = getattr(report, "capture_started_at", None)
                job.capture_ended_at = getattr(report, "capture_ended_at", None)
                terminal_status = str(getattr(report, "status", "complete") or "complete").lower()
                job.summary = dict(getattr(report, "summary", {}) or {})
                job.summary["triage"] = triage
                job.report_id = getattr(report, "report_id", None)
                job.bytes_processed = int(getattr(report, "bytes_processed", job.file_size) or 0)
                job.progress = round(min(100.0, job.bytes_processed * 100 / max(1, job.file_size)), 2)
                terminal_error = getattr(report, "error", None)
            if index_builder and terminal_status in {"complete", "partial"}:
                try:
                    manifest = packet_index_future.result() if packet_index_future else None
                    if manifest is None:
                        raise PacketIndexError("packet index worker did not return a manifest")
                    self._persist_packet_index(job, manifest)
                    with self._lock:
                        job.summary["packet_index"] = {
                            "state": "complete",
                            "schema_version": int(manifest["schema_version"]),
                            "row_count": int(manifest["row_count"]),
                            "partition_count": len(manifest.get("partitions") or []),
                            "manifest_sha256": str(manifest["manifest_sha256"]),
                        }
                except PacketIndexCancelled:
                    terminal_status = "cancelled"
                    terminal_error = "PCAP analysis was cancelled"
                    with self._lock:
                        job.summary["packet_index"] = {"state": "cancelled"}
                        limitations = list(job.summary.get("visibility_limitations") or [])
                        if "packet_index_cancelled" not in limitations:
                            limitations.append("packet_index_cancelled")
                        job.summary["visibility_limitations"] = limitations
                except Exception:
                    logger.exception("Packet index build failed for job %s", job_id)
                    if terminal_status == "complete":
                        terminal_status = "partial"
                    terminal_error = "PCAP analysis completed partially"
                    with self._lock:
                        job.summary["packet_index"] = {"state": "failed"}
                        limitations = list(job.summary.get("visibility_limitations") or [])
                        if "packet_index_unavailable" not in limitations:
                            limitations.append("packet_index_unavailable")
                        job.summary["visibility_limitations"] = limitations
            if self.tshark_dissector and terminal_status in {"complete", "partial"}:
                tshark_result = tshark_future.result() if tshark_future else None
                if tshark_result is None:
                    raise RuntimeError("TShark worker did not return a dissection result")
                tshark_component = None
                tshark_health = dict(tshark_result.health)
                tshark_limitations = list(tshark_result.limitations)
                if not tshark_limitations:
                    try:
                        tshark_component = self.db.save_forensic_deep_dissection(
                            job.case_id,
                            job.analysis_id,
                            tshark_result.records,
                            completeness="complete",
                        )
                    except Exception:
                        logger.exception(
                            "TShark evidence publication failed for job %s",
                            job_id,
                        )
                        if terminal_status == "complete":
                            terminal_status = "partial"
                        terminal_error = "PCAP analysis completed partially"
                        tshark_limitations.append(
                            "tshark_evidence_unavailable"
                        )
                        tshark_health.update({
                            "state": "degraded",
                            "error_code": "tshark_evidence_unavailable",
                        })
                with self._lock:
                    job.summary["tshark"] = {
                        "state": tshark_health["state"],
                        "record_count": len(tshark_result.records),
                        "health": tshark_health,
                        "evidence_sha256": (
                            tshark_component["sha256"]
                            if tshark_component is not None
                            else None
                        ),
                    }
                    limitations = list(
                        job.summary.get("visibility_limitations") or []
                    )
                    for limitation in tshark_limitations:
                        if limitation not in limitations:
                            limitations.append(limitation)
                    job.summary["visibility_limitations"] = limitations
        except Exception as exc:
            logger.exception("PCAP analysis job %s failed", job_id)
            terminal_error = self._public_exception(exc)
        finally:
            if terminal_status not in {"complete", "partial"}:
                for future in (packet_index_future, tshark_future):
                    if future is not None:
                        future.cancel()
            auxiliary_executor.shutdown(wait=True, cancel_futures=True)
            plaintext_cleanup_failed = False
            for plaintext_path in (plaintext_pcap, plaintext_keylog):
                if plaintext_path:
                    removed, _cleanup_error = self._remove_path(plaintext_path)
                    plaintext_cleanup_failed = plaintext_cleanup_failed or not removed
            if plaintext_cleanup_failed:
                if terminal_status == "complete":
                    terminal_status = "partial"
                terminal_error = self._cleanup_public_error()
            if hasattr(self.db, "rollback"):
                try:
                    self.db.rollback()
                except Exception:
                    pass
            try:
                self._finish(job_id, terminal_status, terminal_error)
            finally:
                if hasattr(self.db, "remove"):
                    self.db.remove()

    def _finish(self, job_id: str, status: str, error: Optional[str] = None) -> None:
        """Remove the upload before exposing a terminal job state."""
        cleanup_failed = False
        with self._lock:
            current = self._jobs[job_id]
            path = current.path
            retained_input = current.retained_input
            evidence_metadata = current.evidence_metadata
            keylog_metadata = current.keylog_metadata
        pcap_cleanup_complete = retained_input
        keylog_cleanup_complete = keylog_metadata is None
        if not retained_input:
            pcap_cleanup_complete, _cleanup_error = self._remove_path(path)
            if pcap_cleanup_complete and evidence_metadata:
                try:
                    self._delete_envelope(job_id, "pcap")
                except Exception:
                    logger.exception("Unable to remove PCAP envelope metadata for job %s", job_id)
                    pcap_cleanup_complete = False
            cleanup_failed = cleanup_failed or not pcap_cleanup_complete
        if keylog_metadata:
            keylog_cleanup_complete, _cleanup_error = self._remove_path(
                keylog_metadata.encrypted_path
            )
            if keylog_cleanup_complete:
                try:
                    self._delete_envelope(job_id, "tls-keylog")
                except Exception:
                    logger.exception(
                        "Unable to remove TLS keylog envelope metadata for job %s",
                        job_id,
                    )
                    keylog_cleanup_complete = False
            cleanup_failed = cleanup_failed or not keylog_cleanup_complete
        if pcap_cleanup_complete and keylog_cleanup_complete:
            self._delete_case_key_if_unused(current.case_id)

        with self._lock:
            job = self._jobs[job_id]
            if cleanup_failed and status == "complete":
                status = "partial"
                error = self._cleanup_public_error()
            elif cleanup_failed:
                error = self._cleanup_public_error()
            error = self._public_error_text(error, status)
            job.status = status
            job.error = error
            job.completed_at = time.time()
            if keylog_cleanup_complete:
                job.keylog_path = None
                job.keylog_metadata = None
            self._persist(
                job,
                clear_paths=not retained_input and pcap_cleanup_complete,
            )
            self._update_case(job, state=status, error=error)
            self._append_case_event(job, "completed", metadata={"status": status, "error": error} if error else {"status": status})

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.public() if job else None

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda item: item.created_at, reverse=True)
            return [job.public() for job in jobs[:limit]]

    def cancel(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            if job.status not in TERMINAL_STATES:
                job.cancel_event.set()
                job.status = "cancelling"
                self._persist(job)
            return job.public()

    def shutdown(self) -> None:
        with self._lock:
            for job in self._jobs.values():
                if job.status not in TERMINAL_STATES:
                    job.cancel_event.set()
        # Let queued jobs enter _run so their temporary uploads are removed.
        # Active analyses observe cancel_event during packet processing.
        self._executor.shutdown(wait=True, cancel_futures=False)

    def _persist(self, job: PcapJob, clear_paths: bool = False) -> None:
        if not hasattr(self.db, "save_pcap_analysis_job"):
            return
        values = job.public()
        values.update({"path": job.path, "keylog_path": job.keylog_path})
        self.db.save_pcap_analysis_job(values, clear_paths=clear_paths)

    def _save_envelope(self, job: PcapJob, metadata: EnvelopeMetadata) -> None:
        if not hasattr(self.db, "save_forensic_evidence_envelope"):
            return
        self.db.save_forensic_evidence_envelope({
            "id": f"{job.id}:{metadata.purpose}",
            "job_id": job.id,
            "case_id": job.case_id,
            "purpose": metadata.purpose,
            "credential_reference": metadata.credential_reference,
            "nonce": metadata.nonce,
            "format_version": metadata.format_version,
            "digest": metadata.digest,
            "encrypted_path": metadata.encrypted_path,
        })

    def _delete_envelope(self, job_id: str, purpose: str) -> None:
        if hasattr(self.db, "delete_forensic_evidence_envelope"):
            self.db.delete_forensic_evidence_envelope(job_id, purpose)

    def _persist_packet_index(self, job: PcapJob, manifest: Dict[str, Any]) -> None:
        if not hasattr(self.db, "save_forensic_packet_index"):
            raise PacketIndexError("packet index repository is unavailable")
        self.db.save_forensic_packet_index({
            "analysis_id": job.analysis_id,
            "case_id": job.case_id,
            "pcap_sha256": job.pcap_sha256,
            "schema_version": int(manifest["schema_version"]),
            "manifest_path": str(manifest["manifest_path"]),
            "manifest_sha256": str(manifest["manifest_sha256"]),
            "row_count": int(manifest["row_count"]),
            "partition_count": len(manifest.get("partitions") or []),
            "first_timestamp": manifest.get("first_timestamp"),
            "last_timestamp": manifest.get("last_timestamp"),
            "state": "complete",
            "created_at": manifest.get("created_at"),
        })

    def _delete_case_key_if_unused(self, case_id: Optional[str]) -> None:
        if not case_id or not hasattr(self.db, "count_forensic_evidence_envelopes"):
            return
        if self.db.count_forensic_evidence_envelopes(case_id) == 0:
            self.evidence_envelope.delete_case_key(case_id)

    @staticmethod
    def _accepts_keyword(function: Callable[..., Any], name: str) -> bool:
        """Pass new engine options only to engines that explicitly support them."""
        try:
            signature = inspect.signature(function)
        except (TypeError, ValueError):
            return False
        return name in signature.parameters or any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )

    @staticmethod
    def _hash_file(path: str, chunk_size: int = 1024 * 1024) -> str:
        digest = sha256()
        with open(path, "rb") as source:
            while chunk := source.read(chunk_size):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _remove_path(path: str | Path, attempts: int = 3) -> tuple[bool, Optional[OSError]]:
        last_error = None
        for attempt in range(max(1, int(attempts))):
            try:
                os.remove(path)
                return True, None
            except FileNotFoundError:
                return True, None
            except OSError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    time.sleep(0.02 * (attempt + 1))
        return False, last_error

    @staticmethod
    def _cleanup_public_error() -> str:
        return "Evidence cleanup is pending and will be retried on restart"

    @staticmethod
    def _public_exception(exc: Exception) -> str:
        if isinstance(exc, EvidenceKeyUnavailable):
            return "Retained evidence key is unavailable"
        if isinstance(exc, EvidenceIntegrityError):
            return "Retained evidence failed integrity verification"
        if isinstance(exc, FileNotFoundError):
            return "Retained evidence is unavailable"
        if isinstance(exc, OSError):
            return "Evidence storage operation failed"
        return f"PCAP analysis failed ({type(exc).__name__})"

    @classmethod
    def _public_error_text(cls, error: Optional[str], status: str) -> Optional[str]:
        if not error:
            return None
        safe = {
            cls._cleanup_public_error(),
            "Retained evidence key is unavailable",
            "Retained evidence failed integrity verification",
            "Retained evidence is unavailable",
            "Evidence storage operation failed",
            "Analysis was interrupted by a WatchTower API restart",
        }
        value = str(error)
        generated_prefix = "PCAP analysis failed ("
        generated_type = (
            value[len(generated_prefix):-1]
            if value.startswith(generated_prefix) and value.endswith(")")
            else ""
        )
        if value in safe or (generated_type.isidentifier() and generated_type.isascii()):
            return value
        if status == "cancelled":
            return "PCAP analysis was cancelled"
        if status == "partial":
            return "PCAP analysis completed partially"
        return "PCAP analysis failed"

    def _update_case(self, job: PcapJob, *, state: str, error: Optional[str] = None) -> None:
        if not job.case_id or not hasattr(self.db, "create_forensic_case"):
            return
        report_hash = (
            sha256(json.dumps(job.summary, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
            if job.summary and str(state).lower() in TERMINAL_STATES
            else None
        )
        visibility_limitations = list(
            job.summary.get("visibility_limitations") or []
        )
        values = {
            "id": job.case_id,
            "analysis_id": job.analysis_id or job.id,
            "sha256": job.pcap_sha256 or "",
            "filename": job.filename,
            "byte_count": job.file_size,
            "backend": job.backend,
            "state": str(state or "created").lower(),
            "progress": job.progress,
            "retained_input": job.retained_input,
            "completed_at": job.completed_at,
            "capture_started_at": job.capture_started_at,
            "capture_ended_at": job.capture_ended_at,
            "link_type": job.link_type,
            "parser_version": job.parser_version,
            "backend_version": job.backend_version,
            "configuration_hash": job.configuration_hash,
            "pipeline_version": job.pipeline_version,
            "retention_mode": job.retention_mode,
            "encryption_format": job.encryption_format,
            "report_hash": report_hash,
            "visibility_limitations": visibility_limitations,
        }
        if error:
            values["warnings"] = [str(error)[:4000]]
        revision = {
            "case_id": job.case_id,
            "analysis_id": job.analysis_id,
            "pcap_sha256": job.pcap_sha256,
            "pipeline_version": job.pipeline_version,
            "configuration_hash": job.configuration_hash,
            "backend": job.backend,
            "backend_version": job.backend_version,
            "state": str(state or "queued").lower(),
            "created_at": job.created_at,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "report_hash": report_hash,
            "visibility_limitations": visibility_limitations,
        }
        if hasattr(self.db, "save_forensic_case_revision"):
            self.db.save_forensic_case_revision(values, revision)
            return
        self.db.create_forensic_case(values)
        if hasattr(self.db, "save_forensic_analysis_revision"):
            self.db.save_forensic_analysis_revision(revision)

    def _append_case_event(self, job: PcapJob, event_type: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if not job.case_id or not job.pcap_sha256 or not hasattr(self.db, "append_case_custody_event"):
            return
        try:
            self.db.append_case_custody_event(job.case_id, event_type, job.pcap_sha256, metadata=metadata or {})
        except Exception:
            pass

    def _persist_case_entities(self, job: PcapJob, report: Any) -> None:
        """Project both source directions into the case-scoped identity view."""
        if not job.case_id or not hasattr(self.db, "upsert_case_entity"):
            return
        for ip, profile in (getattr(report, "entities", {}) or {}).items():
            total_packets = int(getattr(profile, "total_packets", 0) or 0)
            total_bytes = int(getattr(profile, "total_bytes", 0) or 0)
            has_identity = any(
                getattr(profile, field, None)
                for field in ("mac", "hostname", "user", "full_name", "os", "ja3_hash", "ja4_string")
            )
            try:
                self.db.upsert_case_entity(job.case_id, {
                    "ip": str(ip),
                    "mac": getattr(profile, "mac", None),
                    "hostname": getattr(profile, "hostname", None),
                    "username": getattr(profile, "user", None),
                    "full_name": getattr(profile, "full_name", None),
                    "os": getattr(profile, "os", None),
                    "confidence": 0.75 if has_identity else 0.20,
                    "total_packets": total_packets,
                    "total_bytes": total_bytes,
                    "provenance": {
                        "source": "pcap_analysis",
                        "identity_quality": "evidence_backed" if has_identity else "address_only",
                        "report_id": getattr(report, "report_id", None),
                    },
                })
            except Exception:
                continue

    def _run_case_triage(self, job: PcapJob) -> Dict[str, Any]:
        if not job.case_id:
            return {"flagged": 0, "signals": 0}
        try:
            from core.forensics.triage import OfflineTriageEngine
            return OfflineTriageEngine(self.db).run(case_id=job.case_id, source=job.source)
        except Exception:
            return {"flagged": 0, "signals": 0, "error": "triage_unavailable"}

    def _restore(self) -> None:
        if not hasattr(self.db, "load_pcap_analysis_jobs"):
            return
        rows = self.db.load_pcap_analysis_jobs()
        now = time.time()
        for row in rows:
            evidence_row = (
                self.db.get_forensic_evidence_envelope(row["id"], "pcap")
                if hasattr(self.db, "get_forensic_evidence_envelope")
                else None
            )
            keylog_row = (
                self.db.get_forensic_evidence_envelope(row["id"], "tls-keylog")
                if hasattr(self.db, "get_forensic_evidence_envelope")
                else None
            )
            evidence_metadata = self._metadata_from_row(evidence_row)
            keylog_metadata = self._metadata_from_row(keylog_row)
            status = str(row.get("status") or "failed").lower()
            error = self._public_error_text(row.get("error"), status)
            completed_at = row.get("completed_at")
            interrupted = status not in TERMINAL_STATES
            cleanup_failed = False
            reconciled_changed = False
            active_paths = {
                f"{metadata.encrypted_path}.active"
                for metadata in (evidence_metadata, keylog_metadata)
                if metadata
            }
            for stored_path in (row.get("path"), row.get("keylog_path")):
                if stored_path:
                    active_paths.add(f"{stored_path}.active")
            for active_path in active_paths:
                removed, _cleanup_error = self._remove_path(active_path)
                cleanup_failed = cleanup_failed or not removed

            if evidence_metadata and not bool(row.get("retained_input")):
                removed, _cleanup_error = self._remove_path(
                    evidence_metadata.encrypted_path
                )
                if removed:
                    try:
                        self._delete_envelope(str(row["id"]), "pcap")
                        evidence_metadata = None
                        reconciled_changed = True
                    except Exception:
                        logger.exception(
                            "Unable to reconcile PCAP envelope metadata for job %s",
                            row["id"],
                        )
                        cleanup_failed = True
                else:
                    cleanup_failed = True
            if keylog_metadata:
                removed, _cleanup_error = self._remove_path(
                    keylog_metadata.encrypted_path
                )
                if removed:
                    try:
                        self._delete_envelope(str(row["id"]), "tls-keylog")
                        keylog_metadata = None
                        reconciled_changed = True
                    except Exception:
                        logger.exception(
                            "Unable to reconcile keylog envelope metadata for job %s",
                            row["id"],
                        )
                        cleanup_failed = True
                else:
                    cleanup_failed = True
            if evidence_metadata is None and keylog_metadata is None:
                self._delete_case_key_if_unused(row.get("case_id"))

            if interrupted:
                status = "failed"
                error = "Analysis was interrupted by a WatchTower API restart"
                completed_at = now
            if cleanup_failed:
                if status == "complete":
                    status = "partial"
                error = self._cleanup_public_error()
                completed_at = now
            if interrupted or cleanup_failed or reconciled_changed:
                row.update({
                    "status": status,
                    "error": error,
                    "completed_at": completed_at,
                    "path": (
                        evidence_metadata.encrypted_path
                        if evidence_metadata
                        else ""
                    ),
                    "keylog_path": (
                        keylog_metadata.encrypted_path
                        if keylog_metadata
                        else None
                    ),
                })
                self.db.save_pcap_analysis_job(
                    row,
                    clear_paths=(
                        not bool(row.get("retained_input"))
                        and evidence_metadata is None
                    ),
                )
            job_id = str(row["id"])
            self._jobs[job_id] = PcapJob(
                id=job_id,
                filename=str(row.get("filename") or ""),
                path=str(row.get("path") or ""),
                file_size=int(row.get("file_size") or 0),
                mode=str(row.get("mode") or "auto"),
                backend=backend_policy.replay_backend(row.get("backend")),
                source=str(row.get("source") or ""),
                case_id=row.get("case_id"),
                analysis_id=row.get("analysis_id") or job_id,
                pcap_sha256=row.get("pcap_sha256"),
                capture_started_at=row.get("capture_started_at"),
                capture_ended_at=row.get("capture_ended_at"),
                link_type=row.get("link_type"),
                parser_version=row.get("parser_version"),
                backend_version=row.get("backend_version"),
                configuration_hash=row.get("configuration_hash"),
                pipeline_version=row.get("pipeline_version") or PIPELINE_VERSION,
                retention_mode=row.get("retention_mode") or (
                    "encrypted" if bool(row.get("retained_input")) else "discard"
                ),
                encryption_format=row.get("encryption_format"),
                status=status,
                created_at=float(row.get("created_at") or now),
                started_at=row.get("started_at"),
                completed_at=completed_at,
                bytes_processed=int(row.get("bytes_processed") or 0),
                progress=float(row.get("progress") or 0.0),
                error=error,
                summary=dict(row.get("summary") or {}),
                report_id=row.get("report_id"),
                retained_input=bool(row.get("retained_input")),
                evidence_metadata=evidence_metadata,
                keylog_metadata=keylog_metadata,
                keylog_path=(
                    keylog_metadata.encrypted_path if keylog_metadata else None
                ),
            )

    @staticmethod
    def _metadata_from_row(row: Optional[Dict[str, Any]]) -> Optional[EnvelopeMetadata]:
        if not row:
            return None
        return EnvelopeMetadata(
            case_id=str(row["case_id"]),
            digest=str(row["digest"]),
            purpose=str(row["purpose"]),
            credential_reference=str(row["credential_reference"]),
            nonce=str(row["nonce"]),
            encrypted_path=str(row["encrypted_path"]),
            format_version=str(row["format_version"]),
        )

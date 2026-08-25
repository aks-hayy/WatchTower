import base64
import builtins
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

import core.api.pcap_jobs as pcap_jobs_module
from core.api.pcap_jobs import PcapJobManager
from core.forensics.analysis_identity import (
    PIPELINE_VERSION,
    build_analysis_identity,
    canonical_configuration_json,
)
from core.forensics.evidence_envelope import (
    EvidenceEnvelope,
    EvidenceIntegrityError,
    EvidenceKeyUnavailable,
)
from core.storage.database import WatchtowerDB


class MemoryCredentialStore:
    def __init__(self):
        self.secrets = {}

    def set(self, reference, secret):
        self.secrets[reference] = secret

    def get(self, reference):
        return self.secrets.get(reference)

    def delete(self, reference):
        return self.secrets.pop(reference, None) is not None


def test_analysis_identity_is_canonical_and_ignores_runtime_only_choices():
    digest = "ab" * 32
    first = build_analysis_identity(
        digest,
        {
            "backend": "python",
            "detectors": {"dns": True, "threshold": 1.0},
            "mode": "memory",
            "temporary_path": Path("C:/temporary/first"),
            "progress_callback": object(),
        },
    )
    second = build_analysis_identity(
        digest,
        {
            "progress_callback": lambda *_args: None,
            "temporary_path": "/different/runtime/path",
            "mode": "streaming",
            "detectors": {"threshold": 1, "dns": True},
            "backend": "python",
        },
    )

    assert first.pipeline_version == "watchtower-forensics-v2.0"
    assert first.pipeline_version == PIPELINE_VERSION
    assert first.case_id == second.case_id
    assert first.configuration_hash == second.configuration_hash
    assert first.analysis_id == second.analysis_id
    assert canonical_configuration_json({"b": 2, "a": 1.0}) == '{"a":1,"b":2}'


def test_analysis_revision_changes_only_when_forensic_configuration_changes():
    digest = "cd" * 32
    python_identity = build_analysis_identity(digest, {"backend": "python", "mode": "memory"})
    rust_identity = build_analysis_identity(digest, {"backend": "rust", "mode": "memory"})

    assert python_identity.case_id == rust_identity.case_id
    assert python_identity.configuration_hash != rust_identity.configuration_hash
    assert python_identity.analysis_id != rust_identity.analysis_id


def _encrypt_fixture(tmp_path, *, content=b"forensic packet evidence", chunk_size=8):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "capture.pcap"
    encrypted = tmp_path / "capture.wte"
    source.write_bytes(content)
    credentials = MemoryCredentialStore()
    envelope = EvidenceEnvelope(credentials, "installation-test", chunk_size=chunk_size)
    metadata = envelope.encrypt(
        source,
        encrypted,
        case_id="case-test",
        digest=__import__("hashlib").sha256(content).hexdigest(),
        purpose="pcap",
    )
    return envelope, credentials, source, encrypted, metadata


def test_encrypted_evidence_round_trip_uses_different_ciphertext_each_time(tmp_path):
    content = b"same packet evidence" * 5
    first = _encrypt_fixture(tmp_path / "first", content=content)
    second = _encrypt_fixture(tmp_path / "second", content=content)

    first_output = tmp_path / "first.active"
    second_output = tmp_path / "second.active"
    first[0].decrypt(first[4], first_output)
    second[0].decrypt(second[4], second_output)

    assert first_output.read_bytes() == content
    assert second_output.read_bytes() == content
    assert first[3].read_bytes() != second[3].read_bytes()
    assert first[4].nonce != second[4].nonce
    assert len(base64.b64decode(first[1].secrets[first[4].credential_reference])) == 32


def test_envelopes_for_one_case_share_a_case_key_but_use_unique_nonces(tmp_path):
    credentials = MemoryCredentialStore()
    envelope = EvidenceEnvelope(credentials, "installation-test", chunk_size=8)
    pcap = tmp_path / "capture.pcap"
    keylog = tmp_path / "capture.keylog"
    pcap.write_bytes(b"pcap evidence")
    keylog.write_bytes(b"CLIENT_RANDOM redacted")

    pcap_metadata = envelope.encrypt(
        pcap,
        tmp_path / "capture.pcap.wte",
        case_id="case-shared",
        digest=__import__("hashlib").sha256(pcap.read_bytes()).hexdigest(),
        purpose="pcap",
    )
    keylog_metadata = envelope.encrypt(
        keylog,
        tmp_path / "capture.keylog.wte",
        case_id="case-shared",
        digest=__import__("hashlib").sha256(keylog.read_bytes()).hexdigest(),
        purpose="tls-keylog",
    )

    assert pcap_metadata.credential_reference == keylog_metadata.credential_reference
    assert pcap_metadata.nonce != keylog_metadata.nonce
    assert len(credentials.secrets) == 1


def test_envelope_public_projection_never_leaks_secret_storage_details(tmp_path):
    envelope, credentials, _source, encrypted, metadata = _encrypt_fixture(tmp_path)

    public = metadata.public_dict()
    serialized = repr(public)

    assert public == {
        "retention_mode": "encrypted",
        "encryption_format": "aes-256-gcm-chunked-v1",
        "digest": metadata.digest,
    }
    assert metadata.credential_reference not in serialized
    assert metadata.nonce not in serialized
    assert str(encrypted) not in serialized
    assert credentials.secrets[metadata.credential_reference] not in serialized
    assert envelope is not None


def test_envelope_rejects_tampering_missing_keys_digest_mismatch_and_truncation(tmp_path):
    envelope, credentials, _source, encrypted, metadata = _encrypt_fixture(tmp_path)

    tampered = bytearray(encrypted.read_bytes())
    tampered[-6] ^= 0x01
    encrypted.write_bytes(tampered)
    with pytest.raises(EvidenceIntegrityError):
        envelope.decrypt(metadata, tmp_path / "tampered.active")

    encrypted.unlink()
    _, _, _, encrypted, metadata = _encrypt_fixture(tmp_path / "missing")
    missing_envelope = EvidenceEnvelope(MemoryCredentialStore(), "installation-test", chunk_size=8)
    with pytest.raises(EvidenceKeyUnavailable):
        missing_envelope.decrypt(metadata, tmp_path / "missing.active")

    digest_envelope, _, _, _, digest_metadata = _encrypt_fixture(tmp_path / "digest")
    digest_metadata.digest = "00" * 32
    with pytest.raises(EvidenceIntegrityError):
        digest_envelope.decrypt(digest_metadata, tmp_path / "digest.active")

    truncated_envelope, _, _, truncated_path, truncated_metadata = _encrypt_fixture(tmp_path / "truncated")
    truncated_path.write_bytes(truncated_path.read_bytes()[:-3])
    with pytest.raises(EvidenceIntegrityError):
        truncated_envelope.decrypt(truncated_metadata, tmp_path / "truncated.active")


def test_envelope_authenticates_its_serialized_header(tmp_path):
    envelope, _credentials, _source, encrypted, metadata = _encrypt_fixture(tmp_path)
    raw = bytearray(encrypted.read_bytes())
    raw[7] = 16
    encrypted.write_bytes(raw)

    with pytest.raises(EvidenceIntegrityError):
        envelope.decrypt(metadata, tmp_path / "header-tampered.active")


def test_envelope_io_is_chunk_bounded(monkeypatch, tmp_path):
    content = b"x" * 257
    source = tmp_path / "large.pcap"
    encrypted = tmp_path / "large.wte"
    source.write_bytes(content)
    read_sizes = []
    real_open = builtins.open

    class TrackingReader:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self._wrapped.__exit__(*args)

        def read(self, size=-1):
            read_sizes.append(size)
            return self._wrapped.read(size)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    def tracking_open(path, mode="r", *args, **kwargs):
        opened = real_open(path, mode, *args, **kwargs)
        if Path(path) == source and mode == "rb":
            return TrackingReader(opened)
        return opened

    monkeypatch.setattr(builtins, "open", tracking_open)
    envelope = EvidenceEnvelope(MemoryCredentialStore(), "installation-test", chunk_size=32)
    envelope.encrypt(
        source,
        encrypted,
        case_id="case-test",
        digest=__import__("hashlib").sha256(content).hexdigest(),
        purpose="pcap",
    )

    assert read_sizes
    assert max(read_sizes) <= 32
    assert -1 not in read_sizes


def test_analysis_revisions_are_idempotent_and_case_scoped(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        digest = "12" * 32
        case_id = f"case-{digest}"
        db.create_forensic_case({"id": case_id, "analysis_id": "legacy", "sha256": digest})
        first_values = {
            "case_id": case_id,
            "analysis_id": "analysis-python",
            "pcap_sha256": digest,
            "pipeline_version": PIPELINE_VERSION,
            "configuration_hash": "34" * 32,
            "backend": "python",
            "backend_version": "python-test",
            "state": "queued",
            "created_at": 100.0,
        }

        first = db.save_forensic_analysis_revision(first_values)
        repeated = db.save_forensic_analysis_revision({**first_values, "state": "complete", "report_hash": "56" * 32})
        second = db.save_forensic_analysis_revision({
            **first_values,
            "analysis_id": "analysis-rust",
            "configuration_hash": "78" * 32,
            "backend": "rust",
        })
        revisions = db.list_forensic_analysis_revisions(case_id)

        assert first["analysis_id"] == repeated["analysis_id"]
        assert repeated["created_at"] == 100.0
        assert repeated["state"] == "complete"
        assert repeated["report_hash"] == "56" * 32
        assert second["analysis_id"] == "analysis-rust"
        assert [item["analysis_id"] for item in revisions] == ["analysis-python", "analysis-rust"]
        assert db.get_forensic_case(case_id)["analysis_id"] == "analysis-rust"
    finally:
        db.close()


def test_completed_analysis_revision_cannot_be_downgraded_by_a_rerun(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        digest = "21" * 32
        case_id = f"case-{digest}"
        db.create_forensic_case({"id": case_id, "analysis_id": "analysis-fixed", "sha256": digest})
        values = {
            "case_id": case_id,
            "analysis_id": "analysis-fixed",
            "pcap_sha256": digest,
            "pipeline_version": PIPELINE_VERSION,
            "configuration_hash": "43" * 32,
            "backend": "rust",
            "state": "complete",
            "report_hash": "65" * 32,
            "created_at": 100.0,
            "completed_at": 200.0,
        }
        db.save_forensic_analysis_revision(values)

        repeated = db.save_forensic_analysis_revision({
            **values,
            "state": "queued",
            "report_hash": None,
            "completed_at": None,
        })

        assert repeated["state"] == "complete"
        assert repeated["report_hash"] == "65" * 32
        assert repeated["completed_at"] == 200.0
    finally:
        db.close()


def test_existing_database_gets_additive_task_3a_columns_and_revision_table(tmp_path):
    database_path = tmp_path / "watchtower.db"
    connection = sqlite3.connect(database_path)
    connection.execute(
        """
        CREATE TABLE forensic_cases (
            id TEXT PRIMARY KEY,
            analysis_id TEXT NOT NULL UNIQUE,
            sha256 TEXT NOT NULL,
            filename TEXT,
            byte_count INTEGER NOT NULL DEFAULT 0,
            state TEXT NOT NULL DEFAULT 'created',
            progress REAL NOT NULL DEFAULT 0.0,
            warnings_json TEXT NOT NULL DEFAULT '[]',
            visibility_limitations_json TEXT NOT NULL DEFAULT '[]',
            retained_input BOOLEAN NOT NULL DEFAULT 0,
            created_at REAL NOT NULL,
            completed_at REAL
        )
        """
    )
    connection.execute(
        "INSERT INTO forensic_cases "
        "(id, analysis_id, sha256, created_at) VALUES (?, ?, ?, ?)",
        ("legacy-case", "legacy-analysis", "ab" * 32, 1.0),
    )
    connection.commit()
    connection.close()

    db = WatchtowerDB(data_dir=str(tmp_path))
    try:
        legacy = db.get_forensic_case("legacy-case")
        tables = {
            row[0]
            for row in db.engine.connect().exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert legacy["retention_mode"] == "discard"
        assert legacy["encryption_format"] is None
        assert legacy["configuration_hash"] is None
        assert legacy["pipeline_version"] is None
        assert "forensic_analysis_revisions" in tables
        assert "forensic_evidence_envelopes" in tables
    finally:
        db.close()


class GateEngine:
    original_path = None
    started = threading.Event()
    release = threading.Event()
    observed = {}

    def __init__(self, **_kwargs):
        pass

    def analyze_pcap(self, path, progress_callback, source_name, mode, backend, cancel_event, **options):
        type(self).observed = {
            "original_exists": Path(type(self).original_path).exists(),
            "analysis_path": str(path),
            "analysis_exists": Path(path).exists(),
            "keylog_file": options.get("keylog_file"),
        }
        type(self).started.set()
        type(self).release.wait(timeout=3)
        size = Path(path).stat().st_size
        progress_callback(size, size)
        return SimpleNamespace(
            status="COMPLETE",
            summary={"total_flows": 1},
            bytes_processed=size,
            error=None,
            report_id=None,
        )


def _wait_for_terminal(manager, job_id, timeout=5):
    deadline = time.time() + timeout
    job = manager.get(job_id)
    while job["status"] not in {"complete", "partial", "failed", "cancelled"} and time.time() < deadline:
        time.sleep(0.01)
        job = manager.get(job_id)
    return job


def test_submit_encrypts_before_engine_and_public_projection_is_redacted(tmp_path):
    GateEngine.started = threading.Event()
    GateEngine.release = threading.Event()
    GateEngine.observed = {}
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "submitted.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    GateEngine.original_path = capture
    manager = PcapJobManager(db=db, engine_factory=GateEngine, credential_store=credentials)
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        assert GateEngine.started.wait(timeout=3)
        assert not capture.exists()
        assert GateEngine.observed["original_exists"] is False
        assert GateEngine.observed["analysis_exists"] is True
        assert GateEngine.observed["analysis_path"].endswith(".active")
        assert submitted["retention_mode"] == "encrypted"
        assert submitted["encryption_format"] == "aes-256-gcm-chunked-v1"
        assert submitted["pipeline_version"] == PIPELINE_VERSION
        assert len(submitted["configuration_hash"]) == 64
        assert submitted["analysis_id"].startswith("analysis-")
        serialized = repr(submitted)
        for secret in credentials.secrets.values():
            assert secret not in serialized
        assert "credential_reference" not in serialized
        assert "nonce" not in serialized
        assert "encrypted_path" not in serialized
    finally:
        GateEngine.release.set()
        manager.shutdown()
        db.close()


def test_retained_ciphertext_is_published_under_the_case_evidence_root(tmp_path):
    GateEngine.started = threading.Event()
    GateEngine.release = threading.Event()
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    evidence_root = tmp_path / "cases"
    capture = tmp_path / "upload" / "submitted.pcap"
    capture.parent.mkdir()
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    GateEngine.original_path = capture
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=evidence_root,
    )
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        assert GateEngine.started.wait(timeout=3)
        retained = list((evidence_root / submitted["case_id"]).rglob("*.wte"))
        assert len(retained) == 1
        assert not list(capture.parent.glob("*.wte"))
    finally:
        GateEngine.release.set()
        manager.shutdown()
        db.close()


def test_submission_persistence_failure_cleans_ciphertext_key_and_revision_state(tmp_path):
    class FailingEnvelopeDatabase(WatchtowerDB):
        def save_forensic_evidence_envelope(self, values):
            raise RuntimeError("envelope persistence failed")

    credentials = MemoryCredentialStore()
    db = FailingEnvelopeDatabase(data_dir=str(tmp_path / "db"))
    evidence_root = tmp_path / "cases"
    capture = tmp_path / "submitted.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x03" * 64)
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=evidence_root,
    )
    try:
        with pytest.raises(RuntimeError, match="envelope persistence failed"):
            manager.submit(str(capture), capture.name, "memory", "python")

        cases = db.list_forensic_cases()
        assert len(cases) == 1
        assert cases[0]["state"] == "failed"
        assert not list(evidence_root.rglob("*.wte"))
        assert credentials.secrets == {}
    finally:
        manager.shutdown()
        db.close()


def test_case_revision_persistence_failure_aborts_submission(tmp_path):
    class FailingCaseDatabase(WatchtowerDB):
        def save_forensic_case_revision(self, case_values, revision_values):
            raise RuntimeError("case persistence failed")

    credentials = MemoryCredentialStore()
    db = FailingCaseDatabase(data_dir=str(tmp_path / "db"))
    evidence_root = tmp_path / "cases"
    capture = tmp_path / "submitted.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x04" * 64)
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=evidence_root,
    )
    try:
        with pytest.raises(RuntimeError, match="case persistence failed"):
            manager.submit(str(capture), capture.name, "memory", "python")
        assert not list(evidence_root.rglob("*.wte"))
        assert credentials.secrets == {}
    finally:
        manager.shutdown()
        db.close()


def test_tls_keylog_digest_participates_in_analysis_identity(tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    GateEngine.release.set()
    try:
        jobs = []
        for suffix, keylog_content in (
            ("none", None),
            ("first", b"CLIENT_RANDOM first value"),
            ("second", b"CLIENT_RANDOM second value"),
        ):
            capture = tmp_path / f"{suffix}.pcap"
            capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x05" * 64)
            keylog = None
            if keylog_content is not None:
                keylog = tmp_path / f"{suffix}.keylog"
                keylog.write_bytes(keylog_content)
            submitted = manager.submit(
                str(capture),
                capture.name,
                "memory",
                "python",
                keylog_path=str(keylog) if keylog else None,
            )
            jobs.append(_wait_for_terminal(manager, submitted["id"]))

        assert len({job["case_id"] for job in jobs}) == 1
        assert len({job["analysis_id"] for job in jobs}) == 3
        assert len({job["configuration_hash"] for job in jobs}) == 3
    finally:
        manager.shutdown()
        db.close()


def test_same_identity_rerun_keeps_completed_case_projection_immutable(tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    GateEngine.started = threading.Event()
    GateEngine.release = threading.Event()
    GateEngine.release.set()
    try:
        first_capture = tmp_path / "first.pcap"
        first_capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x0a" * 64)
        first = manager.submit(str(first_capture), first_capture.name, "memory", "python")
        first_job = _wait_for_terminal(manager, first["id"])
        original_case = db.get_forensic_case(first_job["case_id"])
        assert original_case["state"] == "complete"
        assert original_case["report_hash"]

        GateEngine.started = threading.Event()
        GateEngine.release = threading.Event()
        second_capture = tmp_path / "second.pcap"
        second_capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x0a" * 64)
        second = manager.submit(str(second_capture), second_capture.name, "memory", "python")
        assert GateEngine.started.wait(timeout=3)
        projected = db.get_forensic_case(second["case_id"])

        assert second["analysis_id"] == first["analysis_id"]
        assert projected["state"] == "complete"
        assert projected["report_hash"] == original_case["report_hash"]
        assert projected["completed_at"] == original_case["completed_at"]
    finally:
        GateEngine.release.set()
        manager.shutdown()
        db.close()


def test_explicit_discard_removes_encrypted_staging_active_plaintext_and_key(tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "discard.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x01" * 64)
    manager = PcapJobManager(db=db, engine_factory=GateEngine, credential_store=credentials)
    GateEngine.release.set()
    try:
        submitted = manager.submit(
            str(capture),
            capture.name,
            "streaming",
            "python",
            retain_input=False,
        )
        job = _wait_for_terminal(manager, submitted["id"])

        assert job["status"] == "complete"
        assert job["retention_mode"] == "discard"
        assert credentials.secrets == {}
        assert not list(tmp_path.rglob("*.active"))
        assert not list(tmp_path.rglob("*.wte"))
    finally:
        manager.shutdown()
        db.close()


def test_ciphertext_cleanup_failure_preserves_retry_metadata_and_case_key(monkeypatch, tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "discard.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x06" * 64)
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    GateEngine.release.set()
    real_remove = pcap_jobs_module.os.remove

    def fail_ciphertext_remove(path):
        if str(path).endswith(".pcap.wte"):
            raise PermissionError("locked retained ciphertext")
        return real_remove(path)

    monkeypatch.setattr(pcap_jobs_module.os, "remove", fail_ciphertext_remove)
    try:
        submitted = manager.submit(
            str(capture), capture.name, "memory", "python", retain_input=False
        )
        job = _wait_for_terminal(manager, submitted["id"])
        envelope_row = db.get_forensic_evidence_envelope(job["id"], "pcap")

        assert job["status"] == "partial"
        assert envelope_row is not None
        assert Path(envelope_row["encrypted_path"]).exists()
        assert credentials.get(envelope_row["credential_reference"])
    finally:
        manager.shutdown()
        db.close()


def test_active_plaintext_cleanup_failure_still_terminalizes_job(monkeypatch, tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "active-cleanup.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x07" * 64)
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    GateEngine.release.set()
    real_remove = pcap_jobs_module.os.remove

    def fail_active_remove(path):
        if str(path).endswith(".active"):
            raise PermissionError("locked active plaintext")
        return real_remove(path)

    monkeypatch.setattr(pcap_jobs_module.os, "remove", fail_active_remove)
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_terminal(manager, submitted["id"])
        assert job["status"] == "partial"
        assert job["status"] != "running"
    finally:
        manager.shutdown()
        db.close()


def test_public_job_error_does_not_disclose_evidence_paths(monkeypatch, tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "redacted.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x08" * 64)
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "secret-case-root",
    )
    secret_path = tmp_path / "secret-case-root" / "private-ciphertext.wte"

    def fail_with_path(*_args, **_kwargs):
        raise FileNotFoundError(str(secret_path))

    monkeypatch.setattr(manager.evidence_envelope, "decrypt", fail_with_path)
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_terminal(manager, submitted["id"])
        assert job["status"] == "failed"
        assert str(secret_path) not in str(job["error"])
        assert "secret-case-root" not in str(job["error"])
    finally:
        manager.shutdown()
        db.close()


def test_interrupted_keylog_cleanup_does_not_delete_retained_case_key(tmp_path):
    GateEngine.started = threading.Event()
    GateEngine.release = threading.Event()
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "restart.pcap"
    keylog = tmp_path / "restart.keylog"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x09" * 64)
    keylog.write_bytes(b"CLIENT_RANDOM restart value")
    first = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    restored = None
    try:
        submitted = first.submit(
            str(capture), capture.name, "memory", "python", keylog_path=str(keylog)
        )
        assert GateEngine.started.wait(timeout=3)
        pcap_metadata = db.get_forensic_evidence_envelope(submitted["id"], "pcap")
        restored = PcapJobManager(
            db=db,
            engine_factory=GateEngine,
            credential_store=credentials,
            evidence_root=tmp_path / "cases",
        )
        retained = db.get_forensic_evidence_envelope(submitted["id"], "pcap")

        assert retained is not None
        assert credentials.get(pcap_metadata["credential_reference"])
        output = tmp_path / "retained.active"
        restored.evidence_envelope.decrypt(restored._metadata_from_row(retained), output)
        assert output.exists()
    finally:
        GateEngine.release.set()
        if restored:
            restored.shutdown()
        first.shutdown()
        db.close()


def test_restart_cleanup_error_is_bounded_and_manager_still_restores(monkeypatch, tmp_path):
    GateEngine.started = threading.Event()
    GateEngine.release = threading.Event()
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "restart-locked.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x0b" * 64)
    first = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=credentials,
        evidence_root=tmp_path / "cases",
    )
    restored = None
    try:
        submitted = first.submit(str(capture), capture.name, "memory", "python")
        assert GateEngine.started.wait(timeout=3)
        real_remove = pcap_jobs_module.os.remove

        def fail_active_remove(path):
            if str(path).endswith(".active"):
                raise PermissionError("locked active plaintext")
            return real_remove(path)

        monkeypatch.setattr(pcap_jobs_module.os, "remove", fail_active_remove)
        restored = PcapJobManager(
            db=db,
            engine_factory=GateEngine,
            credential_store=credentials,
            evidence_root=tmp_path / "cases",
        )
        job = restored.get(submitted["id"])

        assert job is not None
        assert job["status"] == "failed"
        assert job["error"] == "Evidence cleanup is pending and will be retried on restart"
    finally:
        GateEngine.release.set()
        if restored:
            restored.shutdown()
        first.shutdown()
        db.close()


def test_restart_redacts_path_bearing_legacy_terminal_errors(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    secret_path = tmp_path / "cases" / "private" / "capture.pcap.wte"
    db.save_pcap_analysis_job({
        "id": "legacy-terminal-job",
        "filename": "capture.pcap",
        "file_size": 64,
        "mode": "memory",
        "backend": "python",
        "source": "pcap:legacy-terminal-job:capture.pcap",
        "status": "failed",
        "created_at": 1.0,
        "completed_at": 2.0,
        "error": f"PCAP analysis failed (FileNotFoundError: '{secret_path}')",
        "retained_input": False,
        "retention_mode": "discard",
    })

    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
    )
    try:
        restored = manager.get("legacy-terminal-job")
        assert restored["status"] == "failed"
        assert restored["error"] == "PCAP analysis failed"
        assert str(secret_path) not in restored["error"]
    finally:
        manager.shutdown()
        db.close()


def test_integrity_failure_never_completes_and_leaves_no_active_plaintext(monkeypatch, tmp_path):
    credentials = MemoryCredentialStore()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "corrupt.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x02" * 64)
    manager = PcapJobManager(db=db, engine_factory=GateEngine, credential_store=credentials)

    def reject_integrity(*_args, **_kwargs):
        raise EvidenceIntegrityError("tampered evidence")

    monkeypatch.setattr(manager.evidence_envelope, "decrypt", reject_integrity)
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_terminal(manager, submitted["id"])

        assert job["status"] in {"failed", "partial"}
        assert job["status"] != "complete"
        assert job["error"] == "Retained evidence failed integrity verification"
        assert not list(tmp_path.rglob("*.active"))
        revision = db.get_forensic_analysis_revision(job["analysis_id"])
        assert revision["state"] in {"failed", "partial"}
    finally:
        manager.shutdown()
        db.close()

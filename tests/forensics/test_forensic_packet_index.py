from hashlib import sha256
import importlib
import json
from pathlib import Path
import threading

import pytest

from core.forensics.packet_index import (
    PacketIndexBuilder,
    PacketIndexCancelled,
    PacketIndexError,
    PacketIndexReader,
)
from core.forensics.packet_query import PacketFilter, PacketQuery
from core.api.pcap_jobs import PcapJobManager
from core.storage.database import WatchtowerDB
from tests.forensics.test_forensic_evidence_retention import (
    GateEngine,
    MemoryCredentialStore,
    _wait_for_terminal,
)


def _record(ordinal, *, src_ip="192.0.2.10", dst_ip="198.51.100.20", decoded=True):
    return {
        "packet_ordinal": ordinal,
        "timestamp": 100.0 + ordinal,
        "caplen": 64,
        "wirelen": 64,
        "link_type": "ethernet",
        "decoded": decoded,
        "decode_reason": "" if decoded else "unsupported_ethertype",
        "src_ip": src_ip if decoded else None,
        "dst_ip": dst_ip if decoded else None,
        "src_port": 49_152 if decoded else 0,
        "dst_port": 443 if decoded else 0,
        "protocol": "TCP" if decoded else "OTHER",
        "ip_protocol": 6 if decoded else 0,
        "tcp_flags": "SA" if decoded else "",
        "frame_sha256": sha256(f"frame-{ordinal}".encode()).hexdigest(),
    }


def test_packet_index_builds_atomic_partitioned_manifest_and_bounded_queries(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"pcap-index-fixture")
    digest = sha256(pcap.read_bytes()).hexdigest()
    records = [_record(index) for index in range(1, 6)]
    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter(records),
        partition_rows=2,
        batch_rows=2,
    )

    manifest = builder.build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-test",
        pcap_sha256=digest,
    )

    assert manifest["schema_version"] == 1
    assert manifest["analysis_id"] == "analysis-test"
    assert manifest["pcap_sha256"] == digest
    assert manifest["row_count"] == 5
    assert manifest["first_timestamp"] == 101.0
    assert manifest["last_timestamp"] == 105.0
    assert len(manifest["partitions"]) == 3
    assert sum(item["row_count"] for item in manifest["partitions"]) == 5
    assert all(len(item["sha256"]) == 64 for item in manifest["partitions"])
    assert not list((tmp_path / "cases").rglob("*.tmp"))

    reader = PacketIndexReader.from_manifest(manifest["manifest_path"])
    first = reader.query(PacketQuery(
        select=("packet_ordinal", "src_ip", "dst_port"),
        filters=(PacketFilter("dst_port", "eq", 443),),
        limit=2,
    ))
    second = reader.query(PacketQuery(
        select=("packet_ordinal", "src_ip", "dst_port"),
        filters=(PacketFilter("dst_port", "eq", 443),),
        cursor=first["next_cursor"],
        limit=2,
    ))

    assert [item["packet_ordinal"] for item in first["items"]] == [1, 2]
    assert first["next_cursor"] == 2
    assert [item["packet_ordinal"] for item in second["items"]] == [3, 4]
    assert "raw" not in first["items"][0]


def test_packet_index_reader_bounds_default_and_explicit_partition_scans(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"partition-scan-bounds")
    digest = sha256(pcap.read_bytes()).hexdigest()
    manifest = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: (_record(index) for index in range(1, 34)),
        partition_rows=1,
        batch_rows=8,
    ).build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-partition-bounds",
        pcap_sha256=digest,
    )
    reader = PacketIndexReader.from_manifest(manifest["manifest_path"])

    with pytest.raises(PacketIndexError, match="at most 32"):
        reader.query(PacketQuery(select=("packet_ordinal",), limit=10))

    result = reader.query(PacketQuery(
        select=("packet_ordinal",),
        partition_ids=(0, 1),
        limit=10,
    ))
    assert [item["packet_ordinal"] for item in result["items"]] == [1, 2]


def test_packet_index_normalizes_rust_protocol_and_numeric_tcp_flags(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"rust-shaped-index")
    digest = sha256(pcap.read_bytes()).hexdigest()
    rust_record = _record(1)
    rust_record.pop("ip_protocol")
    rust_record["tcp_flags"] = 0x12
    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([rust_record]),
    )

    manifest = builder.build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-rust-shape",
        pcap_sha256=digest,
    )
    result = PacketIndexReader.from_manifest(manifest["manifest_path"]).query(
        PacketQuery(
            select=("packet_ordinal", "protocol", "ip_protocol", "tcp_flags"),
            limit=1,
        )
    )

    assert result["items"] == [{
        "packet_ordinal": 1,
        "protocol": "TCP",
        "ip_protocol": 6,
        "tcp_flags": "SA",
    }]


def test_packet_index_normalizes_rust_protocol_without_transport_ports(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"rust-icmp-index")
    digest = sha256(pcap.read_bytes()).hexdigest()
    rust_record = _record(1)
    rust_record.pop("ip_protocol")
    rust_record.update({
        "src_port": None,
        "dst_port": None,
        "protocol": "ICMP",
        "tcp_flags": None,
    })
    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([rust_record]),
    )

    manifest = builder.build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-rust-icmp",
        pcap_sha256=digest,
    )
    result = PacketIndexReader.from_manifest(manifest["manifest_path"]).query(
        PacketQuery(
            select=("protocol", "ip_protocol", "src_port", "dst_port", "tcp_flags"),
            limit=1,
        )
    )

    assert result["items"] == [{
        "protocol": "ICMP",
        "ip_protocol": 1,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": "",
    }]


def test_packet_index_uses_genuinely_bounded_bulk_import_batches(
    monkeypatch, tmp_path
):
    duckdb = importlib.import_module("duckdb")
    real_connect = duckdb.connect
    import_copies = []

    class ConnectionProxy:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, statement, *args, **kwargs):
            if str(statement).lstrip().startswith("COPY packet_import FROM"):
                import_copies.append(statement)
            return self.connection.execute(statement, *args, **kwargs)

        def executemany(self, *_args, **_kwargs):
            pytest.fail("packet index must use bounded bulk import")

    monkeypatch.setattr(
        duckdb,
        "connect",
        lambda *args, **kwargs: ConnectionProxy(real_connect(*args, **kwargs)),
    )
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"bulk-index")
    digest = sha256(pcap.read_bytes()).hexdigest()

    manifest = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: (_record(index) for index in range(1, 101)),
        batch_rows=10,
    ).build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-bulk",
        pcap_sha256=digest,
    )

    assert manifest["row_count"] == 100
    assert len(import_copies) == 10


@pytest.mark.parametrize("cancel_phase", ["import", "export"])
def test_packet_index_interrupts_duckdb_during_import_and_export(
    monkeypatch, tmp_path, cancel_phase
):
    duckdb = importlib.import_module("duckdb")
    real_connect = duckdb.connect
    cancelled = threading.Event()
    interrupted = threading.Event()

    class ConnectionProxy:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, statement, *args, **kwargs):
            sql = str(statement)
            is_import = sql.lstrip().startswith("COPY packet_import FROM")
            is_export = "FORMAT PARQUET" in sql
            if (
                (cancel_phase == "import" and is_import)
                or (cancel_phase == "export" and is_export)
            ):
                cancelled.set()
                if not interrupted.wait(2):
                    raise AssertionError("DuckDB operation was not interrupted")
                raise RuntimeError("interrupted by cancellation")
            return self.connection.execute(statement, *args, **kwargs)

        def interrupt(self):
            interrupted.set()

    monkeypatch.setattr(
        duckdb,
        "connect",
        lambda *args, **kwargs: ConnectionProxy(real_connect(*args, **kwargs)),
    )
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(f"cancel-{cancel_phase}".encode())
    digest = sha256(pcap.read_bytes()).hexdigest()
    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: (_record(index) for index in range(1, 4)),
        partition_rows=2,
        batch_rows=2,
    )

    with pytest.raises(PacketIndexCancelled):
        builder.build(
            pcap,
            case_id=f"case-{digest}",
            analysis_id=f"analysis-cancel-{cancel_phase}",
            pcap_sha256=digest,
            cancel_event=cancelled,
        )

    assert interrupted.is_set()
    assert not list((tmp_path / "cases").rglob("manifest.json"))
    assert not list((tmp_path / "cases").rglob("*.parquet"))


def test_packet_index_is_idempotent_and_rejects_manifest_or_partition_corruption(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"immutable-index")
    digest = sha256(pcap.read_bytes()).hexdigest()
    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([_record(1)]),
        partition_rows=10,
    )
    first = builder.build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-immutable",
        pcap_sha256=digest,
    )
    second = builder.build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-immutable",
        pcap_sha256=digest,
    )
    assert first == second

    manifest_path = Path(first["manifest_path"])
    partition_path = manifest_path.parent / first["partitions"][0]["path"]
    partition_path.write_bytes(partition_path.read_bytes() + b"tamper")
    with pytest.raises(PacketIndexError, match="hash"):
        PacketIndexReader.from_manifest(manifest_path)

    partition_path.write_bytes(partition_path.read_bytes()[:-6])
    raw_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_manifest["analysis_id"] = "../different"
    manifest_path.write_text(json.dumps(raw_manifest), encoding="utf-8")
    with pytest.raises(PacketIndexError):
        PacketIndexReader.from_manifest(manifest_path)


def test_packet_index_reader_rejects_partition_replaced_after_open(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"partition-replacement")
    digest = sha256(pcap.read_bytes()).hexdigest()
    original = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([_record(1, src_ip="192.0.2.1")]),
    ).build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-original",
        pcap_sha256=digest,
    )
    replacement = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([_record(1, src_ip="203.0.113.99")]),
    ).build(
        pcap,
        case_id=f"case-{digest}",
        analysis_id="analysis-replacement",
        pcap_sha256=digest,
    )
    reader = PacketIndexReader.from_manifest(original["manifest_path"])
    original_partition = (
        Path(original["manifest_path"]).parent / original["partitions"][0]["path"]
    )
    replacement_partition = (
        Path(replacement["manifest_path"]).parent
        / replacement["partitions"][0]["path"]
    )
    original_partition.write_bytes(replacement_partition.read_bytes())

    with pytest.raises(PacketIndexError, match="hash"):
        reader.query(PacketQuery(select=("packet_ordinal", "src_ip"), limit=1))


def test_packet_index_cancellation_removes_staging_and_does_not_publish(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"cancelled-index")
    digest = sha256(pcap.read_bytes()).hexdigest()
    cancelled = threading.Event()

    def records(_path):
        yield _record(1)
        cancelled.set()
        yield _record(2)

    builder = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=records,
        partition_rows=1,
        batch_rows=1,
    )
    with pytest.raises(PacketIndexCancelled):
        builder.build(
            pcap,
            case_id=f"case-{digest}",
            analysis_id="analysis-cancelled",
            pcap_sha256=digest,
            cancel_event=cancelled,
        )

    assert not list((tmp_path / "cases").rglob("manifest.json"))
    assert not list((tmp_path / "cases").rglob("*.parquet"))
    assert not list((tmp_path / "cases").rglob("*.duckdb"))
    assert not list((tmp_path / "cases").rglob("*.tmp"))


def test_packet_index_rejects_digest_mismatch_invalid_rows_and_unsafe_manifest_paths(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"validated-index")
    digest = sha256(pcap.read_bytes()).hexdigest()

    with pytest.raises(PacketIndexError, match="digest"):
        PacketIndexBuilder(
            root=tmp_path / "cases",
            record_source=lambda _path: iter([_record(1)]),
        ).build(
            pcap,
            case_id=f"case-{digest}",
            analysis_id="analysis-digest",
            pcap_sha256="00" * 32,
        )

    invalid = _record(2)
    with pytest.raises(PacketIndexError, match="ordinal"):
        PacketIndexBuilder(
            root=tmp_path / "cases",
            record_source=lambda _path: iter([invalid]),
        ).build(
            pcap,
            case_id=f"case-{digest}",
            analysis_id="analysis-invalid",
            pcap_sha256=digest,
        )

    manifest_dir = tmp_path / "unsafe"
    manifest_dir.mkdir()
    outside = tmp_path / "outside.parquet"
    outside.write_bytes(b"not parquet")
    (manifest_dir / "manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "case_id": "case-safe",
        "analysis_id": "analysis-safe",
        "pcap_sha256": digest,
        "row_count": 0,
        "partitions": [{"path": "../outside.parquet", "sha256": sha256(outside.read_bytes()).hexdigest(), "row_count": 0}],
    }), encoding="utf-8")
    with pytest.raises(PacketIndexError, match="path"):
        PacketIndexReader.from_manifest(manifest_dir / "manifest.json")


def test_packet_index_manifest_repository_is_revision_scoped_and_idempotent(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    digest = "ab" * 32
    case_id = f"case-{digest}"
    analysis_id = "analysis-" + "cd" * 32
    db.save_forensic_case_revision(
        {
            "id": case_id,
            "analysis_id": analysis_id,
            "sha256": digest,
            "state": "running",
        },
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": "ef" * 32,
            "backend": "rust",
            "state": "running",
        },
    )
    values = {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "pcap_sha256": digest,
        "schema_version": 1,
        "manifest_path": str(tmp_path / "manifest.json"),
        "manifest_sha256": "12" * 32,
        "row_count": 123,
        "partition_count": 2,
        "first_timestamp": 10.0,
        "last_timestamp": 20.0,
        "state": "complete",
        "created_at": 30.0,
    }
    try:
        first = db.save_forensic_packet_index(values)
        repeated = db.save_forensic_packet_index(values)
        assert first == repeated
        assert db.get_forensic_packet_index(analysis_id)["row_count"] == 123

        with pytest.raises(ValueError, match="identity"):
            db.save_forensic_packet_index({**values, "pcap_sha256": "00" * 32})
    finally:
        db.close()


def test_packet_index_repository_rejects_orphaned_and_cross_scope_saves(tmp_path):
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    digest = "34" * 32
    case_id = f"case-{digest}"
    analysis_id = "analysis-" + "56" * 32
    values = {
        "analysis_id": analysis_id,
        "case_id": case_id,
        "pcap_sha256": digest,
        "schema_version": 1,
        "manifest_path": str(tmp_path / "manifest.json"),
        "manifest_sha256": "78" * 32,
        "row_count": 1,
        "partition_count": 1,
        "state": "complete",
    }
    try:
        with pytest.raises(ValueError, match="revision"):
            db.save_forensic_packet_index(values)

        db.save_forensic_case_revision(
            {
                "id": case_id,
                "analysis_id": analysis_id,
                "sha256": digest,
                "state": "running",
            },
            {
                "case_id": case_id,
                "analysis_id": analysis_id,
                "pcap_sha256": digest,
                "pipeline_version": "watchtower-forensics-v2.0",
                "configuration_hash": "9a" * 32,
                "backend": "rust",
                "state": "running",
            },
        )

        with pytest.raises(ValueError, match="scope"):
            db.save_forensic_packet_index({
                **values,
                "case_id": "case-" + "bc" * 32,
            })
        with pytest.raises(ValueError, match="scope"):
            db.save_forensic_packet_index({
                **values,
                "pcap_sha256": "de" * 32,
            })
    finally:
        db.close()


def test_packet_index_reader_verifies_repository_manifest_digest_and_scope(tmp_path):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"repository-backed-index")
    digest = sha256(pcap.read_bytes()).hexdigest()
    case_id = f"case-{digest}"
    analysis_id = "analysis-" + "ef" * 32
    manifest = PacketIndexBuilder(
        root=tmp_path / "cases",
        record_source=lambda _path: iter([_record(1)]),
    ).build(
        pcap,
        case_id=case_id,
        analysis_id=analysis_id,
        pcap_sha256=digest,
    )
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    db.save_forensic_case_revision(
        {
            "id": case_id,
            "analysis_id": analysis_id,
            "sha256": digest,
            "state": "complete",
        },
        {
            "case_id": case_id,
            "analysis_id": analysis_id,
            "pcap_sha256": digest,
            "pipeline_version": "watchtower-forensics-v2.0",
            "configuration_hash": "12" * 32,
            "backend": "rust",
            "state": "complete",
        },
    )
    db.save_forensic_packet_index({
        **manifest,
        "partition_count": len(manifest["partitions"]),
        "state": "complete",
    })
    try:
        reader = PacketIndexReader.from_repository(db, analysis_id)
        assert reader.manifest["analysis_id"] == analysis_id

        manifest_path = Path(manifest["manifest_path"])
        manifest_path.write_text(
            manifest_path.read_text(encoding="utf-8") + " ",
            encoding="utf-8",
        )
        with pytest.raises(PacketIndexError, match="manifest hash"):
            PacketIndexReader.from_repository(db, analysis_id)
    finally:
        db.close()


def test_pcap_job_persists_packet_index_without_leaking_manifest_path(tmp_path):
    class RecordingBuilder:
        def __init__(self):
            self.calls = []

        def build(self, path, **values):
            self.calls.append((path, values))
            return {
                "schema_version": 1,
                "case_id": values["case_id"],
                "analysis_id": values["analysis_id"],
                "pcap_sha256": values["pcap_sha256"],
                "manifest_path": str(tmp_path / "private" / "manifest.json"),
                "manifest_sha256": "12" * 32,
                "row_count": 2,
                "partitions": [
                    {"path": "parquet/partition_id=0/data.parquet", "row_count": 2}
                ],
                "first_timestamp": 1.0,
                "last_timestamp": 2.0,
                "created_at": 3.0,
            }

    GateEngine.release.set()
    builder = RecordingBuilder()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    GateEngine.original_path = capture
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
        packet_index_builder=builder,
    )
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_terminal(manager, submitted["id"])
        stored = db.get_forensic_packet_index(job["analysis_id"])

        assert job["status"] == "complete"
        assert len(builder.calls) == 1
        assert builder.calls[0][1]["analysis_id"] == job["analysis_id"]
        assert stored["row_count"] == 2
        assert job["summary"]["packet_index"] == {
            "state": "complete",
            "schema_version": 1,
            "row_count": 2,
            "partition_count": 1,
            "manifest_sha256": "12" * 32,
        }
        assert "manifest_path" not in repr(job["summary"]["packet_index"])
    finally:
        manager.shutdown()
        db.close()


def test_packet_index_failure_marks_analysis_partial_with_visibility_limit(tmp_path):
    class FailingBuilder:
        def build(self, path, **values):
            raise PacketIndexError("private index path must not leak")

    GateEngine.release.set()
    db = WatchtowerDB(data_dir=str(tmp_path / "db"))
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
    GateEngine.original_path = capture
    manager = PcapJobManager(
        db=db,
        engine_factory=GateEngine,
        credential_store=MemoryCredentialStore(),
        evidence_root=tmp_path / "cases",
        packet_index_builder=FailingBuilder(),
    )
    try:
        submitted = manager.submit(str(capture), capture.name, "memory", "python")
        job = _wait_for_terminal(manager, submitted["id"])

        assert job["status"] == "partial"
        assert job["summary"]["packet_index"]["state"] == "failed"
        assert "packet_index_unavailable" in job["summary"]["visibility_limitations"]
        case = db.get_forensic_case(job["case_id"])
        revision = db.get_forensic_analysis_revision(job["analysis_id"])
        assert "packet_index_unavailable" in case["visibility_limitations"]
        assert "packet_index_unavailable" in revision["visibility_limitations"]
        assert "private index path" not in repr(job)
    finally:
        manager.shutdown()
        db.close()

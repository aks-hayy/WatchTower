"""Immutable Parquet packet indexes backed by bounded DuckDB operations."""

from __future__ import annotations

import csv
from dataclasses import asdict, is_dataclass
from hashlib import sha256
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping
import uuid

from core.forensics.packet_query import MAX_PARTITIONS, PacketQuery, compile_packet_query


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_FRAME_LENGTH = 2**32 - 1
IP_PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPV6": 58,
    "ARP": 254,
}
TCP_FLAG_NAMES = (
    (0x02, "S"),
    (0x10, "A"),
    (0x01, "F"),
    (0x04, "R"),
    (0x08, "P"),
    (0x20, "U"),
)


class PacketIndexError(RuntimeError):
    pass


class PacketIndexCancelled(PacketIndexError):
    pass


def _file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = sha256()
    with path.open("rb") as source:
        while chunk := source.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _default_record_source(path: str | Path):
    from core.packet_engine.rust_capture import iter_packet_index

    return iter_packet_index(path)


def python_record_source(path: str | Path):
    """Yield redacted packet-index metadata without retaining frame bytes.

    This is the explicit Python replay path used when the Rust sensor is not
    selected.  It keeps the packet index contract identical to the Rust
    source, while avoiding an accidental Rust dependency in a Python job.
    """
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import PcapReader

    def protocol_for(packet):
        if ARP in packet:
            return "ARP", 254
        if TCP in packet:
            return "TCP", 6
        if UDP in packet:
            return "UDP", 17
        if ICMP in packet:
            return "ICMP", 1
        if ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
            return "ICMPV6", 58
        if IP in packet:
            return "IP", int(packet[IP].proto)
        if IPv6 in packet:
            return "IPv6", int(packet[IPv6].nh)
        return "", 0

    with PcapReader(str(path)) as reader:
        for ordinal, packet in enumerate(reader, start=1):
            raw = bytes(packet)
            source = packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else ""
            destination = packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else ""
            protocol, ip_protocol = protocol_for(packet)
            source_port = int(packet[TCP].sport if TCP in packet else packet[UDP].sport) if TCP in packet or UDP in packet else 0
            destination_port = int(packet[TCP].dport if TCP in packet else packet[UDP].dport) if TCP in packet or UDP in packet else 0
            tcp_flags = str(packet[TCP].flags) if TCP in packet else ""
            yield {
                "packet_ordinal": ordinal,
                "timestamp": float(packet.time),
                "caplen": len(raw),
                "wirelen": int(getattr(packet, "wirelen", len(raw)) or len(raw)),
                "link_type": "ethernet" if Ether in packet else "unknown",
                "decoded": bool(source and destination),
                "decode_reason": "" if source and destination else "unsupported link or network layer",
                "src_ip": source or None,
                "dst_ip": destination or None,
                "src_port": source_port,
                "dst_port": destination_port,
                "protocol": protocol,
                "ip_protocol": ip_protocol,
                "tcp_flags": tcp_flags,
                "frame_sha256": sha256(raw).hexdigest(),
            }


def _record_mapping(record: Any) -> Mapping[str, Any]:
    if isinstance(record, Mapping):
        return record
    if is_dataclass(record):
        return asdict(record)
    if hasattr(record, "__dict__"):
        return vars(record)
    raise PacketIndexError("packet index record must be a mapping or dataclass")


def _bounded_text(value: Any, name: str, maximum: int) -> str:
    text = str(value or "")
    if len(text) > maximum or "\x00" in text:
        raise PacketIndexError(f"{name} is invalid")
    return text


def _address_fields(value: Any, name: str):
    if value in (None, ""):
        return None, None, None
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise PacketIndexError(f"{name} is invalid") from exc
    return str(address), address.version, address.packed


def _tcp_flags(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        raise PacketIndexError("TCP flags are invalid")
    if isinstance(value, int):
        if not 0 <= value <= 0xFF:
            raise PacketIndexError("TCP flags are invalid")
        return "".join(name for mask, name in TCP_FLAG_NAMES if value & mask)
    return _bounded_text(value, "TCP flags", 16)


class PacketIndexBuilder:
    def __init__(
        self,
        *,
        root: str | Path,
        record_source: Callable[[str | Path], Iterable[Any]] | None = None,
        partition_rows: int = 250_000,
        batch_rows: int = 4096,
    ):
        self.root = Path(root)
        self.record_source = record_source or _default_record_source
        self.partition_rows = max(1, int(partition_rows))
        self.batch_rows = max(1, min(int(batch_rows), 65_536))

    @staticmethod
    def _check_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event and cancel_event.is_set():
            raise PacketIndexCancelled("packet indexing was cancelled")

    def _execute_cancellable(
        self,
        connection: Any,
        statement: str,
        cancel_event: threading.Event | None,
    ):
        self._check_cancelled(cancel_event)
        if cancel_event is None:
            return connection.execute(statement)

        finished = threading.Event()

        def interrupt_on_cancel() -> None:
            while not finished.wait(0.01):
                if cancel_event.is_set():
                    try:
                        connection.interrupt()
                    except Exception:
                        pass
                    return

        watcher = threading.Thread(
            target=interrupt_on_cancel,
            name="packet-index-duckdb-cancel",
            daemon=True,
        )
        watcher.start()
        try:
            result = connection.execute(statement)
        except Exception as exc:
            if cancel_event.is_set():
                raise PacketIndexCancelled("packet indexing was cancelled") from exc
            raise
        finally:
            finished.set()
            watcher.join()
        self._check_cancelled(cancel_event)
        return result

    def _import_batch(
        self,
        connection: Any,
        import_path: Path,
        rows: list[tuple[Any, ...]],
        cancel_event: threading.Event | None,
    ) -> None:
        self._check_cancelled(cancel_event)
        with import_path.open("w", encoding="utf-8", newline="") as spool:
            writer = csv.writer(spool, lineterminator="\n")
            writer.writerows(
                (
                    r"\N" if value is None else (
                        value.hex() if isinstance(value, bytes) else value
                    )
                    for value in row
                )
                for row in rows
            )
        import_sql_path = str(import_path).replace("'", "''")
        connection.execute("DELETE FROM packet_import")
        try:
            self._execute_cancellable(
                connection,
                f"COPY packet_import FROM '{import_sql_path}' "
                "(FORMAT CSV, HEADER FALSE, NULL '\\N')",
                cancel_event,
            )
            self._execute_cancellable(
                connection,
                """
                INSERT INTO packet_rows
                SELECT
                    partition_id,
                    packet_ordinal,
                    timestamp,
                    caplen,
                    wirelen,
                    link_type,
                    decoded,
                    decode_reason,
                    src_ip,
                    src_ip_version,
                    CASE
                        WHEN src_ip_packed_hex IS NULL THEN NULL
                        ELSE from_hex(src_ip_packed_hex)
                    END,
                    dst_ip,
                    dst_ip_version,
                    CASE
                        WHEN dst_ip_packed_hex IS NULL THEN NULL
                        ELSE from_hex(dst_ip_packed_hex)
                    END,
                    src_port,
                    dst_port,
                    protocol,
                    ip_protocol,
                    tcp_flags,
                    frame_sha256
                FROM packet_import
                """,
                cancel_event,
            )
        finally:
            try:
                import_path.unlink()
            except FileNotFoundError:
                pass

    def _paths(self, case_id: str, analysis_id: str):
        case_token = sha256(str(case_id).encode("utf-8")).hexdigest()[:24]
        case_root = self.root / "packet-indexes" / case_token
        token = sha256(str(analysis_id).encode("utf-8")).hexdigest()[:24]
        final = case_root / token
        staging = case_root / f".{token}.{uuid.uuid4().hex}.tmp"
        work = case_root / f".{token}.{uuid.uuid4().hex}.duckdb.tmp"
        return case_root, final, staging, work

    def build(
        self,
        pcap_path: str | Path,
        *,
        case_id: str,
        analysis_id: str,
        pcap_sha256: str,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        try:
            import duckdb
        except ImportError as exc:
            raise PacketIndexError("DuckDB is required for packet indexing") from exc

        pcap_path = Path(pcap_path)
        expected_digest = str(pcap_sha256).lower()
        if _file_sha256(pcap_path) != expected_digest:
            raise PacketIndexError("PCAP digest does not match packet-index identity")
        case_root, final, staging, work = self._paths(case_id, analysis_id)
        case_root.mkdir(parents=True, exist_ok=True)
        manifest_path = final / "manifest.json"
        if final.exists():
            existing = PacketIndexReader.from_manifest(manifest_path).manifest
            if (
                existing.get("case_id") != str(case_id)
                or existing.get("analysis_id") != str(analysis_id)
                or existing.get("pcap_sha256") != expected_digest
            ):
                raise PacketIndexError("existing packet index identity does not match")
            return {
                **existing,
                "manifest_path": str(manifest_path),
                "manifest_sha256": _file_sha256(manifest_path),
            }

        staging.mkdir(parents=False)
        connection = None
        try:
            connection = duckdb.connect(str(work))
            connection.execute(
                """
                CREATE TABLE packet_rows (
                    partition_id UINTEGER NOT NULL,
                    packet_ordinal UBIGINT NOT NULL,
                    timestamp DOUBLE NOT NULL,
                    caplen UINTEGER NOT NULL,
                    wirelen UINTEGER NOT NULL,
                    link_type VARCHAR NOT NULL,
                    decoded BOOLEAN NOT NULL,
                    decode_reason VARCHAR NOT NULL,
                    src_ip VARCHAR,
                    src_ip_version UTINYINT,
                    src_ip_packed BLOB,
                    dst_ip VARCHAR,
                    dst_ip_version UTINYINT,
                    dst_ip_packed BLOB,
                    src_port USMALLINT NOT NULL,
                    dst_port USMALLINT NOT NULL,
                    protocol VARCHAR NOT NULL,
                    ip_protocol UTINYINT NOT NULL,
                    tcp_flags VARCHAR NOT NULL,
                    frame_sha256 VARCHAR NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TEMP TABLE packet_import (
                    partition_id UINTEGER NOT NULL,
                    packet_ordinal UBIGINT NOT NULL,
                    timestamp DOUBLE NOT NULL,
                    caplen UINTEGER NOT NULL,
                    wirelen UINTEGER NOT NULL,
                    link_type VARCHAR NOT NULL,
                    decoded BOOLEAN NOT NULL,
                    decode_reason VARCHAR NOT NULL,
                    src_ip VARCHAR,
                    src_ip_version UTINYINT,
                    src_ip_packed_hex VARCHAR,
                    dst_ip VARCHAR,
                    dst_ip_version UTINYINT,
                    dst_ip_packed_hex VARCHAR,
                    src_port USMALLINT NOT NULL,
                    dst_port USMALLINT NOT NULL,
                    protocol VARCHAR NOT NULL,
                    ip_protocol UTINYINT NOT NULL,
                    tcp_flags VARCHAR NOT NULL,
                    frame_sha256 VARCHAR NOT NULL
                )
                """
            )
            import_path = staging / "packet-rows.csv"
            expected_ordinal = 1
            first_timestamp = None
            last_timestamp = None
            batch: list[tuple[Any, ...]] = []
            for raw_record in self.record_source(pcap_path):
                self._check_cancelled(cancel_event)
                row = self._normalize_record(raw_record, expected_ordinal)
                batch.append(row)
                timestamp = row[2]
                first_timestamp = (
                    timestamp
                    if first_timestamp is None
                    else min(first_timestamp, timestamp)
                )
                last_timestamp = (
                    timestamp
                    if last_timestamp is None
                    else max(last_timestamp, timestamp)
                )
                expected_ordinal += 1
                if len(batch) == self.batch_rows:
                    self._import_batch(
                        connection,
                        import_path,
                        batch,
                        cancel_event,
                    )
                    batch.clear()
            if batch:
                self._import_batch(
                    connection,
                    import_path,
                    batch,
                    cancel_event,
                )
                batch.clear()
            self._check_cancelled(cancel_event)
            row_count = expected_ordinal - 1
            partition_counts = {
                int(partition): int(count)
                for partition, count in connection.execute(
                    "SELECT partition_id, COUNT(*) FROM packet_rows GROUP BY partition_id ORDER BY partition_id"
                ).fetchall()
            }
            parquet_root = staging / "parquet"
            parquet_root.mkdir()
            for partition_id in partition_counts:
                self._check_cancelled(cancel_event)
                partition_root = parquet_root / f"partition_id={partition_id}"
                partition_root.mkdir()
                output = str(partition_root / "data.parquet").replace("'", "''")
                self._execute_cancellable(
                    connection,
                    "COPY ("
                    "SELECT * EXCLUDE (partition_id) FROM packet_rows "
                    f"WHERE partition_id = {partition_id} ORDER BY packet_ordinal"
                    f") TO '{output}' "
                    "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)",
                    cancel_event,
                )
            connection.close()
            connection = None
            try:
                work.unlink()
            except FileNotFoundError:
                pass
            for suffix in (".wal",):
                try:
                    Path(str(work) + suffix).unlink()
                except FileNotFoundError:
                    pass

            partitions = []
            for parquet in sorted(parquet_root.rglob("*.parquet")):
                relative = parquet.relative_to(staging).as_posix()
                partition_name = next(
                    (
                        part.split("=", 1)[1]
                        for part in PurePosixPath(relative).parts
                        if part.startswith("partition_id=")
                    ),
                    None,
                )
                if partition_name is None:
                    raise PacketIndexError("Parquet partition path is invalid")
                partition_id = int(partition_name)
                partitions.append({
                    "partition_id": partition_id,
                    "path": relative,
                    "sha256": _file_sha256(parquet),
                    "row_count": partition_counts.get(partition_id, 0),
                    "byte_count": parquet.stat().st_size,
                })
            if sum(item["row_count"] for item in partitions) != row_count:
                raise PacketIndexError("Parquet partition row counts are incomplete")

            manifest = {
                "schema_version": SCHEMA_VERSION,
                "case_id": str(case_id),
                "analysis_id": str(analysis_id),
                "pcap_sha256": expected_digest,
                "row_count": row_count,
                "first_timestamp": first_timestamp,
                "last_timestamp": last_timestamp,
                "partition_rows": self.partition_rows,
                "partitions": partitions,
                "created_at": time.time(),
            }
            staging_manifest = staging / "manifest.json"
            staging_manifest.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            manifest_sha256 = _file_sha256(staging_manifest)
            if cancel_event and cancel_event.is_set():
                raise PacketIndexCancelled("packet indexing was cancelled")
            os.replace(staging, final)
            return {
                **manifest,
                "manifest_path": str(manifest_path),
                "manifest_sha256": manifest_sha256,
            }
        except PacketIndexError:
            raise
        except Exception as exc:
            raise PacketIndexError(f"packet index build failed ({type(exc).__name__})") from exc
        finally:
            if connection is not None:
                connection.close()
            try:
                work.unlink()
            except FileNotFoundError:
                pass
            for suffix in (".wal",):
                try:
                    Path(str(work) + suffix).unlink()
                except FileNotFoundError:
                    pass
            if staging.exists():
                shutil.rmtree(staging)

    def _normalize_record(self, raw_record: Any, expected_ordinal: int) -> tuple[Any, ...]:
        record = _record_mapping(raw_record)
        if {"raw", "payload", "frame"} & set(record):
            raise PacketIndexError("packet index records may not contain frame payloads")
        ordinal = record.get("packet_ordinal")
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal != expected_ordinal:
            raise PacketIndexError("packet ordinal sequence is invalid")
        timestamp = record.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp):
            raise PacketIndexError("packet timestamp is invalid")
        caplen = record.get("caplen")
        wirelen = record.get("wirelen")
        if (
            isinstance(caplen, bool)
            or not isinstance(caplen, int)
            or not 0 <= caplen <= MAX_FRAME_LENGTH
            or isinstance(wirelen, bool)
            or not isinstance(wirelen, int)
            or not caplen <= wirelen <= MAX_FRAME_LENGTH
        ):
            raise PacketIndexError("packet lengths are invalid")
        src_ip, src_version, src_packed = _address_fields(record.get("src_ip"), "source IP")
        dst_ip, dst_version, dst_packed = _address_fields(record.get("dst_ip"), "destination IP")
        src_port = record.get("src_port")
        dst_port = record.get("dst_port")
        src_port = 0 if src_port is None else src_port
        dst_port = 0 if dst_port is None else dst_port
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65_535
            for value in (src_port, dst_port)
        ):
            raise PacketIndexError("packet ports are invalid")
        protocol = _bounded_text(record.get("protocol"), "protocol", 32)
        ip_protocol = record.get(
            "ip_protocol",
            IP_PROTOCOL_NUMBERS.get(protocol.upper(), 0),
        )
        if isinstance(ip_protocol, bool) or not isinstance(ip_protocol, int) or not 0 <= ip_protocol <= 255:
            raise PacketIndexError("IP protocol is invalid")
        frame_digest = str(record.get("frame_sha256") or "").lower()
        if len(frame_digest) != 64 or any(value not in "0123456789abcdef" for value in frame_digest):
            raise PacketIndexError("frame SHA-256 is invalid")
        return (
            (ordinal - 1) // self.partition_rows,
            ordinal,
            float(timestamp),
            caplen,
            wirelen,
            _bounded_text(record.get("link_type"), "link type", 64),
            bool(record.get("decoded")),
            _bounded_text(record.get("decode_reason"), "decode reason", 128),
            src_ip,
            src_version,
            src_packed,
            dst_ip,
            dst_version,
            dst_packed,
            src_port,
            dst_port,
            protocol,
            ip_protocol,
            _tcp_flags(record.get("tcp_flags")),
            frame_digest,
        )


class PacketIndexReader:
    def __init__(self, manifest_path: Path, manifest: dict[str, Any], partitions: list[Path]):
        self.manifest_path = manifest_path
        self.manifest = manifest
        self.partitions = tuple(partitions)
        self._partitions_by_id = {
            int(item["partition_id"]): path
            for item, path in zip(manifest["partitions"], partitions)
        }
        self._partition_metadata_by_id = {
            int(item["partition_id"]): item
            for item in manifest["partitions"]
        }
        self._snapshot_directory = tempfile.TemporaryDirectory(
            prefix="watchtower-packet-index-"
        )
        self._snapshot_paths: dict[int, Path] = {}
        self._snapshot_lock = threading.Lock()

    def close(self) -> None:
        self._snapshot_directory.cleanup()

    def _snapshot_partition(self, partition_id: int) -> Path:
        with self._snapshot_lock:
            expected_hash = str(
                self._partition_metadata_by_id[partition_id]["sha256"]
            ).lower()
            existing = self._snapshot_paths.get(partition_id)
            if existing is not None:
                if not existing.is_file() or _file_sha256(existing) != expected_hash:
                    raise PacketIndexError("packet index snapshot hash mismatch")
                return existing

            source = self._partitions_by_id[partition_id]
            snapshot_root = Path(self._snapshot_directory.name)
            partition_root = snapshot_root / f"partition_id={partition_id}"
            partition_root.mkdir(exist_ok=True)
            destination = partition_root / "data.parquet"
            temporary = partition_root / ".data.tmp"
            digest = sha256()
            try:
                with source.open("rb") as input_file, temporary.open("xb") as output_file:
                    while chunk := input_file.read(1024 * 1024):
                        digest.update(chunk)
                        output_file.write(chunk)
                if digest.hexdigest() != expected_hash:
                    raise PacketIndexError("packet index partition hash mismatch")
                os.replace(temporary, destination)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
            self._snapshot_paths[partition_id] = destination
            return destination

    @classmethod
    def from_repository(cls, repository: Any, analysis_id: str) -> "PacketIndexReader":
        stored = repository.get_forensic_packet_index(str(analysis_id))
        if not stored or stored.get("state") != "complete":
            raise PacketIndexError("completed packet index is unavailable")
        manifest_path = Path(str(stored.get("manifest_path") or ""))
        expected_hash = str(stored.get("manifest_sha256") or "").lower()
        if (
            len(expected_hash) != 64
            or any(value not in "0123456789abcdef" for value in expected_hash)
            or not manifest_path.is_file()
            or _file_sha256(manifest_path) != expected_hash
        ):
            raise PacketIndexError("packet index manifest hash mismatch")
        reader = cls.from_manifest(manifest_path)
        manifest = reader.manifest
        if (
            manifest.get("analysis_id") != str(analysis_id)
            or manifest.get("case_id") != str(stored.get("case_id"))
            or manifest.get("pcap_sha256") != str(stored.get("pcap_sha256"))
            or manifest.get("schema_version") != int(stored.get("schema_version"))
            or manifest.get("row_count") != int(stored.get("row_count"))
            or len(manifest.get("partitions", ())) != int(stored.get("partition_count"))
        ):
            raise PacketIndexError("packet index repository scope mismatch")
        return reader

    @classmethod
    def from_manifest(cls, manifest_path: str | Path) -> "PacketIndexReader":
        manifest_path = Path(manifest_path)
        try:
            if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
                raise PacketIndexError("packet index manifest is oversized")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except PacketIndexError:
            raise
        except Exception as exc:
            raise PacketIndexError("packet index manifest is unreadable") from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
            raise PacketIndexError("packet index manifest schema is unsupported")
        for name in ("case_id", "analysis_id", "pcap_sha256", "partitions", "row_count"):
            if name not in manifest:
                raise PacketIndexError("packet index manifest is incomplete")
        if not str(manifest["case_id"]).startswith("case-") or not str(manifest["analysis_id"]).startswith("analysis-"):
            raise PacketIndexError("packet index manifest identity is invalid")
        digest = str(manifest["pcap_sha256"])
        if len(digest) != 64 or any(value not in "0123456789abcdef" for value in digest):
            raise PacketIndexError("packet index manifest digest is invalid")
        if not isinstance(manifest["partitions"], list) or len(manifest["partitions"]) > 100_000:
            raise PacketIndexError("packet index manifest partitions are invalid")

        base = manifest_path.parent.resolve()
        partitions = []
        total_rows = 0
        partition_ids = set()
        for item in manifest["partitions"]:
            if not isinstance(item, dict):
                raise PacketIndexError("packet index partition is invalid")
            raw_path = str(item.get("path") or "")
            relative = PurePosixPath(raw_path)
            if not raw_path or relative.is_absolute() or ".." in relative.parts:
                raise PacketIndexError("packet index partition path is unsafe")
            candidate = (base / Path(*relative.parts)).resolve()
            try:
                candidate.relative_to(base)
            except ValueError as exc:
                raise PacketIndexError("packet index partition path escapes its manifest") from exc
            partition_id = item.get("partition_id")
            if (
                isinstance(partition_id, bool)
                or not isinstance(partition_id, int)
                or partition_id < 0
                or partition_id in partition_ids
            ):
                raise PacketIndexError("packet index partition ID is invalid")
            partition_ids.add(partition_id)
            if not candidate.is_file():
                raise PacketIndexError("packet index partition is missing")
            expected_hash = str(item.get("sha256") or "").lower()
            if (
                len(expected_hash) != 64
                or any(value not in "0123456789abcdef" for value in expected_hash)
                or _file_sha256(candidate) != expected_hash
            ):
                raise PacketIndexError("packet index partition hash mismatch")
            total_rows += int(item.get("row_count") or 0)
            partitions.append(candidate)
        if total_rows != int(manifest["row_count"]):
            raise PacketIndexError("packet index manifest row count is invalid")
        return cls(manifest_path, manifest, partitions)

    def query(self, query: PacketQuery) -> dict[str, Any]:
        try:
            import duckdb
        except ImportError as exc:
            raise PacketIndexError("DuckDB is required for packet queries") from exc
        internal_query = query
        hidden_ordinal = "packet_ordinal" not in query.select
        if hidden_ordinal:
            internal_query = PacketQuery(
                select=tuple(query.select) + ("packet_ordinal",),
                filters=query.filters,
                partition_ids=query.partition_ids,
                order_by=query.order_by,
                descending=query.descending,
                cursor=query.cursor,
                limit=query.limit,
            )
        compiled = compile_packet_query(internal_query)
        if query.partition_ids:
            selected_partition_ids = tuple(
                partition_id
                for partition_id in sorted(set(query.partition_ids))
                if partition_id in self._partitions_by_id
            )
        else:
            if len(self.partitions) > MAX_PARTITIONS:
                raise PacketIndexError(
                    f"at most {MAX_PARTITIONS} partitions may be scanned"
                )
            selected_partition_ids = tuple(self._partitions_by_id)
        selected_partitions = tuple(
            self._snapshot_partition(partition_id)
            for partition_id in selected_partition_ids
        )
        connection = duckdb.connect()
        try:
            if selected_partitions:
                connection.from_parquet(
                    [str(path) for path in selected_partitions],
                    hive_partitioning=True,
                ).create_view("packet_index")
            else:
                connection.execute(
                    """
                    CREATE VIEW packet_index AS SELECT
                        0::UBIGINT AS packet_ordinal,
                        0.0::DOUBLE AS timestamp,
                        0::UINTEGER AS caplen,
                        0::UINTEGER AS wirelen,
                        ''::VARCHAR AS link_type,
                        FALSE::BOOLEAN AS decoded,
                        ''::VARCHAR AS decode_reason,
                        NULL::VARCHAR AS src_ip,
                        NULL::UTINYINT AS src_ip_version,
                        NULL::BLOB AS src_ip_packed,
                        NULL::VARCHAR AS dst_ip,
                        NULL::UTINYINT AS dst_ip_version,
                        NULL::BLOB AS dst_ip_packed,
                        0::USMALLINT AS src_port,
                        0::USMALLINT AS dst_port,
                        ''::VARCHAR AS protocol,
                        0::UTINYINT AS ip_protocol,
                        ''::VARCHAR AS tcp_flags,
                        ''::VARCHAR AS frame_sha256,
                        0::UINTEGER AS partition_id
                    WHERE FALSE
                    """
                )
            rows = connection.execute(compiled.sql, compiled.parameters).fetchall()
        except Exception as exc:
            raise PacketIndexError(f"packet index query failed ({type(exc).__name__})") from exc
        finally:
            connection.close()

        has_more = len(rows) > query.limit
        visible_rows = rows[:query.limit]
        internal_columns = compiled.columns
        items = []
        ordinals = []
        for row in visible_rows:
            values = dict(zip(internal_columns, row))
            ordinals.append(int(values["packet_ordinal"]))
            if hidden_ordinal:
                values.pop("packet_ordinal", None)
            items.append(values)
        return {
            "items": items,
            "next_cursor": ordinals[-1] if has_more and ordinals else None,
            "has_more": has_more,
            "limit": query.limit,
        }

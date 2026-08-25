"""Adapter for the crash-isolated WatchTower Rust capture sensor."""

from pathlib import Path
import json
import logging
import math
import os
import queue as queue_module
import shutil
import struct
import subprocess
import threading

from core.packet_engine.schemas import PacketEvent


logger = logging.getLogger("rust_capture")
MAGIC = b"WT01"
FRAME_EVENTS = 1
FRAME_HEALTH = 2
FRAME_PACKET_INDEX = 3
PACKET_INDEX_SCHEMA_VERSION = 1
MAX_FRAME_BYTES = 128 * 1024 * 1024
MAX_PACKET_INDEX_FRAME_BYTES = 4 * 1024 * 1024
MAX_PACKET_INDEX_BATCH_RECORDS = 4096


class TruncatedRustFrameError(EOFError):
    """Raised when a sensor frame ends after its boundary has started."""


def build_aggregate_analysis_plan(
    *,
    semantic_plugin_digest,
    analysis_mode,
    origin,
    selector_programs=(),
    preserve_tcp_streams=True,
):
    from core.packet_engine import rust_analysis

    try:
        semantic_digest = bytes.fromhex(str(semantic_plugin_digest))
    except ValueError as exc:
        raise ValueError("semantic plugin digest must be hexadecimal SHA-256") from exc
    if len(semantic_digest) != 32:
        raise ValueError("semantic plugin digest must be hexadecimal SHA-256")
    origin = dict(origin or {})
    wire_programs = [
        rust_analysis.AnalysisSelectorProgramWire(
            program_id=int(program.program_id),
            candidate_mode=str(program.candidate_mode),
            clauses=tuple(
                rust_analysis.AnalysisSelectorClauseWire(
                    opcode=str(clause.opcode),
                    values=tuple(clause.values),
                )
                for clause in program.clauses
            ),
        )
        for program in selector_programs
    ]
    if preserve_tcp_streams:
        next_program_id = max((program.program_id for program in wire_programs), default=-1) + 1
        if next_program_id >= 64:
            raise ValueError("aggregate selector plan has no slot for TCP stream preservation")
        wire_programs.append(rust_analysis.AnalysisSelectorProgramWire(
            program_id=next_program_id,
            candidate_mode="fast-v1",
            clauses=(
                rust_analysis.AnalysisSelectorClauseWire("ip-protocol-in", (6,)),
                rust_analysis.AnalysisSelectorClauseWire("payload-minimum-length", (1,)),
            ),
        ))
    return rust_analysis.AnalysisPlanWire(
        plan_sha256=b"\x00" * 32,
        semantic_plugin_sha256=semantic_digest,
        execution_mode="aggregate-v1",
        analysis_mode=str(analysis_mode),
        flags=(
            rust_analysis.ANALYSIS_FLAG_PACKET_INDEX
            | rust_analysis.ANALYSIS_FLAG_NATIVE_CONVERSATIONS
            | rust_analysis.ANALYSIS_FLAG_TERMINAL_METRICS
        ),
        target_batch_bytes=1024 * 1024,
        max_active_conversations=100_000,
        max_resume_conversations=100_000,
        max_directional_flows=220_000,
        max_endpoints=440_000,
        max_flow_samples=500,
        max_flow_sample_bytes=256 * 1024 * 1024,
        max_stream_segments=10_000,
        max_stream_bytes=16 * 1024 * 1024,
        source=str(origin.get("source") or "pcap"),
        session_id=str(origin.get("session_id") or "rust-analysis"),
        interface=str(origin.get("device_id") or "pcap"),
        sensor_node_id=str(origin.get("sensor_node_id") or "local"),
        selector_programs=tuple(wire_programs),
    )


def _analysis_digest(previous, payload):
    from hashlib import sha256

    return sha256(previous + payload).digest()


def sensor_binary() -> Path:
    """Resolve the Rust sensor for native and packaged deployments.

    Source installs keep the release binary under ``rust/.../target``.  The
    controller container installs it into ``PATH`` so the image never needs a
    compiler or an in-image source tree at runtime.
    """
    configured = os.getenv("WATCHTOWER_RUST_SENSOR")
    if configured:
        return Path(configured)
    name = "watchtower-sensor.exe" if os.name == "nt" else "watchtower-sensor"
    packaged = shutil.which(name)
    if packaged:
        return Path(packaged)
    return Path(__file__).resolve().parents[2] / "rust" / "watchtower-sensor" / "target" / "release" / name


def rust_sensor_available() -> bool:
    return sensor_binary().is_file()


def rust_sensor_version():
    binary = sensor_binary()
    if not binary.is_file():
        return None
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    prefix = "watchtower-sensor "
    value = result.stdout.strip()
    return value[len(prefix):].strip() if result.returncode == 0 and value.startswith(prefix) else None


def _sensor_environment():
    environment = os.environ.copy()
    if os.name == "nt":
        npcap_runtime = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap"
        environment["PATH"] = f"{npcap_runtime}{os.pathsep}{environment.get('PATH', '')}"
    return environment


def _resolve_device(interface):
    try:
        import scapy.all as scapy

        device = scapy.conf.ifaces.dev_from_name(str(interface))
        return str(getattr(device, "network_name", None) or device)
    except Exception:
        return str(interface)


def _read_exact(stream, size, *, allow_clean_eof=False):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            if not data and allow_clean_eof:
                raise EOFError("Rust sensor closed its event stream")
            raise TruncatedRustFrameError("Rust sensor emitted a truncated frame")
        data.extend(chunk)
    return bytes(data)


def read_frame(stream):
    header = _read_exact(stream, 10, allow_clean_eof=True)
    if header[:4] != MAGIC or header[4] != 1:
        raise ValueError("Invalid Rust sensor frame header")
    frame_type = header[5]
    payload_size = struct.unpack(">I", header[6:10])[0]
    frame_limit = (
        MAX_PACKET_INDEX_FRAME_BYTES
        if frame_type == FRAME_PACKET_INDEX
        else MAX_FRAME_BYTES
    )
    if payload_size > frame_limit:
        if frame_type == FRAME_PACKET_INDEX:
            raise ValueError(
                f"Rust sensor packet-index frame exceeds limit: {payload_size}"
            )
        raise ValueError(f"Rust sensor frame exceeds limit: {payload_size}")
    return frame_type, _read_exact(stream, payload_size)


def decode_event_batch(payload, origin):
    view = memoryview(payload)
    if len(view) < 2:
        raise ValueError("Truncated event batch")
    count = struct.unpack_from(">H", view, 0)[0]
    offset = 2
    events = []
    protocol_names = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPV6", 254: "ARP"}
    tcp_flags = ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U"))
    for _ in range(count):
        if offset + 9 > len(view):
            raise ValueError("Truncated event header")
        timestamp = struct.unpack_from(">d", view, offset)[0]
        offset += 8
        src_len = view[offset]
        offset += 1
        if offset + src_len + 1 > len(view):
            raise ValueError("Truncated source address")
        src = bytes(view[offset:offset + src_len]).decode("ascii")
        offset += src_len
        dst_len = view[offset]
        offset += 1
        if offset + dst_len + 15 > len(view):
            raise ValueError("Truncated destination address")
        dst = bytes(view[offset:offset + dst_len]).decode("ascii")
        offset += dst_len
        src_port, dst_port = struct.unpack_from(">HH", view, offset)
        offset += 4
        protocol_number = view[offset]
        offset += 1
        size, flags, raw_len = struct.unpack_from(">IHI", view, offset)
        offset += 10
        if offset + raw_len > len(view):
            raise ValueError("Truncated raw packet")
        raw = bytes(view[offset:offset + raw_len])
        offset += raw_len
        events.append(PacketEvent(
            timestamp=timestamp, src_ip=src, dst_ip=dst,
            src_port=src_port, dst_port=dst_port,
            protocol=protocol_names.get(protocol_number, "OTHER"), size=size,
            flags="".join(name for mask, name in tcp_flags if flags & mask), raw=raw,
            interface=origin["device_id"], session_id=origin["session_id"],
            source_type=origin.get("source_type", "network"), backend="rust",
            link_type=origin.get("link_type", "ethernet"),
            sensor_node_id=origin.get("sensor_node_id"),
            source=origin.get("source"),
        ))
    if offset != len(view):
        raise ValueError("Event batch contains trailing bytes")
    return events


def decode_packet_index_batch(payload):
    view = memoryview(payload)
    offset = 0

    def require(size):
        if size < 0 or offset + size > len(view):
            raise ValueError("Truncated packet-index batch")

    def unpack(fmt):
        nonlocal offset
        size = struct.calcsize(fmt)
        require(size)
        values = struct.unpack_from(fmt, view, offset)
        offset += size
        return values

    def read_byte():
        return unpack(">B")[0]

    def read_short_ascii(max_length):
        nonlocal offset
        length = read_byte()
        if length > max_length:
            raise ValueError("Packet-index text field exceeds limit")
        require(length)
        try:
            value = bytes(view[offset:offset + length]).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Packet-index text field is not ASCII") from exc
        offset += length
        return value

    schema_version, count = unpack(">BH")
    if schema_version != PACKET_INDEX_SCHEMA_VERSION:
        raise ValueError(f"Unsupported packet-index schema version: {schema_version}")
    if count > MAX_PACKET_INDEX_BATCH_RECORDS:
        raise ValueError(f"Packet-index batch exceeds record limit: {count}")
    rows = []
    protocol_names = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPV6",
        254: "ARP",
    }

    for _ in range(count):
        packet_ordinal, timestamp, caplen, wirelen = unpack(">QdII")
        link_type = read_short_ascii(32)
        decoded_marker = read_byte()
        if decoded_marker not in (0, 1):
            raise ValueError("Invalid packet-index decode marker")
        decoded = bool(decoded_marker)
        decode_reason = read_short_ascii(64)
        src_ip = read_short_ascii(45)
        dst_ip = read_short_ascii(45)
        presence = read_byte()
        if presence & ~0x0F:
            raise ValueError("Invalid packet-index presence mask")
        src_port, dst_port, protocol_number, tcp_flags = unpack(">HHBH")
        require(32)
        frame_sha256 = bytes(view[offset:offset + 32]).hex()
        offset += 32
        if packet_ordinal == 0:
            raise ValueError("Packet ordinal must be nonzero")
        if not math.isfinite(timestamp):
            raise ValueError("Packet timestamp must be finite")
        if caplen > wirelen:
            raise ValueError("Captured length exceeds wire length")
        if not link_type:
            raise ValueError("Packet link type is required")
        if decoded:
            if decode_reason:
                raise ValueError("Decoded packet cannot have a decode reason")
            if not src_ip or not dst_ip:
                raise ValueError("Decoded packet must have addresses")
        elif not decode_reason or src_ip or dst_ip or presence:
            raise ValueError("Undecoded packet fields are not canonical")
        if not presence & 0x01 and src_port:
            raise ValueError("Absent source port must be zero")
        if not presence & 0x02 and dst_port:
            raise ValueError("Absent destination port must be zero")
        if not presence & 0x04 and protocol_number:
            raise ValueError("Absent protocol must be zero")
        if not presence & 0x08 and tcp_flags:
            raise ValueError("Absent TCP flags must be zero")
        has_ports = presence & 0x03
        if has_ports not in (0, 0x03):
            raise ValueError("Packet ports must be present together")
        if has_ports and (not presence & 0x04 or protocol_number not in (6, 17)):
            raise ValueError("Packet ports require TCP or UDP")
        if presence & 0x08 and (not presence & 0x04 or protocol_number != 6):
            raise ValueError("TCP flags require TCP")
        rows.append({
            "packet_ordinal": packet_ordinal,
            "timestamp": timestamp,
            "caplen": caplen,
            "wirelen": wirelen,
            "link_type": link_type,
            "decoded": decoded,
            "decode_reason": decode_reason or None,
            "src_ip": src_ip or None,
            "dst_ip": dst_ip or None,
            "src_port": src_port if presence & 0x01 else None,
            "dst_port": dst_port if presence & 0x02 else None,
            "protocol": (
                protocol_names.get(protocol_number, f"IP-{protocol_number}")
                if presence & 0x04 else None
            ),
            "tcp_flags": tcp_flags if presence & 0x08 else None,
            "frame_sha256": frame_sha256,
        })
    if offset != len(view):
        raise ValueError("Packet-index batch contains trailing bytes")
    return rows


def validate_packet_index_batch(payload):
    """Validate an unused aggregate index frame without materializing row dictionaries."""
    view = memoryview(payload)
    if len(view) < 3:
        raise ValueError("Truncated packet-index batch")
    schema_version, count = struct.unpack_from(">BH", view, 0)
    if schema_version != PACKET_INDEX_SCHEMA_VERSION:
        raise ValueError(f"Unsupported packet-index schema version: {schema_version}")
    if count > MAX_PACKET_INDEX_BATCH_RECORDS:
        raise ValueError(f"Packet-index batch exceeds record limit: {count}")
    offset = 3

    def require(size):
        if size < 0 or offset + size > len(view):
            raise ValueError("Truncated packet-index batch")

    def skip_text(maximum):
        nonlocal offset
        require(1)
        length = int(view[offset])
        offset += 1
        if length > maximum:
            raise ValueError("Packet-index text field exceeds limit")
        require(length)
        offset += length
        return length

    for _ in range(count):
        require(24)
        packet_ordinal, timestamp, caplen, wirelen = struct.unpack_from(">QdII", view, offset)
        offset += 24
        link_length = skip_text(32)
        require(1)
        decoded_marker = int(view[offset])
        offset += 1
        reason_length = skip_text(64)
        src_length = skip_text(45)
        dst_length = skip_text(45)
        require(8)
        presence, src_port, dst_port, protocol_number, tcp_flags = struct.unpack_from(">BHHBH", view, offset)
        offset += 8
        require(32)
        offset += 32
        if packet_ordinal == 0 or not math.isfinite(timestamp) or caplen > wirelen:
            raise ValueError("Invalid packet-index scalar field")
        if not link_length or decoded_marker not in (0, 1) or presence & ~0x0F:
            raise ValueError("Invalid packet-index marker")
        if decoded_marker:
            if reason_length or not src_length or not dst_length:
                raise ValueError("Decoded packet-index row is not canonical")
        elif not reason_length or src_length or dst_length or presence:
            raise ValueError("Undecoded packet-index row is not canonical")
        if (not presence & 0x01 and src_port) or (not presence & 0x02 and dst_port):
            raise ValueError("Absent packet-index port must be zero")
        if (not presence & 0x04 and protocol_number) or (not presence & 0x08 and tcp_flags):
            raise ValueError("Absent packet-index protocol field must be zero")
        has_ports = presence & 0x03
        if has_ports not in (0, 0x03):
            raise ValueError("Packet-index ports must be present together")
        if has_ports and (not presence & 0x04 or protocol_number not in (6, 17)):
            raise ValueError("Packet-index ports require TCP or UDP")
        if presence & 0x08 and (not presence & 0x04 or protocol_number != 6):
            raise ValueError("Packet-index TCP flags require TCP")
    if offset != len(view):
        raise ValueError("Packet-index batch contains trailing bytes")
    return count


def _stderr_relay(stream):
    for line in iter(stream.readline, b""):
        logger.info("[rust] %s", line.decode("utf-8", errors="replace").rstrip())


def start_rust_capture(
    interface,
    packet_queue,
    silent=False,
    stop_event=None,
    origin=None,
    metrics=None,
    readiness_queue=None,
):
    binary = sensor_binary()
    if not binary.is_file():
        raise FileNotFoundError(f"Rust sensor binary not found: {binary}")
    origin = dict(origin or {})

    def notify_readiness(status, message=None):
        if readiness_queue is None:
            return
        payload = {"status": status}
        if message:
            payload["message"] = str(message)
        try:
            readiness_queue.put(payload, timeout=0.2)
        except queue_module.Full:
            pass

    try:
        process = subprocess.Popen(
            [str(binary), "capture", "--interface", _resolve_device(interface), "--batch", "256"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            env=_sensor_environment(),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except OSError as exc:
        notify_readiness("error", exc)
        raise RuntimeError(f"Rust capture failed to start: {exc}") from exc

    frames = queue_module.Queue(maxsize=64)

    def reader():
        try:
            while True:
                frames.put(read_frame(process.stdout))
        except EOFError:
            frames.put(EOFError("Rust sensor closed its capture stream"))
        except Exception as exc:
            frames.put(exc)

    threading.Thread(target=reader, daemon=True).start()
    ready = False
    try:
        try:
            first_item = frames.get(timeout=5.0)
        except queue_module.Empty as exc:
            message = "Rust capture sensor did not become ready within 5 seconds"
            notify_readiness("error", message)
            raise RuntimeError(message) from exc
        if isinstance(first_item, Exception):
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
            message = stderr or str(first_item)
            notify_readiness("error", message)
            raise RuntimeError(message)
        frame_type, payload = first_item
        if frame_type != FRAME_HEALTH:
            message = "Rust capture sensor emitted packet data before readiness"
            notify_readiness("error", message)
            raise RuntimeError(message)
        health = json.loads(payload.decode("utf-8"))
        if health.get("status") == "error":
            message = str(health.get("message") or "Rust capture sensor failed to open")
            notify_readiness("error", message)
            raise RuntimeError(message)
        ready = True
        notify_readiness("ready")
        threading.Thread(target=_stderr_relay, args=(process.stderr,), daemon=True).start()

        while process.poll() is None and not (stop_event and stop_event.is_set()):
            try:
                item = frames.get(timeout=0.2)
            except queue_module.Empty:
                continue
            if isinstance(item, Exception):
                if isinstance(item, EOFError):
                    break
                raise item
            frame_type, payload = item
            if frame_type == FRAME_EVENTS:
                events = decode_event_batch(payload, origin)
                if metrics is not None:
                    metrics["received_packets"].value += len(events)
                for event in events:
                    try:
                        packet_queue.put(event, timeout=0.05)
                        if metrics is not None:
                            metrics["emitted_packets"].value += 1
                            metrics["last_packet_at"].value = event.timestamp
                    except queue_module.Full:
                        if metrics is not None:
                            metrics["dropped_packets"].value += 1
                            metrics["queue_full_events"].value += 1
            elif frame_type == FRAME_HEALTH:
                json.loads(payload.decode("utf-8"))
    except Exception as exc:
        if not ready:
            notify_readiness("error", exc)
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def replay_events(path, origin=None):
    binary = sensor_binary()
    if not binary.is_file():
        raise FileNotFoundError(
            f"Rust sensor binary not found: {binary}. Run scripts/build_rust_sensor.ps1"
        )
    origin = dict(origin or {
        "session_id": "rust-replay", "source_type": "network",
        "device_id": "pcap", "link_type": "ethernet",
    })
    process = subprocess.Popen(
        [str(binary), "replay", "--pcap", str(path), "--batch", "256"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_sensor_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    normal_eof = False
    try:
        while True:
            frame_type, payload = read_frame(process.stdout)
            if frame_type == FRAME_EVENTS:
                yield from decode_event_batch(payload, origin)
            elif frame_type == FRAME_HEALTH:
                health = json.loads(payload.decode("utf-8"))
                if health.get("link_type"):
                    origin["link_type"] = str(health["link_type"])
    except EOFError:
        normal_eof = True
    finally:
        # Generators are often stopped early by a caller performing a bounded
        # replay or cancellation.  The sensor blocks once its stdout pipe is
        # full, so waiting before terminating would deadlock that caller.
        if normal_eof:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        elif process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stderr = process.stderr.read().decode("utf-8", errors="replace")
        code = process.returncode
        process.stdout.close()
        process.stderr.close()
        if normal_eof and code:
            raise RuntimeError(stderr or f"Rust replay failed with exit code {code}")


def aggregate_replay_events(
    path,
    *,
    semantic_plugin_digest,
    analysis_mode="memory",
    origin=None,
    result=None,
    selector_programs=(),
    cancel_event=None,
):
    """Replay through the certified Rust aggregate protocol.

    The yielded packet events preserve the existing Python parser/detector
    surface. Aggregate terminal records are validated and summarized in
    ``result`` while the engine transition remains compatibility-safe.
    """
    from core.packet_engine import rust_analysis

    binary = sensor_binary()
    if not binary.is_file():
        raise FileNotFoundError(
            f"Rust sensor binary not found: {binary}. Run scripts/build_rust_sensor.ps1"
        )
    origin = dict(origin or {
        "session_id": "rust-analysis",
        "source_type": "network",
        "device_id": "pcap",
        "sensor_node_id": "local",
        "source": "pcap",
    })
    plan = build_aggregate_analysis_plan(
        semantic_plugin_digest=semantic_plugin_digest,
        analysis_mode=analysis_mode,
        origin=origin,
        selector_programs=selector_programs,
    )
    process = subprocess.Popen(
        [str(binary), "analyze", "--pcap", str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_sensor_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    session = rust_analysis.RustAnalysisChild(process, plan)
    decoder = rust_analysis.AnalysisDataDecoder()
    counts = {
        "packet_index_rows": 0,
        "decoded_work_items": 0,
        "raw_candidate_items": 0,
        "raw_candidate_bytes": 0,
        "terminal_directional_flows": 0,
        "terminal_conversations": 0,
    }
    digests = {
        "packet_index": b"\x00" * 32,
        "work": b"\x00" * 32,
        "flow": b"\x00" * 32,
        "conversation": b"\x00" * 32,
        "stream": b"\x00" * 32,
    }
    last_sequence = 0
    terminal_flows = []
    terminal_conversations = []
    normal_eof = False
    cancelled = False

    def cancellation_requested():
        if cancel_event is None:
            return False
        if callable(cancel_event):
            return bool(cancel_event())
        return bool(hasattr(cancel_event, "is_set") and cancel_event.is_set())

    try:
        hello = session.start()
        while True:
            try:
                frame_kind, payload = rust_analysis.read_transport_frame(process.stdout)
            except EOFError:
                normal_eof = True
                break
            session.validator.accept(frame_kind, payload)
            if frame_kind == rust_analysis.FRAME_ANALYSIS_PACKET_INDEX:
                row_count = validate_packet_index_batch(payload)
                counts["packet_index_rows"] += row_count
                digests["packet_index"] = _analysis_digest(
                    digests["packet_index"], payload
                )
                if callable(cancel_event):
                    for _ in range(row_count):
                        if cancellation_requested():
                            cancelled = True
                            break
                else:
                    cancelled = cancellation_requested()
                if cancelled:
                    if result is not None:
                        result.clear()
                        result.update({
                            "terminal_status": "cancelled",
                            "error_code": "operator_cancelled",
                            "sensor_version": hello.sensor_version,
                            "link_type": hello.normalized_link_type,
                            **counts,
                        })
                    session.close()
                    return
            elif frame_kind == rust_analysis.FRAME_ANALYSIS_WORK:
                batch = decoder.decode_work(payload)
                if batch.sequence <= last_sequence:
                    raise rust_analysis.AnalysisProtocolError(
                        "analysis data sequence is not monotonic"
                    )
                last_sequence = batch.sequence
                digests["work"] = _analysis_digest(digests["work"], payload)
                for item in batch.items:
                    counts["decoded_work_items"] += 1
                    if item.raw_frame:
                        counts["raw_candidate_items"] += 1
                        counts["raw_candidate_bytes"] += len(item.raw_frame)
                    yield rust_analysis.work_item_to_packet_event(
                        item,
                        origin,
                        link_type=hello.normalized_link_type,
                    )
            elif frame_kind == rust_analysis.FRAME_ANALYSIS_FLOW:
                batch = decoder.decode_flows(payload)
                if batch.sequence <= last_sequence:
                    raise rust_analysis.AnalysisProtocolError(
                        "analysis data sequence is not monotonic"
                    )
                last_sequence = batch.sequence
                counts["terminal_directional_flows"] += len(batch.records)
                terminal_flows.extend(batch.records)
                digests["flow"] = _analysis_digest(digests["flow"], payload)
            elif frame_kind == rust_analysis.FRAME_ANALYSIS_CONVERSATION:
                batch = decoder.decode_conversations(payload)
                if batch.sequence <= last_sequence:
                    raise rust_analysis.AnalysisProtocolError(
                        "analysis data sequence is not monotonic"
                    )
                last_sequence = batch.sequence
                counts["terminal_conversations"] += len(batch.records)
                terminal_conversations.extend(batch.records)
                digests["conversation"] = _analysis_digest(
                    digests["conversation"], payload
                )
            elif frame_kind == rust_analysis.FRAME_ANALYSIS_STREAM:
                digests["stream"] = _analysis_digest(digests["stream"], payload)
            elif frame_kind == rust_analysis.FRAME_ANALYSIS_ERROR:
                raise rust_analysis.AnalysisProtocolError(
                    payload.decode("utf-8", errors="replace")
                    or "Rust aggregate analysis failed"
                )
        process.wait(timeout=5)
        end = session.validator.finish(process.returncode)
        expected_counts = {
            "packet_index_rows": end.packet_index_rows,
            "decoded_work_items": end.decoded_work_items,
            "raw_candidate_items": end.raw_candidate_items,
            "raw_candidate_bytes": end.raw_candidate_bytes,
            "terminal_directional_flows": end.terminal_directional_flows,
            "terminal_conversations": end.terminal_conversations,
        }
        if counts != expected_counts:
            raise rust_analysis.AnalysisProtocolError(
                "analysis terminal counters do not match received frames"
            )
        expected_digests = {
            "packet_index": end.packet_index_digest,
            "work": end.work_digest,
            "flow": end.flow_digest,
            "conversation": end.conversation_digest,
            "stream": end.stream_digest,
        }
        if digests != expected_digests:
            raise rust_analysis.AnalysisProtocolError(
                "analysis terminal digests do not match received frames"
            )
        if result is not None:
            result.clear()
            result.update({
                "terminal_status": end.terminal_status,
                "error_code": end.error_code or None,
                "sensor_version": hello.sensor_version,
                "link_type": hello.normalized_link_type,
                **counts,
                "read_decode_ns": end.read_decode_ns,
                "candidate_match_ns": end.candidate_match_ns,
                "aggregate_ns": end.aggregate_ns,
                "blocked_write_ns": end.blocked_write_ns,
                "endpoint_high_water": end.endpoint_high_water,
                "flow_high_water": end.flow_high_water,
                "conversation_high_water": end.conversation_high_water,
                "resume_high_water": end.resume_high_water,
                "sample_bytes_high_water": end.sample_bytes_high_water,
                "_terminal_flows": tuple(terminal_flows),
                "_terminal_conversations": tuple(terminal_conversations),
            })
        session.closed = True
    finally:
        if not normal_eof or process.poll() is None:
            session.close()
        stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
        if normal_eof and process.returncode:
            raise RuntimeError(
                stderr or f"Rust aggregate analysis failed with exit code {process.returncode}"
            )
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except Exception:
                pass


def iter_packet_index(path, *, batch=256):
    if type(batch) is not int or not 1 <= batch <= MAX_PACKET_INDEX_BATCH_RECORDS:
        raise ValueError(
            f"packet-index batch must be an integer from 1 to "
            f"{MAX_PACKET_INDEX_BATCH_RECORDS}"
        )
    binary = sensor_binary()
    if not binary.is_file():
        raise FileNotFoundError(
            f"Rust sensor binary not found: {binary}. Run scripts/build_rust_sensor.ps1"
        )
    process = subprocess.Popen(
        [
            str(binary),
            "index",
            "--pcap",
            str(path),
            "--batch",
            str(batch),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=_sensor_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    normal_eof = False
    try:
        while True:
            frame_type, payload = read_frame(process.stdout)
            if frame_type != FRAME_PACKET_INDEX:
                raise ValueError(
                    f"Rust packet index emitted unexpected frame type: {frame_type}"
                )
            yield from decode_packet_index_batch(payload)
    except TruncatedRustFrameError:
        raise
    except EOFError:
        normal_eof = True
    finally:
        if normal_eof:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        elif process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        stderr = process.stderr.read().decode("utf-8", errors="replace").strip()
        code = process.returncode
        process.stdout.close()
        process.stderr.close()
        if normal_eof and code:
            raise RuntimeError(
                stderr or f"Rust packet index failed with exit code {code}"
            )

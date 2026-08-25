"""Strict control and handshake codec for Rust aggregate offline analysis.

This module owns only the process boundary.  It intentionally does not decide
which packets are candidates or how forensic evidence is interpreted.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import math
import subprocess
import struct
from typing import Iterable


ANALYSIS_SCHEMA_VERSION = 1
FRAME_ANALYSIS_HELLO = 0x04
FRAME_ANALYSIS_WORK = 0x05
FRAME_ANALYSIS_FLOW = 0x06
FRAME_ANALYSIS_CONVERSATION = 0x07
FRAME_ANALYSIS_STREAM = 0x08
FRAME_ANALYSIS_END = 0x09
FRAME_ANALYSIS_ERROR = 0x0A
FRAME_ANALYSIS_PACKET_INDEX = 0x0B
FRAME_ANALYSIS_PLAN = 0x10
FRAME_ANALYSIS_CANCEL = 0x11

ANALYSIS_FLAG_PACKET_INDEX = 0x0001
ANALYSIS_FLAG_NATIVE_CONVERSATIONS = 0x0002
ANALYSIS_FLAG_STREAM_SEGMENTS = 0x0004
ANALYSIS_FLAG_TERMINAL_METRICS = 0x0008
_KNOWN_FLAGS = (
    ANALYSIS_FLAG_PACKET_INDEX
    | ANALYSIS_FLAG_NATIVE_CONVERSATIONS
    | ANALYSIS_FLAG_STREAM_SEGMENTS
    | ANALYSIS_FLAG_TERMINAL_METRICS
)

ANALYSIS_CAPABILITY_V1 = (
    (1 << FRAME_ANALYSIS_HELLO)
    | (1 << FRAME_ANALYSIS_WORK)
    | (1 << FRAME_ANALYSIS_FLOW)
    | (1 << FRAME_ANALYSIS_CONVERSATION)
    | (1 << FRAME_ANALYSIS_STREAM)
    | (1 << FRAME_ANALYSIS_END)
    | (1 << FRAME_ANALYSIS_ERROR)
)

_TRANSPORT_MAGIC = b"WT01"
_TRANSPORT_VERSION = 1
_MAX_CONTROL_FRAME_BYTES = 1024 * 1024
_MAX_ANALYSIS_FRAME_BYTES = 128 * 1024 * 1024

_EXECUTION_MODES = {"aggregate-v1": 1, "compatibility-v1": 2}
_ANALYSIS_MODES = {"memory": 1, "streaming": 2}
_MAX_TARGET_BATCH_BYTES = 8 * 1024 * 1024
_MAX_SELECTOR_PROGRAMS = 64
_TERMINAL_STATUSES = {"complete": 1, "partial": 2, "cancelled": 3}


class AnalysisProtocolError(ValueError):
    """The aggregate child crossed a strict protocol boundary incorrectly."""


def encode_transport_frame(frame_kind: int, payload: bytes) -> bytes:
    """Encode one bounded WT01 transport frame for the aggregate child."""
    if type(frame_kind) is not int or not 0 <= frame_kind <= 0xFF:
        raise AnalysisProtocolError("analysis frame kind must be a byte")
    if not isinstance(payload, bytes):
        raise AnalysisProtocolError("analysis frame payload must be bytes")
    limit = _MAX_CONTROL_FRAME_BYTES if frame_kind in (FRAME_ANALYSIS_PLAN, FRAME_ANALYSIS_CANCEL) else _MAX_ANALYSIS_FRAME_BYTES
    if len(payload) > limit:
        raise AnalysisProtocolError(f"analysis frame exceeds limit: {len(payload)}")
    return _TRANSPORT_MAGIC + bytes([_TRANSPORT_VERSION, frame_kind]) + struct.pack(">I", len(payload)) + payload


def _read_transport_exact(stream, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise EOFError("Rust analysis child closed a truncated frame")
        result.extend(chunk)
    return bytes(result)


def read_transport_frame(stream) -> tuple[int, bytes]:
    """Read exactly one bounded frame; callers decide semantic ordering."""
    header = _read_transport_exact(stream, 10)
    if header[:4] != _TRANSPORT_MAGIC or header[4] != _TRANSPORT_VERSION:
        raise AnalysisProtocolError("invalid Rust analysis frame header")
    kind = header[5]
    size = struct.unpack(">I", header[6:])[0]
    limit = _MAX_CONTROL_FRAME_BYTES if kind in (FRAME_ANALYSIS_PLAN, FRAME_ANALYSIS_CANCEL) else _MAX_ANALYSIS_FRAME_BYTES
    if size > limit:
        raise AnalysisProtocolError(f"analysis frame exceeds limit: {size}")
    return kind, _read_transport_exact(stream, size)


@dataclass(frozen=True)
class AnalysisSelectorClauseWire:
    opcode: str
    values: tuple[object, ...] = ()


@dataclass(frozen=True)
class AnalysisSelectorProgramWire:
    program_id: int
    candidate_mode: str
    clauses: tuple[AnalysisSelectorClauseWire, ...]


@dataclass(frozen=True)
class AnalysisPlanWire:
    plan_sha256: bytes
    semantic_plugin_sha256: bytes
    execution_mode: str
    analysis_mode: str
    flags: int
    target_batch_bytes: int
    max_active_conversations: int
    max_resume_conversations: int
    max_directional_flows: int
    max_endpoints: int
    max_flow_samples: int
    max_flow_sample_bytes: int
    max_stream_segments: int
    max_stream_bytes: int
    source: str
    session_id: str
    interface: str
    sensor_node_id: str
    selector_programs: tuple[AnalysisSelectorProgramWire, ...] = ()


@dataclass(frozen=True)
class AnalysisHelloWire:
    plan_sha256: bytes
    sensor_version: str
    pcap_datalink: int
    normalized_link_type: str
    capability_bits: int


@dataclass(frozen=True)
class AnalysisEndWire:
    plan_sha256: bytes
    terminal_status: str
    error_code: str
    packet_index_rows: int
    decoded_work_items: int
    raw_candidate_items: int
    raw_candidate_bytes: int
    flow_snapshot_records: int
    terminal_directional_flows: int
    conversation_snapshot_records: int
    terminal_conversations: int
    stream_segment_records: int
    stream_segment_bytes: int
    stream_truncated_segments: int
    stream_truncated_bytes: int
    first_decoded_timestamp: float | None
    last_decoded_timestamp: float | None
    packet_index_digest: bytes
    work_digest: bytes
    flow_digest: bytes
    conversation_digest: bytes
    stream_digest: bytes
    read_decode_ns: int
    candidate_match_ns: int
    aggregate_ns: int
    blocked_write_ns: int
    endpoint_high_water: int
    flow_high_water: int
    conversation_high_water: int
    resume_high_water: int
    sample_bytes_high_water: int


@dataclass(frozen=True)
class AnalysisEndpointWire:
    endpoint_id: int
    address: str


@dataclass(frozen=True)
class AnalysisFlowDefinitionWire:
    flow_id: int
    source: AnalysisEndpointWire
    destination: AnalysisEndpointWire
    source_port: int
    destination_port: int
    protocol: int


@dataclass(frozen=True)
class AnalysisConversationDefinitionWire:
    conversation_id: int
    endpoint_a: AnalysisEndpointWire
    endpoint_a_port: int
    endpoint_b: AnalysisEndpointWire
    endpoint_b_port: int
    initiator: AnalysisEndpointWire
    initiator_port: int
    responder: AnalysisEndpointWire
    responder_port: int
    protocol: int
    first_seen: float


@dataclass(frozen=True)
class AnalysisFlowSnapshotWire:
    start_time: float
    packet_count: int
    byte_count: int
    syn_count: int
    syn_ack_count: int
    rst_count: int


@dataclass(frozen=True)
class AnalysisConversationSnapshotWire:
    generation: int
    to_responder_packets: int
    to_responder_bytes: int
    to_initiator_packets: int
    to_initiator_bytes: int
    syn_count: int
    syn_ack_count: int
    rst_count: int
    established: bool


@dataclass(frozen=True)
class AnalysisWorkItemWire:
    packet_ordinal: int
    timestamp: float
    size: int
    flow: AnalysisFlowDefinitionWire
    conversation: AnalysisConversationDefinitionWire
    hop_limit: int
    tcp_flags: int
    direction: str
    candidate_mode: str
    matched_programs: int
    flow_snapshot: AnalysisFlowSnapshotWire
    conversation_snapshot: AnalysisConversationSnapshotWire
    syn_delta: int
    syn_ack_delta: int
    rst_delta: int
    raw_frame: bytes


@dataclass(frozen=True)
class AnalysisWorkBatchWire:
    sequence: int
    items: tuple[AnalysisWorkItemWire, ...]


@dataclass(frozen=True)
class AnalysisTerminalFlowWire:
    definition: AnalysisFlowDefinitionWire
    generation: int
    start_time: float
    last_seen: float
    packet_count: int
    byte_count: int
    syn_count: int
    syn_ack_count: int
    rst_count: int
    samples: tuple[tuple[int, float], ...]


@dataclass(frozen=True)
class AnalysisFlowBatchWire:
    sequence: int
    records: tuple[AnalysisTerminalFlowWire, ...]


@dataclass(frozen=True)
class AnalysisTerminalConversationWire:
    definition: AnalysisConversationDefinitionWire
    last_seen: float
    generation: int
    to_responder_packets: int
    to_responder_bytes: int
    to_initiator_packets: int
    to_initiator_bytes: int
    syn_count: int
    syn_ack_count: int
    rst_count: int
    established: bool


@dataclass(frozen=True)
class AnalysisConversationBatchWire:
    sequence: int
    records: tuple[AnalysisTerminalConversationWire, ...]


class _Reader:
    def __init__(self, payload: bytes):
        self.payload = memoryview(payload)
        self.offset = 0

    def take(self, size: int, label: str) -> bytes:
        if size < 0 or self.offset + size > len(self.payload):
            raise AnalysisProtocolError(f"truncated {label}")
        value = bytes(self.payload[self.offset:self.offset + size])
        self.offset += size
        return value

    def unpack(self, fmt: str, label: str):
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(size, label))[0]

    def ascii8(self, maximum: int, label: str) -> str:
        length = self.unpack(">B", f"{label} length")
        if length > maximum:
            raise AnalysisProtocolError(f"{label} exceeds {maximum} bytes")
        try:
            return self.take(length, label).decode("ascii")
        except UnicodeDecodeError as exc:
            raise AnalysisProtocolError(f"{label} is not ASCII") from exc

    def finish(self) -> None:
        if self.offset != len(self.payload):
            raise AnalysisProtocolError("trailing bytes in analysis payload")


class AnalysisDataDecoder:
    """Stateful decoder for evidence-bearing aggregate data frames.

    Definitions are immutable for the lifetime of one child process.  A frame
    referencing an unknown or redefined ID is rejected before callers can use
    any of its observations.
    """

    _CANDIDATE_MODES = {0: "none", 1: "fast-v1", 2: "deep-scapy-v1"}
    _DIRECTIONS = {1: "to_responder", 2: "to_initiator"}

    def __init__(self):
        self.endpoints: dict[int, AnalysisEndpointWire] = {}
        self.flows: dict[int, AnalysisFlowDefinitionWire] = {}
        self.conversations: dict[int, AnalysisConversationDefinitionWire] = {}

    @staticmethod
    def _nonzero(value: int, label: str) -> int:
        if value == 0:
            raise AnalysisProtocolError(f"{label} must be nonzero")
        return value

    @staticmethod
    def _finite(value: float, label: str) -> float:
        if not math.isfinite(value):
            raise AnalysisProtocolError(f"{label} must be finite")
        return value

    @staticmethod
    def _boolean(value: int, label: str) -> bool:
        if value not in (0, 1):
            raise AnalysisProtocolError(f"{label} must be 0 or 1")
        return bool(value)

    def _endpoint(self, endpoint_id: int, label: str) -> AnalysisEndpointWire:
        try:
            return self.endpoints[endpoint_id]
        except KeyError as exc:
            raise AnalysisProtocolError(f"unknown endpoint ID for {label}: {endpoint_id}") from exc

    def decode_work(self, payload: bytes) -> AnalysisWorkBatchWire:
        reader = _Reader(payload)
        schema = reader.unpack(">B", "analysis work schema")
        if schema != ANALYSIS_SCHEMA_VERSION:
            raise AnalysisProtocolError(f"unsupported analysis work schema {schema}")
        sequence = reader.unpack(">I", "analysis work sequence")
        endpoint_count = reader.unpack(">H", "endpoint definition count")
        flow_count = reader.unpack(">H", "flow definition count")
        conversation_count = reader.unpack(">H", "conversation definition count")
        item_count = reader.unpack(">H", "analysis work item count")

        pending_endpoints: dict[int, AnalysisEndpointWire] = {}
        pending_flows: dict[int, AnalysisFlowDefinitionWire] = {}
        pending_conversations: dict[int, AnalysisConversationDefinitionWire] = {}
        for _ in range(endpoint_count):
            endpoint_id = self._nonzero(reader.unpack(">I", "endpoint ID"), "endpoint ID")
            address = reader.ascii8(45, "endpoint address")
            if endpoint_id in self.endpoints or endpoint_id in pending_endpoints:
                raise AnalysisProtocolError(f"duplicate endpoint ID: {endpoint_id}")
            if not address:
                raise AnalysisProtocolError("endpoint address is required")
            pending_endpoints[endpoint_id] = AnalysisEndpointWire(endpoint_id, address)
        self.endpoints.update(pending_endpoints)

        for _ in range(flow_count):
            flow_id = self._nonzero(reader.unpack(">I", "flow ID"), "flow ID")
            source_id = reader.unpack(">I", "flow source endpoint ID")
            destination_id = reader.unpack(">I", "flow destination endpoint ID")
            source_port = reader.unpack(">H", "flow source port")
            destination_port = reader.unpack(">H", "flow destination port")
            protocol = reader.unpack(">B", "flow protocol")
            if flow_id in self.flows or flow_id in pending_flows:
                raise AnalysisProtocolError(f"duplicate flow ID: {flow_id}")
            pending_flows[flow_id] = AnalysisFlowDefinitionWire(
                flow_id=flow_id,
                source=self._endpoint(source_id, "flow source"),
                destination=self._endpoint(destination_id, "flow destination"),
                source_port=source_port,
                destination_port=destination_port,
                protocol=protocol,
            )
        self.flows.update(pending_flows)

        for _ in range(conversation_count):
            conversation_id = self._nonzero(
                reader.unpack(">I", "conversation ID"), "conversation ID"
            )
            endpoint_a_id = reader.unpack(">I", "conversation endpoint A ID")
            endpoint_a_port = reader.unpack(">H", "conversation endpoint A port")
            endpoint_b_id = reader.unpack(">I", "conversation endpoint B ID")
            endpoint_b_port = reader.unpack(">H", "conversation endpoint B port")
            initiator_id = reader.unpack(">I", "conversation initiator ID")
            initiator_port = reader.unpack(">H", "conversation initiator port")
            responder_id = reader.unpack(">I", "conversation responder ID")
            responder_port = reader.unpack(">H", "conversation responder port")
            protocol = reader.unpack(">B", "conversation protocol")
            first_seen = self._finite(
                reader.unpack(">d", "conversation first seen"),
                "conversation first seen",
            )
            if conversation_id in self.conversations or conversation_id in pending_conversations:
                raise AnalysisProtocolError(f"duplicate conversation ID: {conversation_id}")
            pending_conversations[conversation_id] = AnalysisConversationDefinitionWire(
                conversation_id=conversation_id,
                endpoint_a=self._endpoint(endpoint_a_id, "conversation endpoint A"),
                endpoint_a_port=endpoint_a_port,
                endpoint_b=self._endpoint(endpoint_b_id, "conversation endpoint B"),
                endpoint_b_port=endpoint_b_port,
                initiator=self._endpoint(initiator_id, "conversation initiator"),
                initiator_port=initiator_port,
                responder=self._endpoint(responder_id, "conversation responder"),
                responder_port=responder_port,
                protocol=protocol,
                first_seen=first_seen,
            )
        self.conversations.update(pending_conversations)

        items = []
        for _ in range(item_count):
            packet_ordinal = self._nonzero(
                reader.unpack(">Q", "packet ordinal"), "packet ordinal"
            )
            timestamp = self._finite(
                reader.unpack(">d", "packet timestamp"), "packet timestamp"
            )
            size = reader.unpack(">I", "packet size")
            flow_id = reader.unpack(">I", "work flow ID")
            conversation_id = reader.unpack(">I", "work conversation ID")
            try:
                flow = self.flows[flow_id]
            except KeyError as exc:
                raise AnalysisProtocolError(f"unknown flow ID: {flow_id}") from exc
            try:
                conversation = self.conversations[conversation_id]
            except KeyError as exc:
                raise AnalysisProtocolError(
                    f"unknown conversation ID: {conversation_id}"
                ) from exc
            hop_limit = reader.unpack(">B", "hop limit")
            tcp_flags = reader.unpack(">H", "TCP flags")
            direction_code = reader.unpack(">B", "conversation direction")
            if direction_code not in self._DIRECTIONS:
                raise AnalysisProtocolError("unsupported conversation direction")
            candidate_code = reader.unpack(">B", "candidate mode")
            if candidate_code not in self._CANDIDATE_MODES:
                raise AnalysisProtocolError("unsupported candidate mode")
            matched_programs = reader.unpack(">Q", "matched selector programs")
            flow_start = self._finite(
                reader.unpack(">d", "flow start time"), "flow start time"
            )
            flow_values = [reader.unpack(">Q", "flow counter") for _ in range(5)]
            conversation_values = [
                reader.unpack(">Q", "conversation counter") for _ in range(8)
            ]
            deltas = [reader.unpack(">I", "conversation delta") for _ in range(3)]
            established = self._boolean(
                reader.unpack(">B", "conversation established"),
                "conversation established",
            )
            raw_length = reader.unpack(">I", "raw candidate length")
            raw_frame = reader.take(raw_length, "raw candidate frame")
            candidate_mode = self._CANDIDATE_MODES[candidate_code]
            if (candidate_mode == "none") != (not raw_frame):
                raise AnalysisProtocolError(
                    "raw candidate presence disagrees with candidate mode"
                )
            items.append(AnalysisWorkItemWire(
                packet_ordinal=packet_ordinal,
                timestamp=timestamp,
                size=size,
                flow=flow,
                conversation=conversation,
                hop_limit=hop_limit,
                tcp_flags=tcp_flags,
                direction=self._DIRECTIONS[direction_code],
                candidate_mode=candidate_mode,
                matched_programs=matched_programs,
                flow_snapshot=AnalysisFlowSnapshotWire(
                    flow_start, *flow_values
                ),
                conversation_snapshot=AnalysisConversationSnapshotWire(
                    *conversation_values, established
                ),
                syn_delta=deltas[0],
                syn_ack_delta=deltas[1],
                rst_delta=deltas[2],
                raw_frame=raw_frame,
            ))
        reader.finish()
        return AnalysisWorkBatchWire(sequence=sequence, items=tuple(items))

    def decode_flows(self, payload: bytes) -> AnalysisFlowBatchWire:
        reader = _Reader(payload)
        schema = reader.unpack(">B", "analysis flow schema")
        if schema != ANALYSIS_SCHEMA_VERSION:
            raise AnalysisProtocolError(f"unsupported analysis flow schema {schema}")
        sequence = reader.unpack(">I", "analysis flow sequence")
        count = reader.unpack(">H", "analysis flow record count")
        records = []
        for _ in range(count):
            flow_id = reader.unpack(">I", "terminal flow ID")
            try:
                definition = self.flows[flow_id]
            except KeyError as exc:
                raise AnalysisProtocolError(
                    f"unknown terminal flow ID: {flow_id}"
                ) from exc
            generation = reader.unpack(">I", "terminal flow generation")
            state = reader.unpack(">B", "terminal flow state")
            if state != 2:
                raise AnalysisProtocolError("terminal flow state must be terminal")
            start_time = self._finite(
                reader.unpack(">d", "terminal flow start"), "terminal flow start"
            )
            last_seen = self._finite(
                reader.unpack(">d", "terminal flow last seen"),
                "terminal flow last seen",
            )
            counters = [reader.unpack(">Q", "terminal flow counter") for _ in range(5)]
            sample_count = reader.unpack(">H", "terminal flow sample count")
            if sample_count > 500:
                raise AnalysisProtocolError("terminal flow sample count exceeds 500")
            samples = []
            for _ in range(sample_count):
                size = reader.unpack(">I", "flow sample size")
                timestamp = self._finite(
                    reader.unpack(">d", "flow sample timestamp"),
                    "flow sample timestamp",
                )
                samples.append((size, timestamp))
            records.append(AnalysisTerminalFlowWire(
                definition=definition,
                generation=generation,
                start_time=start_time,
                last_seen=last_seen,
                packet_count=counters[0],
                byte_count=counters[1],
                syn_count=counters[2],
                syn_ack_count=counters[3],
                rst_count=counters[4],
                samples=tuple(samples),
            ))
        reader.finish()
        return AnalysisFlowBatchWire(sequence=sequence, records=tuple(records))

    def decode_conversations(self, payload: bytes) -> AnalysisConversationBatchWire:
        reader = _Reader(payload)
        schema = reader.unpack(">B", "analysis conversation schema")
        if schema != ANALYSIS_SCHEMA_VERSION:
            raise AnalysisProtocolError(
                f"unsupported analysis conversation schema {schema}"
            )
        sequence = reader.unpack(">I", "analysis conversation sequence")
        count = reader.unpack(">H", "analysis conversation record count")
        records = []
        for _ in range(count):
            conversation_id = reader.unpack(">I", "terminal conversation ID")
            try:
                definition = self.conversations[conversation_id]
            except KeyError as exc:
                raise AnalysisProtocolError(
                    f"unknown terminal conversation ID: {conversation_id}"
                ) from exc
            state = reader.unpack(">B", "terminal conversation state")
            if state != 2:
                raise AnalysisProtocolError(
                    "terminal conversation state must be terminal"
                )
            last_seen = self._finite(
                reader.unpack(">d", "terminal conversation last seen"),
                "terminal conversation last seen",
            )
            values = [
                reader.unpack(">Q", "terminal conversation counter")
                for _ in range(8)
            ]
            established = self._boolean(
                reader.unpack(">B", "terminal conversation established"),
                "terminal conversation established",
            )
            records.append(AnalysisTerminalConversationWire(
                definition=definition,
                last_seen=last_seen,
                generation=values[0],
                to_responder_packets=values[1],
                to_responder_bytes=values[2],
                to_initiator_packets=values[3],
                to_initiator_bytes=values[4],
                syn_count=values[5],
                syn_ack_count=values[6],
                rst_count=values[7],
                established=established,
            ))
        reader.finish()
        return AnalysisConversationBatchWire(sequence=sequence, records=tuple(records))


def _digest(value: bytes, label: str) -> None:
    if not isinstance(value, bytes) or len(value) != 32:
        raise AnalysisProtocolError(f"{label} must be a 32-byte SHA-256 digest")


def _range(value: int, minimum: int, maximum: int, label: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise AnalysisProtocolError(f"{label} must be {minimum}..{maximum}")


def _ascii8(value: str, maximum: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise AnalysisProtocolError(f"{label} must be ASCII text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AnalysisProtocolError(f"{label} must be ASCII text") from exc
    if len(encoded) > maximum:
        raise AnalysisProtocolError(f"{label} exceeds {maximum} bytes")
    return bytes([len(encoded)]) + encoded


_SELECTOR_OPCODES = {
    "always": 1,
    "link-class-in": 2,
    "ethertype-in": 3,
    "ip-protocol-in": 4,
    "either-port-in": 5,
    "source-port-in": 6,
    "destination-port-in": 7,
    "tcp-flags": 8,
    "icmp-type-in": 9,
    "payload-minimum-length": 10,
    "payload-prefix-in": 11,
    "payload-contains-any": 12,
    "payload-byte-mask": 13,
    "payload-diversity": 14,
    "frame-window-contains-any": 15,
}
_SELECTOR_NAMES = {value: key for key, value in _SELECTOR_OPCODES.items()}
_CANDIDATE_MODE_CODES = {"fast-v1": 1, "deep-scapy-v1": 2}
_LINK_CLASS_CODES = {"ethernet": 1, "raw-ip": 2}


def _selector_literals(values, label):
    if not 1 <= len(values) <= 32:
        raise AnalysisProtocolError(f"{label} requires 1..32 literals")
    output = bytearray((len(values),))
    for value in values:
        if not isinstance(value, bytes) or not 1 <= len(value) <= 256:
            raise AnalysisProtocolError(f"{label} literal must contain 1..256 bytes")
        output.extend(struct.pack(">H", len(value)))
        output.extend(value)
    return bytes(output)


def _encode_selector_clause(clause: AnalysisSelectorClauseWire) -> bytes:
    if not isinstance(clause, AnalysisSelectorClauseWire):
        raise AnalysisProtocolError("selector clause has an invalid type")
    if clause.opcode not in _SELECTOR_OPCODES:
        raise AnalysisProtocolError(f"unknown selector opcode: {clause.opcode}")
    values = clause.values
    output = bytearray((_SELECTOR_OPCODES[clause.opcode],))
    if clause.opcode == "always":
        if values:
            raise AnalysisProtocolError("always selector does not accept values")
    elif clause.opcode == "link-class-in":
        if not 1 <= len(values) <= 2 or any(value not in _LINK_CLASS_CODES for value in values):
            raise AnalysisProtocolError("link-class-in values are invalid")
        output.append(len(values))
        output.extend(_LINK_CLASS_CODES[value] for value in values)
    elif clause.opcode in {"ethertype-in", "either-port-in", "source-port-in", "destination-port-in"}:
        maximum = 255 if clause.opcode == "ethertype-in" else 512
        if not 1 <= len(values) <= maximum:
            raise AnalysisProtocolError(f"{clause.opcode} value count is invalid")
        output.extend(struct.pack(">H", len(values)))
        for value in values:
            _range(value, 0, 0xFFFF, clause.opcode)
            output.extend(struct.pack(">H", value))
    elif clause.opcode in {"ip-protocol-in", "icmp-type-in"}:
        if not 1 <= len(values) <= 255:
            raise AnalysisProtocolError(f"{clause.opcode} value count is invalid")
        output.append(len(values))
        for value in values:
            _range(value, 0, 0xFF, clause.opcode)
            output.append(value)
    elif clause.opcode == "tcp-flags":
        if len(values) != 2:
            raise AnalysisProtocolError("tcp-flags requires two values")
        for value in values:
            _range(value, 0, 0xFFFF, "tcp-flags")
            output.extend(struct.pack(">H", value))
    elif clause.opcode == "payload-minimum-length":
        if len(values) != 1:
            raise AnalysisProtocolError("payload-minimum-length requires one value")
        _range(values[0], 0, 0xFFFFFFFF, "payload-minimum-length")
        output.extend(struct.pack(">I", values[0]))
    elif clause.opcode in {"payload-prefix-in", "payload-contains-any"}:
        output.extend(_selector_literals(values, clause.opcode))
    elif clause.opcode == "payload-byte-mask":
        if len(values) != 3:
            raise AnalysisProtocolError("payload-byte-mask requires three values")
        _range(values[0], 0, 0xFFFF, "payload-byte-mask offset")
        _range(values[1], 0, 0xFF, "payload-byte-mask mask")
        _range(values[2], 0, 0xFF, "payload-byte-mask expected")
        output.extend(struct.pack(">HBB", *values))
    elif clause.opcode == "payload-diversity":
        if len(values) != 2:
            raise AnalysisProtocolError("payload-diversity requires two values")
        for value in values:
            _range(value, 0, 0xFFFF, "payload-diversity")
        if values[1] > values[0]:
            raise AnalysisProtocolError("payload-diversity minimum exceeds sample")
        output.extend(struct.pack(">HH", *values))
    elif clause.opcode == "frame-window-contains-any":
        if len(values) < 3:
            raise AnalysisProtocolError("frame-window-contains-any requires a window and literals")
        start, end, *literals = values
        _range(start, 0, 0xFFFF, "frame window start")
        _range(end, start, 0xFFFF, "frame window end")
        output.extend(struct.pack(">HH", start, end))
        output.extend(_selector_literals(tuple(literals), clause.opcode))
    return bytes(output)


def _encode_selector_program(program: AnalysisSelectorProgramWire) -> bytes:
    if not isinstance(program, AnalysisSelectorProgramWire):
        raise AnalysisProtocolError("selector program has an invalid type")
    _range(program.program_id, 0, 63, "selector program ID")
    if program.candidate_mode not in _CANDIDATE_MODE_CODES:
        raise AnalysisProtocolError("selector candidate mode is invalid")
    if not 1 <= len(program.clauses) <= 16:
        raise AnalysisProtocolError("selector program requires 1..16 clauses")
    output = bytearray((
        program.program_id,
        _CANDIDATE_MODE_CODES[program.candidate_mode],
        len(program.clauses),
    ))
    for clause in program.clauses:
        output.extend(_encode_selector_clause(clause))
    return bytes(output)


def _decode_selector_literals(reader: _Reader, label: str) -> tuple[bytes, ...]:
    count = reader.unpack(">B", f"{label} literal count")
    if not 1 <= count <= 32:
        raise AnalysisProtocolError(f"{label} requires 1..32 literals")
    return tuple(
        reader.take(reader.unpack(">H", f"{label} literal length"), f"{label} literal")
        for _ in range(count)
    )


def _decode_selector_clause(reader: _Reader) -> AnalysisSelectorClauseWire:
    code = reader.unpack(">B", "selector opcode")
    if code not in _SELECTOR_NAMES:
        raise AnalysisProtocolError(f"unknown selector opcode: {code}")
    opcode = _SELECTOR_NAMES[code]
    if opcode == "always":
        values = ()
    elif opcode == "link-class-in":
        count = reader.unpack(">B", "link class count")
        names = {value: key for key, value in _LINK_CLASS_CODES.items()}
        codes = [reader.unpack(">B", "link class") for _ in range(count)]
        if not codes or any(value not in names for value in codes):
            raise AnalysisProtocolError("link-class-in values are invalid")
        values = tuple(names[value] for value in codes)
    elif opcode in {"ethertype-in", "either-port-in", "source-port-in", "destination-port-in"}:
        count = reader.unpack(">H", f"{opcode} count")
        values = tuple(reader.unpack(">H", opcode) for _ in range(count))
    elif opcode in {"ip-protocol-in", "icmp-type-in"}:
        count = reader.unpack(">B", f"{opcode} count")
        values = tuple(reader.unpack(">B", opcode) for _ in range(count))
    elif opcode == "tcp-flags":
        values = (reader.unpack(">H", "required TCP flags"), reader.unpack(">H", "forbidden TCP flags"))
    elif opcode == "payload-minimum-length":
        values = (reader.unpack(">I", opcode),)
    elif opcode in {"payload-prefix-in", "payload-contains-any"}:
        values = _decode_selector_literals(reader, opcode)
    elif opcode == "payload-byte-mask":
        values = (
            reader.unpack(">H", "payload mask offset"),
            reader.unpack(">B", "payload mask"),
            reader.unpack(">B", "payload mask expected"),
        )
    elif opcode == "payload-diversity":
        values = (reader.unpack(">H", "payload sample"), reader.unpack(">H", "payload minimum distinct"))
    else:
        start = reader.unpack(">H", "frame window start")
        end = reader.unpack(">H", "frame window end")
        values = (start, end, *_decode_selector_literals(reader, opcode))
    clause = AnalysisSelectorClauseWire(opcode, tuple(values))
    _encode_selector_clause(clause)
    return clause


def _decode_selector_program(reader: _Reader) -> AnalysisSelectorProgramWire:
    program_id = reader.unpack(">B", "selector program ID")
    mode_code = reader.unpack(">B", "selector candidate mode")
    modes = {value: key for key, value in _CANDIDATE_MODE_CODES.items()}
    if mode_code not in modes:
        raise AnalysisProtocolError("selector candidate mode is invalid")
    clause_count = reader.unpack(">B", "selector clause count")
    program = AnalysisSelectorProgramWire(
        program_id=program_id,
        candidate_mode=modes[mode_code],
        clauses=tuple(_decode_selector_clause(reader) for _ in range(clause_count)),
    )
    _encode_selector_program(program)
    return program


def _validate_plan(plan: AnalysisPlanWire) -> None:
    _digest(plan.plan_sha256, "plan digest")
    _digest(plan.semantic_plugin_sha256, "semantic plugin digest")
    if plan.execution_mode not in _EXECUTION_MODES:
        raise AnalysisProtocolError("unsupported execution mode")
    if plan.analysis_mode not in _ANALYSIS_MODES:
        raise AnalysisProtocolError("unsupported analysis mode")
    _range(plan.flags, 0, 0xFFFF, "flags")
    if plan.flags & ~_KNOWN_FLAGS:
        raise AnalysisProtocolError("unknown analysis plan flags")
    _range(plan.target_batch_bytes, 1, _MAX_TARGET_BATCH_BYTES, "target batch bytes")
    _range(plan.max_active_conversations, 1, 100_000, "max active conversations")
    _range(plan.max_resume_conversations, 1, 100_000, "max resume conversations")
    _range(plan.max_directional_flows, 1, 220_000, "max directional flows")
    _range(plan.max_endpoints, 1, 440_000, "max endpoints")
    _range(plan.max_flow_samples, 1, 500, "max flow samples")
    _range(plan.max_flow_sample_bytes, 1, 268_435_456, "max flow sample bytes")
    _range(plan.max_stream_segments, 1, 10_000, "max stream segments")
    _range(plan.max_stream_bytes, 1, 16_777_216, "max stream bytes")
    if len(plan.selector_programs) > _MAX_SELECTOR_PROGRAMS:
        raise AnalysisProtocolError("selector program count exceeds 64")
    if len({program.program_id for program in plan.selector_programs}) != len(plan.selector_programs):
        raise AnalysisProtocolError("selector program IDs must be unique")
    for program in plan.selector_programs:
        _encode_selector_program(program)
    _ascii8(plan.source, 255, "source")
    _ascii8(plan.session_id, 255, "session ID")
    _ascii8(plan.interface, 64, "interface")
    _ascii8(plan.sensor_node_id, 128, "sensor node ID")


def encode_analysis_plan(plan: AnalysisPlanWire) -> bytes:
    _validate_plan(plan)
    body = bytearray()
    body.extend(plan.semantic_plugin_sha256)
    body.append(_EXECUTION_MODES[plan.execution_mode])
    body.append(_ANALYSIS_MODES[plan.analysis_mode])
    body.extend(struct.pack(">H", plan.flags))
    body.extend(struct.pack(">I", plan.target_batch_bytes))
    body.extend(struct.pack(">IIII", plan.max_active_conversations, plan.max_resume_conversations, plan.max_directional_flows, plan.max_endpoints))
    body.extend(struct.pack(">H", plan.max_flow_samples))
    body.extend(struct.pack(">Q", plan.max_flow_sample_bytes))
    body.extend(struct.pack(">I", plan.max_stream_segments))
    body.extend(struct.pack(">Q", plan.max_stream_bytes))
    body.extend(_ascii8(plan.source, 255, "source"))
    body.extend(_ascii8(plan.session_id, 255, "session ID"))
    body.extend(_ascii8(plan.interface, 64, "interface"))
    body.extend(_ascii8(plan.sensor_node_id, 128, "sensor node ID"))
    body.append(len(plan.selector_programs))
    for program in plan.selector_programs:
        body.extend(_encode_selector_program(program))
    payload = bytes([ANALYSIS_SCHEMA_VERSION]) + (b"\x00" * 32) + bytes(body)
    digest = sha256(payload[33:]).digest()
    return bytes([ANALYSIS_SCHEMA_VERSION]) + digest + bytes(body)


def decode_analysis_plan(payload: bytes) -> AnalysisPlanWire:
    reader = _Reader(payload)
    schema = reader.unpack(">B", "analysis plan schema")
    if schema != ANALYSIS_SCHEMA_VERSION:
        raise AnalysisProtocolError(f"unsupported analysis plan schema {schema}")
    digest = reader.take(32, "plan digest")
    semantic_digest = reader.take(32, "semantic plugin digest")
    execution_code = reader.unpack(">B", "execution mode")
    execution_modes = {value: key for key, value in _EXECUTION_MODES.items()}
    if execution_code not in execution_modes:
        raise AnalysisProtocolError("unsupported execution mode")
    analysis_code = reader.unpack(">B", "analysis mode")
    analysis_modes = {value: key for key, value in _ANALYSIS_MODES.items()}
    if analysis_code not in analysis_modes:
        raise AnalysisProtocolError("unsupported analysis mode")
    flags = reader.unpack(">H", "flags")
    target_batch_bytes = reader.unpack(">I", "target batch bytes")
    max_active_conversations = reader.unpack(">I", "max active conversations")
    max_resume_conversations = reader.unpack(">I", "max resume conversations")
    max_directional_flows = reader.unpack(">I", "max directional flows")
    max_endpoints = reader.unpack(">I", "max endpoints")
    max_flow_samples = reader.unpack(">H", "max flow samples")
    max_flow_sample_bytes = reader.unpack(">Q", "max flow sample bytes")
    max_stream_segments = reader.unpack(">I", "max stream segments")
    max_stream_bytes = reader.unpack(">Q", "max stream bytes")
    source = reader.ascii8(255, "source")
    session_id = reader.ascii8(255, "session ID")
    interface = reader.ascii8(64, "interface")
    sensor_node_id = reader.ascii8(128, "sensor node ID")
    program_count = reader.unpack(">B", "selector program count")
    selector_programs = tuple(_decode_selector_program(reader) for _ in range(program_count))
    reader.finish()
    plan = AnalysisPlanWire(
        plan_sha256=digest,
        semantic_plugin_sha256=semantic_digest,
        execution_mode=execution_modes[execution_code],
        analysis_mode=analysis_modes[analysis_code],
        flags=flags,
        target_batch_bytes=target_batch_bytes,
        max_active_conversations=max_active_conversations,
        max_resume_conversations=max_resume_conversations,
        max_directional_flows=max_directional_flows,
        max_endpoints=max_endpoints,
        max_flow_samples=max_flow_samples,
        max_flow_sample_bytes=max_flow_sample_bytes,
        max_stream_segments=max_stream_segments,
        max_stream_bytes=max_stream_bytes,
        source=source,
        session_id=session_id,
        interface=interface,
        sensor_node_id=sensor_node_id,
        selector_programs=selector_programs,
    )
    _validate_plan(plan)
    # Validate the bounded wire structure before reporting an integrity error.
    # This keeps child-process diagnostics actionable for malformed frames.
    if digest != sha256(bytes(payload)[33:]).digest():
        raise AnalysisProtocolError("analysis plan digest mismatch")
    return plan


def encode_analysis_hello(hello: AnalysisHelloWire) -> bytes:
    _digest(hello.plan_sha256, "plan digest")
    _range(hello.pcap_datalink, -(2**31), 2**31 - 1, "pcap datalink")
    _range(hello.capability_bits, 0, 2**64 - 1, "capability bits")
    return b"".join((
        bytes([ANALYSIS_SCHEMA_VERSION]),
        hello.plan_sha256,
        _ascii8(hello.sensor_version, 32, "sensor version"),
        struct.pack(">i", hello.pcap_datalink),
        _ascii8(hello.normalized_link_type, 32, "normalized link type"),
        struct.pack(">Q", hello.capability_bits),
    ))


def decode_analysis_hello(payload: bytes) -> AnalysisHelloWire:
    reader = _Reader(payload)
    schema = reader.unpack(">B", "analysis hello schema")
    if schema != ANALYSIS_SCHEMA_VERSION:
        raise AnalysisProtocolError(f"unsupported analysis hello schema {schema}")
    result = AnalysisHelloWire(
        plan_sha256=reader.take(32, "plan digest"),
        sensor_version=reader.ascii8(32, "sensor version"),
        pcap_datalink=reader.unpack(">i", "pcap datalink"),
        normalized_link_type=reader.ascii8(32, "normalized link type"),
        capability_bits=reader.unpack(">Q", "capability bits"),
    )
    reader.finish()
    _digest(result.plan_sha256, "plan digest")
    return result


def _encode_optional_timestamp(value: float | None, label: str) -> bytes:
    if value is None:
        return b"\x00" + struct.pack(">d", 0.0)
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        raise AnalysisProtocolError(f"{label} must be a finite timestamp")
    return b"\x01" + struct.pack(">d", float(value))


def _decode_optional_timestamp(reader: _Reader, label: str) -> float | None:
    present = reader.unpack(">B", f"{label} presence")
    if present not in (0, 1):
        raise AnalysisProtocolError(f"{label} presence must be 0 or 1")
    value = reader.unpack(">d", label)
    if present == 0:
        if value != 0.0:
            raise AnalysisProtocolError(f"absent {label} must be zero")
        return None
    if not math.isfinite(value):
        raise AnalysisProtocolError(f"{label} must be finite")
    return value


def _unsigned(value: int, bits: int, label: str) -> bytes:
    _range(value, 0, (1 << bits) - 1, label)
    return struct.pack(">Q" if bits == 64 else ">I", value)


def encode_analysis_end(end: AnalysisEndWire) -> bytes:
    """Encode the terminal certificate required before clean child EOF."""
    _digest(end.plan_sha256, "plan digest")
    if end.terminal_status not in _TERMINAL_STATUSES:
        raise AnalysisProtocolError("unsupported analysis terminal status")
    payload = bytearray((ANALYSIS_SCHEMA_VERSION,))
    payload.extend(end.plan_sha256)
    payload.append(_TERMINAL_STATUSES[end.terminal_status])
    payload.extend(_ascii8(end.error_code, 128, "analysis error code"))
    for label, value in (
        ("packet index rows", end.packet_index_rows),
        ("decoded work items", end.decoded_work_items),
        ("raw candidate items", end.raw_candidate_items),
        ("raw candidate bytes", end.raw_candidate_bytes),
        ("flow snapshot records", end.flow_snapshot_records),
        ("terminal directional flows", end.terminal_directional_flows),
        ("conversation snapshot records", end.conversation_snapshot_records),
        ("terminal conversations", end.terminal_conversations),
        ("stream segment records", end.stream_segment_records),
        ("stream segment bytes", end.stream_segment_bytes),
        ("stream truncated segments", end.stream_truncated_segments),
        ("stream truncated bytes", end.stream_truncated_bytes),
    ):
        payload.extend(_unsigned(value, 64, label))
    payload.extend(_encode_optional_timestamp(end.first_decoded_timestamp, "first decoded timestamp"))
    payload.extend(_encode_optional_timestamp(end.last_decoded_timestamp, "last decoded timestamp"))
    for label, digest in (
        ("packet index digest", end.packet_index_digest),
        ("work digest", end.work_digest),
        ("flow digest", end.flow_digest),
        ("conversation digest", end.conversation_digest),
        ("stream digest", end.stream_digest),
    ):
        _digest(digest, label)
        payload.extend(digest)
    for label, value in (
        ("read/decode nanoseconds", end.read_decode_ns),
        ("candidate-match nanoseconds", end.candidate_match_ns),
        ("aggregate nanoseconds", end.aggregate_ns),
        ("blocked-write nanoseconds", end.blocked_write_ns),
    ):
        payload.extend(_unsigned(value, 64, label))
    for label, value in (
        ("endpoint high water", end.endpoint_high_water),
        ("flow high water", end.flow_high_water),
        ("conversation high water", end.conversation_high_water),
        ("resume high water", end.resume_high_water),
    ):
        payload.extend(_unsigned(value, 32, label))
    payload.extend(_unsigned(end.sample_bytes_high_water, 64, "sample bytes high water"))
    return bytes(payload)


def decode_analysis_end(payload: bytes) -> AnalysisEndWire:
    reader = _Reader(payload)
    schema = reader.unpack(">B", "analysis end schema")
    if schema != ANALYSIS_SCHEMA_VERSION:
        raise AnalysisProtocolError(f"unsupported analysis end schema {schema}")
    plan_sha256 = reader.take(32, "plan digest")
    status_code = reader.unpack(">B", "analysis terminal status")
    statuses = {value: key for key, value in _TERMINAL_STATUSES.items()}
    if status_code not in statuses:
        raise AnalysisProtocolError("unsupported analysis terminal status")
    error_code = reader.ascii8(128, "analysis error code")
    counts = [reader.unpack(">Q", "analysis terminal counter") for _ in range(12)]
    first_timestamp = _decode_optional_timestamp(reader, "first decoded timestamp")
    last_timestamp = _decode_optional_timestamp(reader, "last decoded timestamp")
    digests = [reader.take(32, "analysis terminal digest") for _ in range(5)]
    timers = [reader.unpack(">Q", "analysis terminal timer") for _ in range(4)]
    highs = [reader.unpack(">I", "analysis terminal high water") for _ in range(4)]
    sample_bytes_high_water = reader.unpack(">Q", "sample bytes high water")
    reader.finish()
    return AnalysisEndWire(
        plan_sha256=plan_sha256, terminal_status=statuses[status_code], error_code=error_code,
        packet_index_rows=counts[0], decoded_work_items=counts[1], raw_candidate_items=counts[2],
        raw_candidate_bytes=counts[3], flow_snapshot_records=counts[4], terminal_directional_flows=counts[5],
        conversation_snapshot_records=counts[6], terminal_conversations=counts[7], stream_segment_records=counts[8],
        stream_segment_bytes=counts[9], stream_truncated_segments=counts[10], stream_truncated_bytes=counts[11],
        first_decoded_timestamp=first_timestamp, last_decoded_timestamp=last_timestamp,
        packet_index_digest=digests[0], work_digest=digests[1], flow_digest=digests[2],
        conversation_digest=digests[3], stream_digest=digests[4], read_decode_ns=timers[0],
        candidate_match_ns=timers[1], aggregate_ns=timers[2], blocked_write_ns=timers[3],
        endpoint_high_water=highs[0], flow_high_water=highs[1], conversation_high_water=highs[2],
        resume_high_water=highs[3], sample_bytes_high_water=sample_bytes_high_water,
    )


def work_item_to_packet_event(
    item: AnalysisWorkItemWire,
    origin: dict,
    *,
    link_type: str,
):
    from core.packet_engine.schemas import PacketEvent

    protocol = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPV6",
        254: "ARP",
    }.get(item.flow.protocol, f"IP-{item.flow.protocol}")
    flags = "".join(
        name
        for mask, name in (
            (0x02, "S"),
            (0x10, "A"),
            (0x01, "F"),
            (0x04, "R"),
            (0x08, "P"),
            (0x20, "U"),
        )
        if item.tcp_flags & mask
    )
    conversation = item.conversation_snapshot
    return PacketEvent(
        timestamp=item.timestamp,
        src_ip=item.flow.source.address,
        dst_ip=item.flow.destination.address,
        src_port=item.flow.source_port,
        dst_port=item.flow.destination_port,
        protocol=protocol,
        size=item.size,
        flags=flags,
        l7_info={
            "rust_flow_id": item.flow.flow_id,
            "rust_conversation_id": item.conversation.conversation_id,
            "conversation_direction": item.direction,
            "initiator_ip": item.conversation.initiator.address,
            "initiator_port": item.conversation.initiator_port,
            "responder_ip": item.conversation.responder.address,
            "responder_port": item.conversation.responder_port,
            "conversation_established": conversation.established,
            "conversation_syn_count": conversation.syn_count,
            "conversation_syn_ack_count": conversation.syn_ack_count,
            "conversation_rst_count": conversation.rst_count,
            "conversation_to_responder_packets": conversation.to_responder_packets,
            "conversation_to_responder_bytes": conversation.to_responder_bytes,
            "conversation_to_initiator_packets": conversation.to_initiator_packets,
            "conversation_to_initiator_bytes": conversation.to_initiator_bytes,
        },
        raw=item.raw_frame or None,
        interface=str(origin.get("device_id") or "pcap"),
        session_id=origin.get("session_id"),
        source_type=str(origin.get("source_type") or "network"),
        backend="rust",
        link_type=link_type,
        sensor_node_id=origin.get("sensor_node_id"),
        source=origin.get("source"),
    )


class AnalysisStreamValidator:
    """Reject protocol ordering or handshake drift before evidence is consumed."""

    def __init__(self, plan: AnalysisPlanWire):
        self.plan = decode_analysis_plan(encode_analysis_plan(plan))
        self.hello: AnalysisHelloWire | None = None
        self.end: AnalysisEndWire | None = None

    def accept(self, frame_kind: int, payload: bytes) -> None:
        if self.hello is None:
            if frame_kind != FRAME_ANALYSIS_HELLO:
                raise AnalysisProtocolError("first output frame must be analysis hello")
            hello = decode_analysis_hello(payload)
            if hello.plan_sha256 != self.plan.plan_sha256:
                raise AnalysisProtocolError("analysis hello plan digest mismatch")
            if hello.capability_bits & ANALYSIS_CAPABILITY_V1 != ANALYSIS_CAPABILITY_V1:
                raise AnalysisProtocolError("analysis hello lacks required capability bits")
            self.hello = hello
            return
        if frame_kind == FRAME_ANALYSIS_HELLO:
            raise AnalysisProtocolError("analysis hello may appear only once")
        if self.end is not None:
            raise AnalysisProtocolError("analysis output appeared after terminal certificate")
        if frame_kind not in {
            FRAME_ANALYSIS_WORK,
            FRAME_ANALYSIS_FLOW,
            FRAME_ANALYSIS_CONVERSATION,
            FRAME_ANALYSIS_STREAM,
            FRAME_ANALYSIS_END,
            FRAME_ANALYSIS_ERROR,
            FRAME_ANALYSIS_PACKET_INDEX,
        }:
            raise AnalysisProtocolError(f"unsupported analysis output frame: {frame_kind}")
        if frame_kind == FRAME_ANALYSIS_END:
            end = decode_analysis_end(payload)
            if end.plan_sha256 != self.plan.plan_sha256:
                raise AnalysisProtocolError("analysis terminal certificate plan digest mismatch")
            self.end = end

    def finish(self, exit_code: int) -> AnalysisEndWire:
        if self.hello is None:
            raise AnalysisProtocolError("analysis child ended before handshake")
        if self.end is None:
            raise AnalysisProtocolError("analysis child ended without a terminal certificate")
        if exit_code != 0:
            raise AnalysisProtocolError(f"analysis child exited with code {exit_code}")
        return self.end


class RustAnalysisChild:
    """Small lifecycle guard for the aggregate sensor subprocess.

    It is deliberately transport-only.  The production engine will own
    demultiplexing and terminal certificate validation in a later slice.
    """

    def __init__(self, process, plan: AnalysisPlanWire):
        self.process = process
        self.plan = decode_analysis_plan(encode_analysis_plan(plan))
        self.validator = AnalysisStreamValidator(self.plan)
        self.started = False
        self.closed = False

    def start(self) -> AnalysisHelloWire:
        if self.closed:
            raise AnalysisProtocolError("analysis child is already closed")
        if self.started:
            return self.validator.hello
        if getattr(self.process, "stdin", None) is None or getattr(self.process, "stdout", None) is None:
            raise AnalysisProtocolError("analysis child must expose stdin and stdout")
        try:
            self.process.stdin.write(encode_transport_frame(FRAME_ANALYSIS_PLAN, encode_analysis_plan(self.plan)))
            self.process.stdin.flush()
            frame_kind, payload = read_transport_frame(self.process.stdout)
            self.validator.accept(frame_kind, payload)
            self.started = True
            return self.validator.hello
        except Exception:
            self.close()
            raise

    def close(self, timeout: float = 3.0) -> None:
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

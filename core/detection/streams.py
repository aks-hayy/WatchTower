"""Bounded live TCP reassembly for stream-capable detector plugins."""

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from scapy.layers.inet import TCP

from core.detection.payload import application_payload
from core.packet_engine.conversations import ConversationKey
from core.packet_engine.schemas import PacketEvent


@dataclass
class StreamDirection:
    segments: Dict[int, bytes] = field(default_factory=dict)
    truncated: bool = False
    updates: int = 0
    last_emitted_update: int = 0


@dataclass
class LiveStreamState:
    last_seen: float
    directions: Dict[str, StreamDirection] = field(default_factory=lambda: {
        "to_responder": StreamDirection(),
        "to_initiator": StreamDirection(),
    })


@dataclass(frozen=True)
class LiveStreamSnapshot:
    flow_id: Tuple
    direction: str
    payload: bytes
    timestamp: float
    truncated: bool


class LiveTCPStreamTracker:
    def __init__(self, maximum_streams: int = 4096, maximum_bytes: int = 1024 * 1024,
                 maximum_segments: int = 128, emit_interval: int = 8):
        self.maximum_streams = max(64, int(maximum_streams))
        self.maximum_bytes = max(8192, int(maximum_bytes))
        self.maximum_segments = max(32, int(maximum_segments))
        self.emit_interval = max(1, int(emit_interval))
        self.states: Dict[ConversationKey, LiveStreamState] = {}

    @staticmethod
    def _has_evidence_marker(payload: bytes) -> bool:
        sample = bytes(payload[:8192]).lower()
        return any(marker in sample for marker in (
            b"user ", b"pass ", b"password", b"authorization", b"ntlmssp",
            b"ssh-", b"get ", b"post ", b"http/", b"\x16\x03", b"mqtt",
            b"modbus", b"coap", b"mz",
        ))

    def update(self, packet, event: PacketEvent) -> Optional[LiveStreamSnapshot]:
        if TCP not in packet:
            return None
        payload = application_payload(packet, maximum=self.maximum_bytes)
        if not payload:
            return None
        key = ConversationKey.from_event(event)
        state = self.states.setdefault(key, LiveStreamState(last_seen=float(event.timestamp)))
        state.last_seen = max(state.last_seen, float(event.timestamp))
        direction = str((event.l7_info or {}).get("conversation_direction") or "to_responder")
        stream = state.directions[direction]
        sequence = int(packet[TCP].seq or 0)
        existing = stream.segments.get(sequence)
        if existing == payload:
            return None
        if len(stream.segments) >= self.maximum_segments and sequence not in stream.segments:
            stream.truncated = True
            # A bounded stream may still expose a newly observed protocol
            # marker.  The direct payload is safe evidence, while retaining
            # the existing segment map prevents unbounded memory growth.
            if not self._has_evidence_marker(payload):
                return None
            return LiveStreamSnapshot(
                flow_id=(event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.protocol),
                direction=direction, payload=payload, timestamp=float(event.timestamp),
                truncated=True,
            )
        stream.segments[sequence] = payload
        stream.updates += 1

        # Reassembly is deliberately sparse for bulk traffic.  The first
        # sixteen segments preserve fragmented handshakes/credentials; after
        # that, marked payloads and periodic samples are sufficient for the
        # bounded live stream detectors without sorting the whole stream for
        # every packet.
        segment_count = len(stream.segments)
        marked = self._has_evidence_marker(payload)
        if (
            segment_count > 16
            and not marked
            and stream.updates - stream.last_emitted_update < self.emit_interval
        ):
            self._evict_if_needed()
            return None
        reassembled, truncated = self._reassemble(stream.segments)
        stream.truncated = stream.truncated or truncated
        stream.last_emitted_update = stream.updates
        self._evict_if_needed()
        return LiveStreamSnapshot(
            flow_id=(event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.protocol),
            direction=direction, payload=reassembled, timestamp=float(event.timestamp),
            truncated=stream.truncated,
        )

    def expire(self, before: float) -> None:
        for key in [key for key, state in self.states.items() if state.last_seen < before]:
            self.states.pop(key, None)

    def _reassemble(self, segments: Dict[int, bytes]) -> Tuple[bytes, bool]:
        result = bytearray()
        end = None
        truncated = False
        for sequence, payload in sorted(segments.items()):
            if end is None:
                result.extend(payload)
                end = sequence + len(payload)
                continue
            if sequence > end:
                break
            overlap = max(0, end - sequence)
            if overlap < len(payload):
                result.extend(payload[overlap:])
                end = sequence + len(payload)
            if len(result) >= self.maximum_bytes:
                del result[self.maximum_bytes:]
                truncated = True
                break
        return bytes(result), truncated

    def _evict_if_needed(self) -> None:
        overflow = len(self.states) - self.maximum_streams
        if overflow <= 0:
            return
        for key, _state in sorted(self.states.items(), key=lambda item: item[1].last_seen)[:overflow]:
            self.states.pop(key, None)

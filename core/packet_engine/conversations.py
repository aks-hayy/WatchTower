"""Bounded, session-scoped bidirectional conversation tracking."""

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Dict, Tuple

from core.packet_engine.schemas import PacketEvent

Endpoint = Tuple[str, int]


@dataclass(frozen=True)
class ConversationKey:
    sensor_node_id: str
    source: str
    session_id: str
    interface: str
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    @classmethod
    def from_event(cls, event: PacketEvent) -> "ConversationKey":
        endpoints = sorted(
            ((str(event.src_ip), int(event.src_port or 0)),
             (str(event.dst_ip), int(event.dst_port or 0))),
            key=lambda item: (item[0], item[1]),
        )
        return cls(
            sensor_node_id=str(event.sensor_node_id or "local"),
            source=str(event.source or f"live_{event.interface}"),
            session_id=str(event.session_id or "legacy"),
            interface=str(event.interface or "auto"),
            protocol=str(event.protocol or "OTHER").upper(),
            endpoint_a=endpoints[0],
            endpoint_b=endpoints[1],
        )


@dataclass
class ConversationState:
    key: ConversationKey
    initiator: Endpoint
    responder: Endpoint
    first_seen: float
    last_seen: float
    to_responder_packets: int = 0
    to_responder_bytes: int = 0
    to_initiator_packets: int = 0
    to_initiator_bytes: int = 0
    syn_count: int = 0
    syn_ack_count: int = 0
    rst_count: int = 0
    established: bool = False
    application: Dict = field(default_factory=dict)
    generation: int = 0
    backend: str = "unknown"
    source_type: str = "network"

    def update(self, event: PacketEvent) -> str:
        source = (str(event.src_ip), int(event.src_port or 0))
        direction = "to_responder" if source == self.initiator else "to_initiator"
        if direction == "to_responder":
            self.to_responder_packets += 1
            self.to_responder_bytes += int(event.size or 0)
        else:
            self.to_initiator_packets += 1
            self.to_initiator_bytes += int(event.size or 0)
        flags = str(event.flags or "")
        if "S" in flags and "A" not in flags:
            self.syn_count += 1
        if "S" in flags and "A" in flags:
            self.syn_ack_count += 1
            self.established = True
        if "R" in flags:
            self.rst_count += 1
        self.last_seen = max(self.last_seen, float(event.timestamp))
        self.backend = str(event.backend or self.backend or "unknown")
        self.source_type = str(event.source_type or self.source_type or "network")
        self.generation += 1
        return direction

    def flow_metadata(self, event: PacketEvent, direction: str) -> Dict:
        reverse_bytes = self.to_initiator_bytes if direction == "to_responder" else self.to_responder_bytes
        reverse_packets = self.to_initiator_packets if direction == "to_responder" else self.to_responder_packets
        return {
            "conversation_direction": direction,
            "initiator_ip": self.initiator[0],
            "initiator_port": self.initiator[1],
            "responder_ip": self.responder[0],
            "responder_port": self.responder[1],
            "reverse_byte_count": reverse_bytes,
            "reverse_packet_count": reverse_packets,
            "conversation_established": self.established,
            "conversation_syn_count": self.syn_count,
            "conversation_syn_ack_count": self.syn_ack_count,
            "conversation_rst_count": self.rst_count,
            "conversation_to_responder_bytes": self.to_responder_bytes,
            "conversation_to_initiator_bytes": self.to_initiator_bytes,
            "conversation_to_responder_packets": self.to_responder_packets,
            "conversation_to_initiator_packets": self.to_initiator_packets,
        }


@dataclass(frozen=True)
class ConversationDeltaV2:
    """Versioned cumulative conversation input consumed by stateful detectors."""

    contract_version: int
    key: ConversationKey
    generation: int
    event_time: float
    first_seen: float
    initiator: Endpoint
    responder: Endpoint
    direction: str
    packet_delta: int
    byte_delta: int
    syn_delta: int
    syn_ack_delta: int
    rst_delta: int
    to_responder_packets: int
    to_responder_bytes: int
    to_initiator_packets: int
    to_initiator_bytes: int
    syn_count: int
    syn_ack_count: int
    rst_count: int
    established: bool
    application: Dict
    backend: str
    source_type: str


class ConversationTracker:
    def __init__(self, maximum: int = 100_000):
        self.maximum = max(100, int(maximum))
        self.states: Dict[ConversationKey, ConversationState] = {}
        self._evicted_states = OrderedDict()
        self._pending_evictions = deque(
            maxlen=max(100, min(self.maximum, 1_000))
        )
        self.had_evictions = False
        self.evidence_lost = False

    def update(self, event: PacketEvent) -> Dict:
        metadata, _delta = self.update_with_delta(event)
        return metadata

    def update_with_delta(self, event: PacketEvent) -> Tuple[Dict, ConversationDeltaV2]:
        key = ConversationKey.from_event(event)
        state = self.states.get(key)
        source = (str(event.src_ip), int(event.src_port or 0))
        destination = (str(event.dst_ip), int(event.dst_port or 0))
        if state is None:
            state = self._evicted_states.pop(key, None)
            if state is None:
                flags = str(event.flags or "")
                initial_syn_ack = "S" in flags and "A" in flags
                state = ConversationState(
                    key=key,
                    initiator=destination if initial_syn_ack else source,
                    responder=source if initial_syn_ack else destination,
                    first_seen=float(event.timestamp),
                    last_seen=float(event.timestamp),
                )
            self.states[key] = state
        before_syn = state.syn_count
        before_syn_ack = state.syn_ack_count
        before_rst = state.rst_count
        direction = state.update(event)
        application = dict(event.l7_info or {})
        for name, value in application.items():
            if name not in state.application and value not in (None, "", [], {}):
                state.application[name] = value
        self._evict_if_needed()
        delta = ConversationDeltaV2(
            contract_version=2,
            key=key,
            generation=state.generation,
            event_time=float(event.timestamp),
            first_seen=state.first_seen,
            initiator=state.initiator,
            responder=state.responder,
            direction=direction,
            packet_delta=1,
            byte_delta=int(event.size or 0),
            syn_delta=state.syn_count - before_syn,
            syn_ack_delta=state.syn_ack_count - before_syn_ack,
            rst_delta=state.rst_count - before_rst,
            to_responder_packets=state.to_responder_packets,
            to_responder_bytes=state.to_responder_bytes,
            to_initiator_packets=state.to_initiator_packets,
            to_initiator_bytes=state.to_initiator_bytes,
            syn_count=state.syn_count,
            syn_ack_count=state.syn_ack_count,
            rst_count=state.rst_count,
            established=state.established,
            application=dict(state.application),
            backend=str(event.backend or "python"),
            source_type=str(event.source_type or "network"),
        )
        return state.flow_metadata(event, direction), delta

    def enrich_delta(self, delta: ConversationDeltaV2, metadata: Dict) -> ConversationDeltaV2:
        """Attach parser-confirmed metadata before stateful detection."""
        state = self.states.get(delta.key)
        additions = {
            str(name): value
            for name, value in dict(metadata or {}).items()
            if value not in (None, "", [], {})
        }
        if state is not None:
            state.application.update(additions)
            application = dict(state.application)
        else:
            application = {**dict(delta.application), **additions}
        return ConversationDeltaV2(
            **{
                **delta.__dict__,
                "application": application,
            }
        )

    def finalize(self) -> Tuple[ConversationDeltaV2, ...]:
        return tuple(
            self._final_delta(state)
            for state in sorted(
                self.states.values(),
                key=lambda value: (value.last_seen, repr(value.key)),
            )
        )

    @property
    def pending_eviction_count(self) -> int:
        return len(self._pending_evictions)

    def drain_evicted(self, limit: int = 256) -> Tuple[ConversationDeltaV2, ...]:
        drained = []
        for _index in range(max(1, min(int(limit), 1_000))):
            if not self._pending_evictions:
                break
            drained.append(self._pending_evictions.popleft())
        return tuple(drained)

    def expire(self, before: float) -> None:
        for key in [key for key, state in self.states.items() if state.last_seen < before]:
            self.states.pop(key, None)

    def _evict_if_needed(self) -> None:
        overflow = len(self.states) - self.maximum
        if overflow <= 0:
            return
        oldest = sorted(self.states.items(), key=lambda item: item[1].last_seen)[:overflow]
        for key, state in oldest:
            self.states.pop(key, None)
            self.had_evictions = True
            if len(self._pending_evictions) == self._pending_evictions.maxlen:
                self.evidence_lost = True
            self._pending_evictions.append(self._final_delta(state))
            self._evicted_states[key] = state
            self._evicted_states.move_to_end(key)
            if len(self._evicted_states) > self.maximum:
                self._evicted_states.popitem(last=False)
                self.evidence_lost = True

    @staticmethod
    def _final_delta(state: ConversationState) -> ConversationDeltaV2:
        return ConversationDeltaV2(
            contract_version=2,
            key=state.key,
            generation=state.generation,
            event_time=state.last_seen,
            first_seen=state.first_seen,
            initiator=state.initiator,
            responder=state.responder,
            direction="final",
            packet_delta=0,
            byte_delta=0,
            syn_delta=0,
            syn_ack_delta=0,
            rst_delta=0,
            to_responder_packets=state.to_responder_packets,
            to_responder_bytes=state.to_responder_bytes,
            to_initiator_packets=state.to_initiator_packets,
            to_initiator_bytes=state.to_initiator_bytes,
            syn_count=state.syn_count,
            syn_ack_count=state.syn_ack_count,
            rst_count=state.rst_count,
            established=state.established,
            application=dict(state.application),
            backend=state.backend,
            source_type=state.source_type,
        )

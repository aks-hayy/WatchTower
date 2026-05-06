from dataclasses import dataclass, field
from typing import Tuple, Dict, List, Optional
import time
import math


@dataclass
class PacketEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: str
    l7_info: Dict = field(default_factory=dict)
    raw: Optional[bytes] = None
    interface: str = "auto"


@dataclass
class WindowSnapshot:
    window_start: float
    window_end: float
    total_flows: int
    total_packets: int
    total_bytes: int
    protocol_distribution: Dict[str, int]
    protocol_entropy: float
    # Anomaly scores
    behavior_score: float = 0.0
    threat_score: float = 0.0
    final_score: float = 0.0
    # additional computed distributions for dashboard
    port_distribution: Dict[int, int] = field(default_factory=dict)
    top_talkers: Dict[str, int] = field(default_factory=dict)
    traffic_timeline: Dict[int, Dict[str, int]] = field(default_factory=dict)
    alerts: List['AlertRecord'] = field(default_factory=list)
    interface: str = "auto"


@dataclass
class AlertRecord:
    timestamp: float
    entity_type: str  # "FLOW", "HOST", "NETWORK"
    entity_id: str
    behavior_score: float
    threat_score: float
    final_score: float
    severity: str  # "NORMAL", "SUSPICIOUS", "HIGH", "CRITICAL"
    explanation: str
    recommended_action: str


@dataclass
class FlowAggregate:
    flow_id: Tuple
    start_time: float
    last_seen: float

    packet_count: int = 0
    byte_count: int = 0

    packet_sizes: List[int] = field(default_factory=list)
    arrival_times: List[float] = field(default_factory=list)
    l7_metadata: Dict = field(default_factory=dict)
    raw_packets: List[bytes] = field(default_factory=list)

    tcp_syn_count: int = 0
    tcp_rst_count: int = 0
    
    # Track when specific alert types were last triggered for this flow
    alert_history: Dict[str, float] = field(default_factory=dict)

    reassembled_to_server: Optional[bytes] = None
    reassembled_to_client: Optional[bytes] = None

    def update(self, size, timestamp, flags=None, l7_info=None, raw=None):
        self.packet_count += 1
        self.byte_count += size
        if len(self.packet_sizes) < 500:
            self.packet_sizes.append(size)
        if len(self.arrival_times) < 500:
            self.arrival_times.append(timestamp)
        self.last_seen = timestamp
        
        if raw and len(self.raw_packets) < 100: # Limit raw packets stored per flow
            self.raw_packets.append(raw)

        if flags:
            if "S" in flags and "A" not in flags: # Pure SYN (request)
                self.tcp_syn_count += 1
            if "R" in flags:
                self.tcp_rst_count += 1
        
        if l7_info:
            for k, v in l7_info.items():
                if k not in self.l7_metadata:
                    self.l7_metadata[k] = v
                elif isinstance(v, list):
                    if not isinstance(self.l7_metadata[k], list):
                        self.l7_metadata[k] = [self.l7_metadata[k]]
                    if v[0] not in self.l7_metadata[k]:
                        self.l7_metadata[k].extend(v)
                elif v != self.l7_metadata[k]:
                    if not isinstance(self.l7_metadata[k], list):
                        self.l7_metadata[k] = [self.l7_metadata[k]]
                    if v not in self.l7_metadata[k]:
                        self.l7_metadata[k].append(v)

    def duration(self):
        return self.last_seen - self.start_time

    def avg_packet_size(self):
        if not self.packet_sizes:
            return 0
        return sum(self.packet_sizes) / len(self.packet_sizes)

    def packet_size_variance(self):
        if len(self.packet_sizes) < 2:
            return 0
        mean = self.avg_packet_size()
        return sum((x - mean) ** 2 for x in self.packet_sizes) / len(self.packet_sizes)

    def interarrival_stats(self):
        if len(self.arrival_times) < 2:
            return 0, 0

        diffs = [
            self.arrival_times[i] - self.arrival_times[i - 1]
            for i in range(1, len(self.arrival_times))
        ]
        mean = sum(diffs) / len(diffs)
        var = sum((x - mean) ** 2 for x in diffs) / len(diffs)
        return mean, math.sqrt(var)

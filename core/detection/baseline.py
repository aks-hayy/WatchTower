"""Bounded behavioral feature baselines for WatchTower scoring V2."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Dict, Iterable, List, Optional


MATURITY_SECONDS = 7 * 86400
MATURITY_WINDOWS = 200
MAX_QUANTILE_SAMPLES = 256


@dataclass
class OnlineFeatureStats:
    """Welford/EWMA statistics with a deterministic bounded quantile sample."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0
    ewma: float = 0.0
    ewma_variance: float = 0.0
    samples: List[float] = field(default_factory=list)

    def update(self, value: float, alpha: float = 0.10) -> None:
        value = float(value)
        if not math.isfinite(value):
            raise ValueError("baseline value must be finite")
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)
        if self.count == 1:
            self.ewma = value
        else:
            previous = self.ewma
            self.ewma = alpha * value + (1.0 - alpha) * previous
            self.ewma_variance = (1.0 - alpha) * (
                self.ewma_variance + alpha * (value - previous) ** 2
            )
        if len(self.samples) < MAX_QUANTILE_SAMPLES:
            self.samples.append(value)
        else:
            # Deterministic reservoir replacement keeps recomputation stable.
            slot = (self.count * 2654435761) % MAX_QUANTILE_SAMPLES
            self.samples[slot] = value

    @property
    def variance(self) -> float:
        return self.m2 / max(1, self.count - 1)

    def percentile(self, percentile: float) -> float:
        if not self.samples:
            return 0.0
        values = sorted(self.samples)
        position = max(0, min(len(values) - 1, round((len(values) - 1) * percentile)))
        return float(values[position])

    def to_state(self) -> Dict:
        return {
            "count": self.count, "mean": self.mean, "m2": self.m2,
            "ewma": self.ewma, "ewma_variance": self.ewma_variance,
            "samples": self.samples[-MAX_QUANTILE_SAMPLES:],
        }

    @classmethod
    def from_state(cls, state: Optional[Dict]) -> "OnlineFeatureStats":
        state = state or {}
        return cls(
            count=int(state.get("count") or 0), mean=float(state.get("mean") or 0.0),
            m2=float(state.get("m2") or 0.0), ewma=float(state.get("ewma") or 0.0),
            ewma_variance=float(state.get("ewma_variance") or 0.0),
            samples=[float(value) for value in (state.get("samples") or [])][-MAX_QUANTILE_SAMPLES:],
        )


def baseline_maturity(sample_count: int, first_sample_at: float, last_sample_at: float) -> Dict:
    age = max(0.0, float(last_sample_at or 0) - float(first_sample_at or 0))
    mature = int(sample_count or 0) >= MATURITY_WINDOWS and age >= MATURITY_SECONDS
    return {
        "mature": mature,
        "sample_count": int(sample_count or 0),
        "age_days": round(age / 86400.0, 2),
        "confidence_cap": 1.0 if mature else 0.35,
        "contribution_cap": 100.0 if mature else 10.0,
    }


def host_window_features(flows: Iterable[object]) -> Dict[str, Dict[str, float]]:
    """Produce deterministic directional host features from one five-minute window."""
    result: Dict[str, Dict[str, float]] = {}
    peers: Dict[str, set] = {}
    ports: Dict[str, set] = {}
    for flow in flows:
        src, dst, _sport, dport, _protocol = flow.flow_id
        values = result.setdefault(src, {
            "outbound_bytes": 0.0, "packet_count": 0.0, "flow_count": 0.0,
            "syn_count": 0.0, "syn_ack_count": 0.0, "dns_queries": 0.0,
            "request_periodicity": 0.0,
        })
        values["outbound_bytes"] += float(flow.byte_count or 0)
        values["packet_count"] += float(flow.packet_count or 0)
        values["flow_count"] += 1.0
        values["syn_count"] += float(getattr(flow, "tcp_syn_count", 0) or 0)
        values["syn_ack_count"] += float(getattr(flow, "tcp_syn_ack_count", 0) or 0)
        if int(dport or 0) == 53:
            values["dns_queries"] += float(flow.packet_count or 0)
        mean, deviation = flow.interarrival_stats()
        if mean > 0:
            values["request_periodicity"] = max(values["request_periodicity"], 1.0 - min(1.0, deviation / mean))
        peers.setdefault(src, set()).add(dst)
        ports.setdefault(src, set()).add(int(dport or 0))
    for subject, values in result.items():
        values["peer_cardinality"] = float(len(peers.get(subject, ())))
        values["port_cardinality"] = float(len(ports.get(subject, ())))
        values["syn_response_ratio"] = values.pop("syn_ack_count") / max(1.0, values["syn_count"])
    return result


def learning_allowed(*, generated_probe=False, complete=True, confirmed_threat=False,
                     sensor_drop_ratio=0.0, max_drop_ratio=0.01) -> bool:
    return not generated_probe and complete and not confirmed_threat and float(sensor_drop_ratio) <= max_drop_ratio

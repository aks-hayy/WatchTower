"""Shared bounded state for live and offline host behavior detections."""

from collections import defaultdict, deque
from functools import lru_cache
from ipaddress import ip_address
import math
import statistics
from typing import Deque, Dict, Set, Tuple

from core.forensics.models import ForensicAlert


ADMIN_PORTS = {22, 135, 139, 445, 3389, 5900, 5985, 5986}
MAX_STATE_KEYS = 4096


@lru_cache(maxsize=MAX_STATE_KEYS)
def _address(value: str):
    try:
        return ip_address(value)
    except ValueError:
        return None


@lru_cache(maxsize=MAX_STATE_KEYS)
def _internal(value: str) -> bool:
    address = _address(value)
    return bool(
        address
        and (address.is_private or address.is_link_local or address.is_loopback)
    )


def _broadcast(address) -> bool:
    """Exclude IPv4 limited and directed broadcast destinations."""
    return bool(
        address
        and address.version == 4
        and (str(address) == "255.255.255.255" or int(address) & 0xFF == 0xFF)
    )


def _alert(kind, severity, score, explanation, evidence, timestamp):
    return ForensicAlert(timestamp, kind, severity, score, explanation, evidence)


class StatefulBehaviorEngine:
    WINDOW_SECONDS = 60.0
    EXFIL_COOLDOWN_SECONDS = 3600.0
    MAX_STATE_KEYS = MAX_STATE_KEYS

    def __init__(self, trusted_scanners=None):
        self.trusted_scanners = set(trusted_scanners or ())
        self.reset()

    def reset(self):
        self.attempts: Dict[Tuple, Dict] = {}
        self.last_alert: Dict[Tuple, float] = {}
        self.last_alert_cooldowns: Dict[Tuple, float] = {}
        self.syn_buckets: Dict[Tuple[str, str], Dict[int, int]] = defaultdict(dict)
        self.beacon_events: Dict[Tuple, Deque[Tuple[float, int]]] = defaultdict(
            deque
        )
        self.beacon_interval_totals: Dict[Tuple, list[float]] = {}
        self.peer_seen: Set[Tuple[str, str]] = set()
        self.conversation_novelty: Dict[Tuple, bool] = {}
        self.auth_signals: Dict[str, float] = {}

    def note_signal(self, subject: str, signal: str, timestamp: float) -> None:
        if signal == "auth_failure":
            self.auth_signals[str(subject)] = float(timestamp)
            self._bound_mapping(self.auth_signals)

    @classmethod
    def _bound_mapping(cls, values: Dict) -> None:
        overflow = len(values) - cls.MAX_STATE_KEYS
        for key in list(values)[:max(0, overflow)]:
            values.pop(key, None)

    def _append_beacon_event(
        self,
        conversation_id: Tuple,
        now: float,
        byte_delta: int,
    ) -> tuple[Deque[Tuple[float, int]], list[float]]:
        events = self.beacon_events[conversation_id]
        totals = self.beacon_interval_totals.setdefault(
            conversation_id, [0.0, 0.0]
        )

        def remove_oldest() -> None:
            previous = events.popleft()
            if events:
                interval = events[0][0] - previous[0]
                totals[0] -= interval
                totals[1] -= interval * interval

        while len(events) >= 512:
            remove_oldest()
        while events and now - events[0][0] > 7200.0:
            remove_oldest()
        if events:
            interval = now - events[-1][0]
            totals[0] += interval
            totals[1] += interval * interval
        events.append((now, byte_delta))

        overflow = len(self.beacon_events) - self.MAX_STATE_KEYS
        for key in list(self.beacon_events)[:max(0, overflow)]:
            self.beacon_events.pop(key, None)
            self.beacon_interval_totals.pop(key, None)
        return events, totals

    def detect_conversation(self, delta) -> list[ForensicAlert]:
        """Evaluate one production conversation generation deterministically."""
        if delta is None or int(getattr(delta, "contract_version", 0)) != 2:
            return []
        now = float(delta.event_time)
        src, sport = delta.initiator
        dst, dport = delta.responder
        protocol = str(delta.key.protocol).upper()
        conversation_id = (
            delta.key.sensor_node_id, delta.key.source, delta.key.interface,
            delta.key.session_id, protocol, delta.key.endpoint_a, delta.key.endpoint_b,
        )
        pair = (src, dst)
        if conversation_id not in self.conversation_novelty:
            self.conversation_novelty[conversation_id] = pair not in self.peer_seen
            self.peer_seen.add(pair)
            if len(self.peer_seen) > self.MAX_STATE_KEYS:
                self.peer_seen.remove(sorted(self.peer_seen)[0])
            self._bound_mapping(self.conversation_novelty)
        novel = self.conversation_novelty[conversation_id]
        alerts = []

        scanner_exempt = src in self.trusted_scanners
        attempt_key = (
            delta.key.session_id,
            src,
            dst,
            int(dport),
            int(sport),
        )
        existing_attempt = self.attempts.get(attempt_key)
        new_scan_attempt = (
            protocol == "TCP"
            and delta.syn_delta
            and not scanner_exempt
            and _internal(src)
            and _internal(dst)
        )
        attempt_changed = False
        if new_scan_attempt:
            self.attempts[attempt_key] = {
                "timestamp": now,
                "src": src,
                "dst": dst,
                "port": int(dport),
                "established": bool(delta.established),
                "peer_novelty": novel,
                "auth_failure": now - self.auth_signals.get(src, -10_000.0) <= 300.0,
                "role_policy": bool(delta.application.get("role_policy_violation")),
            }
            attempt_changed = True
        elif existing_attempt is not None:
            updated_attempt = {
                **existing_attempt,
                "established": (
                    bool(existing_attempt["established"])
                    or bool(delta.established)
                ),
                "peer_novelty": (
                    bool(existing_attempt["peer_novelty"]) or novel
                ),
                "auth_failure": (
                    bool(existing_attempt["auth_failure"])
                    or now - self.auth_signals.get(src, -10_000.0) <= 300.0
                ),
                "role_policy": (
                    bool(existing_attempt["role_policy"])
                    or bool(delta.application.get("role_policy_violation"))
                ),
            }
            if updated_attempt != existing_attempt:
                self.attempts[attempt_key] = updated_attempt
                attempt_changed = True

        if attempt_changed:
            self.attempts = {
                key: value for key, value in self.attempts.items()
                if now - float(value["timestamp"]) <= self.WINDOW_SECONDS
            }
            self._bound_mapping(self.attempts)

            source_attempts = [
                value for value in self.attempts.values()
                if value["src"] == src
            ]
            by_target = defaultdict(list)
            by_service = defaultdict(list)
            for attempt in source_attempts:
                by_target[attempt["dst"]].append(attempt)
                by_service[attempt["port"]].append(attempt)
            for target, attempts in by_target.items():
                ports = {item["port"] for item in attempts}
                response_ratio = (
                    sum(item["established"] for item in attempts)
                    / max(1, len(attempts))
                )
                if (
                    len(ports) >= 20
                    and response_ratio < 0.20
                    and self._emit_once((src, "vertical", target), now)
                ):
                    alerts.append(_alert(
                        "PORT_SCAN", "MEDIUM", 30.0,
                        "One source attempted many ports on one internal target with few successful connections.",
                        {"source": src, "scan_type": "vertical", "dst_ip": target,
                         "unique_ports": len(ports), "response_ratio": round(response_ratio, 3),
                         "window_seconds": self.WINDOW_SECONDS}, now,
                    ))
            for port, attempts in by_service.items():
                targets = {item["dst"] for item in attempts}
                response_ratio = (
                    sum(item["established"] for item in attempts)
                    / max(1, len(attempts))
                )
                if (
                    len(targets) >= 20
                    and response_ratio < 0.20
                    and self._emit_once((src, "horizontal", port), now)
                ):
                    alerts.append(_alert(
                        "HORIZONTAL_SCAN", "MEDIUM", 30.0,
                        "One source attempted the same service across many internal targets with few successful connections.",
                        {"source": src, "scan_type": "horizontal", "dst_port": port,
                         "unique_hosts": len(targets), "response_ratio": round(response_ratio, 3),
                         "window_seconds": self.WINDOW_SECONDS}, now,
                    ))

            admin_attempts = [
                item for item in source_attempts if item["port"] in ADMIN_PORTS
            ]
            admin_targets = {item["dst"] for item in admin_attempts}
            lateral_evidence = sorted({
                name for name, present in {
                    "peer_novelty": any(item["peer_novelty"] for item in admin_attempts),
                    "authentication_failure": any(item["auth_failure"] for item in admin_attempts),
                    "role_policy": any(item["role_policy"] for item in admin_attempts),
                }.items() if present
            })
            if (
                len(admin_targets) >= 5
                and lateral_evidence
                and self._emit_once((src, "lateral"), now, 300.0)
            ):
                alerts.append(_alert(
                    "LATERAL_MOVEMENT", "HIGH", 45.0,
                    "A private host contacted administrative services on multiple new internal systems.",
                    {"source": src, "destination_count": len(admin_targets),
                     "admin_ports": sorted({item["port"] for item in admin_attempts}),
                     "corroborators": lateral_evidence}, now,
                ))

        if protocol == "TCP" and delta.syn_delta and not scanner_exempt:
            second = int(now)
            second_counts = self.syn_buckets[(src, dst)]
            second_counts[second] = second_counts.get(second, 0) + int(delta.syn_delta)
            for timestamp in tuple(second_counts):
                if timestamp < second - 3:
                    second_counts.pop(timestamp, None)
            self._bound_mapping(self.syn_buckets)
            seconds = sorted(second_counts)
            sustained = any(
                all(second_counts.get(start + offset, 0) >= 1000 for offset in range(3))
                for start in seconds
            )
            response_ratio = float(delta.syn_ack_count) / max(1, int(delta.syn_count))
            if sustained and response_ratio < 0.10 and self._emit_once((src, "syn_flood", dst), now, 300.0):
                alerts.append(_alert(
                    "SYN_FLOOD", "HIGH", 55.0,
                    "Sustained SYN rate exceeded 1,000/s for three seconds with few SYN-ACK responses.",
                    {"source": src, "dst_ip": dst, "syn_count": sum(second_counts.values()),
                     "syn_ack_ratio": round(response_ratio, 4), "window_seconds": 3}, now,
                ))

        outbound = float(delta.to_responder_bytes)
        inbound = float(delta.to_initiator_bytes)
        baseline_p99 = float(delta.application.get("outbound_bytes_p99") or 0.0)
        threshold = max(100 * 1024 * 1024, 3.0 * baseline_p99)
        ratio = outbound / max(1.0, inbound)
        destination = None
        external_transfer = False
        if outbound >= threshold and ratio >= 4.0 and novel and _internal(src):
            destination = _address(dst)
            external_transfer = bool(destination and destination.is_global)
        if (external_transfer
                and self._emit_once((src, "exfil", dst), now, self.EXFIL_COOLDOWN_SECONDS)):
            cold_start = baseline_p99 <= 0.0
            strong = bool(
                delta.application.get("intel_match")
                or delta.application.get("protocol_corroboration")
            )
            severity = "MEDIUM" if cold_start and not strong else "HIGH"
            alerts.append(_alert(
                "EXFILTRATION", severity, 30.0 if severity == "MEDIUM" else 45.0,
                "Outbound transfer exceeded the host baseline and was strongly directional.",
                {"source": src, "dst_ip": dst, "bytes": int(outbound),
                 "outbound_inbound_ratio": round(ratio, 2), "threshold": threshold,
                 "rare_destination": True, "cold_start": cold_start,
                 "strong_corroboration": strong}, now,
            ))

        excluded_ports = {53, 67, 68, 123, 137, 138, 1900, 5353}
        cast_ports = {8008, 8009}
        common_ports = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 587, 993, 995, 3389}
        generated = delta.application.get("generated_by") == "WatchTower"
        known_heartbeat = bool(delta.application.get("known_heartbeat"))
        application_protocol = str(delta.application.get("application_protocol") or "").lower()
        discovery_protocol = application_protocol in {
            "cast", "google cast", "mdns", "ssdp", "llmnr", "dhcp", "ntp",
        }
        cast_service = bool({sport, dport} & cast_ports) and _internal(src) and _internal(dst)
        beacon_candidate = (
            delta.packet_delta
            and protocol in {"TCP", "UDP"}
            and int(dport) not in excluded_ports
            and not generated
            and not known_heartbeat
            and not discovery_protocol
            and not cast_service
        )
        if beacon_candidate:
            destination = destination or _address(dst)
            excluded_address = (
                destination is None
                or destination.is_multicast
                or destination.is_unspecified
                or destination.is_link_local
                or _broadcast(destination)
            )
        else:
            excluded_address = True
        if beacon_candidate and not excluded_address:
            events, interval_totals = self._append_beacon_event(
                conversation_id, now, int(delta.byte_delta)
            )
            if len(events) >= 20 and events[-1][0] - events[0][0] >= 120.0:
                interval_count = len(events) - 1
                average = interval_totals[0] / interval_count
                if average > 0 and interval_count > 1:
                    variance = max(
                        0.0,
                        (
                            interval_totals[1]
                            - interval_totals[0] * interval_totals[0] / interval_count
                        )
                        / (interval_count - 1),
                    )
                    variation = math.sqrt(variance) / average
                else:
                    variation = float("inf")
                corroborators = set()
                if novel:
                    corroborators.add("destination_novelty")
                if delta.to_initiator_packets == 0:
                    corroborators.add("response_anomaly")
                if int(dport) not in common_ports:
                    corroborators.add("protocol_semantic_anomaly")
                if delta.application.get("intel_match"):
                    corroborators.add("intelligence_match")
                if average > 0.5 and variation < 0.20 and len(corroborators) >= 2 \
                        and self._emit_once((src, "beacon", dst, dport), now, 3600.0):
                    alerts.append(_alert(
                        "BEACONING", "MEDIUM", 30.0,
                        "Periodic traffic had multiple independent beaconing corroborators.",
                        {"source": src, "dst_ip": dst, "dst_port": int(dport),
                         "avg_interval": round(average, 4),
                         "coefficient_of_variation": round(variation, 4),
                         "sample_count": len(events),
                         "duration": events[-1][0] - events[0][0],
                         "corroborators": sorted(corroborators)}, now,
                    ))
        return alerts

    def _emit_once(self, key: Tuple, now: float, cooldown: float = 60.0) -> bool:
        if now - self.last_alert.get(key, -10_000.0) < cooldown:
            return False
        if key not in self.last_alert and len(self.last_alert) >= self.MAX_STATE_KEYS:
            expired = [
                candidate
                for candidate, timestamp in self.last_alert.items()
                if now - timestamp >= self.last_alert_cooldowns.get(
                    candidate,
                    60.0,
                )
            ]
            for candidate in expired:
                self.last_alert.pop(candidate, None)
                self.last_alert_cooldowns.pop(candidate, None)
        self.last_alert[key] = now
        self.last_alert_cooldowns[key] = cooldown
        overflow = len(self.last_alert) - self.MAX_STATE_KEYS
        if overflow > 0:
            victims = sorted(
                self.last_alert,
                key=lambda candidate: (
                    self.last_alert[candidate]
                    + self.last_alert_cooldowns.get(candidate, 60.0),
                    repr(candidate),
                ),
            )[:overflow]
            for candidate in victims:
                self.last_alert.pop(candidate, None)
                self.last_alert_cooldowns.pop(candidate, None)
        return True

    def detect(self, flow) -> list[ForensicAlert]:
        if flow is None:
            return []
        src, dst, _sport, dport, protocol = flow.flow_id
        now = float(flow.last_seen or 0.0)
        metadata = flow.l7_metadata or {}
        alerts = []

        syn_count = int(flow.tcp_syn_count or metadata.get("conversation_syn_count") or 0)
        established = bool(metadata.get("conversation_established"))
        syn_ack_count = int(metadata.get("conversation_syn_ack_count") or flow.tcp_syn_ack_count or 0)
        duration = max(0.0, float(flow.last_seen or 0.0) - float(flow.start_time or 0.0))
        if protocol == "TCP" and duration >= 3.0 and syn_count:
            syn_rate = syn_count / duration
            response_ratio = syn_ack_count / max(1, syn_count)
            if syn_rate >= 1000.0 and response_ratio < 0.10 and self._emit_once((src, "syn_flood", dst), now):
                alerts.append(_alert(
                    "SYN_FLOOD", "HIGH", 55.0,
                    "Sustained SYN rate exceeded 1,000/s with fewer than 10% SYN-ACK responses.",
                    {"source": src, "dst_ip": dst, "syn_count": syn_count,
                     "duration_seconds": duration, "syn_rate": round(syn_rate, 2),
                     "syn_ack_ratio": round(response_ratio, 4)}, now,
                ))

        if (protocol == "TCP" and syn_count and src not in self.trusted_scanners
                and _internal(src) and _internal(dst)):
            self.attempts[flow.flow_id] = {
                "timestamp": now, "src": src, "dst": dst, "port": int(dport),
                "established": established, "peer_novelty": bool(metadata.get("peer_novelty")),
                "auth_failure": bool(metadata.get("auth_failure")),
                "role_policy": bool(metadata.get("role_policy_violation")),
            }
        self.attempts = {
            key: value for key, value in self.attempts.items()
            if now - float(value["timestamp"]) <= self.WINDOW_SECONDS
        }

        source_attempts = [value for value in self.attempts.values() if value["src"] == src]
        by_target = defaultdict(list)
        by_service = defaultdict(list)
        for attempt in source_attempts:
            by_target[attempt["dst"]].append(attempt)
            by_service[attempt["port"]].append(attempt)

        for target, attempts in by_target.items():
            ports = {item["port"] for item in attempts}
            response_ratio = sum(item["established"] for item in attempts) / max(1, len(attempts))
            if len(ports) >= 20 and response_ratio < 0.20 and self._emit_once((src, "vertical", target), now):
                alerts.append(_alert(
                    "PORT_SCAN", "MEDIUM", 30.0,
                    "One source attempted many ports on one internal target with few successful connections.",
                    {"source": src, "scan_type": "vertical", "dst_ip": target,
                     "unique_ports": len(ports), "response_ratio": round(response_ratio, 3),
                     "window_seconds": self.WINDOW_SECONDS}, now,
                ))

        for port, attempts in by_service.items():
            targets = {item["dst"] for item in attempts}
            response_ratio = sum(item["established"] for item in attempts) / max(1, len(attempts))
            if len(targets) >= 20 and response_ratio < 0.20 and self._emit_once((src, "horizontal", port), now):
                alerts.append(_alert(
                    "HORIZONTAL_SCAN", "MEDIUM", 30.0,
                    "One source attempted the same service across many internal targets with few successful connections.",
                    {"source": src, "scan_type": "horizontal", "dst_port": port,
                     "unique_hosts": len(targets), "response_ratio": round(response_ratio, 3),
                     "window_seconds": self.WINDOW_SECONDS}, now,
                ))

        admin_attempts = [item for item in source_attempts if item["port"] in ADMIN_PORTS]
        admin_targets = {item["dst"] for item in admin_attempts}
        lateral_evidence = sorted({
            name for name, present in {
                "peer_novelty": any(item["peer_novelty"] for item in admin_attempts),
                "authentication_failure": any(item["auth_failure"] for item in admin_attempts),
                "role_policy": any(item["role_policy"] for item in admin_attempts),
            }.items() if present
        })
        if (len(admin_targets) >= 5 and lateral_evidence
                and self._emit_once((src, "lateral"), now, 300.0)):
            alerts.append(_alert(
                "LATERAL_MOVEMENT", "HIGH", 45.0,
                "A private host contacted administrative services on multiple internal systems.",
                {"source": src, "destination_count": len(admin_targets),
                 "admin_ports": sorted({item["port"] for item in admin_attempts}),
                 "corroborators": lateral_evidence}, now,
            ))

        try:
            external_transfer = _internal(src) and ip_address(dst).is_global
        except ValueError:
            external_transfer = False
        baseline_p99 = float(metadata.get("outbound_bytes_p99") or 0.0)
        threshold = max(100 * 1024 * 1024, 3.0 * baseline_p99)
        outbound = float(flow.byte_count or 0)
        inbound = float(metadata.get("reverse_byte_count") or 0.0)
        ratio = outbound / max(1.0, inbound)
        rare = bool(metadata.get("peer_novelty"))
        strong_corroboration = bool(metadata.get("intel_match") or metadata.get("protocol_corroboration"))
        if (external_transfer and outbound >= threshold and ratio >= 4.0 and rare
                and self._emit_once((src, "exfil", dst), now, self.EXFIL_COOLDOWN_SECONDS)):
            cold_start = baseline_p99 <= 0.0
            severity = "MEDIUM" if cold_start and not strong_corroboration else "HIGH"
            alerts.append(_alert(
                "EXFILTRATION", severity, 45.0 if severity == "HIGH" else 30.0,
                "Outbound transfer exceeded the host baseline and was strongly directional.",
                {"source": src, "dst_ip": dst, "bytes": int(outbound), "direction": "outbound",
                 "outbound_inbound_ratio": round(ratio, 2), "threshold": threshold,
                 "rare_destination": True, "cold_start": cold_start,
                 "strong_corroboration": strong_corroboration}, now,
            ))

        arrivals = sorted(float(value) for value in (flow.arrival_times or ()))
        excluded_ports = {53, 67, 68, 123, 137, 138, 1900, 5353}
        common_ports = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 587, 993, 995, 3389}
        destination = _address(dst)
        application_protocol = str(metadata.get("application_protocol") or "").lower()
        excluded = (
            int(dport) in excluded_ports
            or metadata.get("generated_by") == "WatchTower"
            or bool(metadata.get("known_heartbeat"))
            or application_protocol in {"cast", "google cast", "mdns", "ssdp", "llmnr", "dhcp", "ntp"}
            or destination is None
            or destination.is_multicast
            or destination.is_unspecified
            or destination.is_link_local
            or _broadcast(destination)
        )
        if not excluded and len(arrivals) >= 20 and arrivals[-1] - arrivals[0] >= 120.0:
            intervals = [arrivals[index] - arrivals[index - 1] for index in range(1, len(arrivals))]
            average = statistics.mean(intervals)
            variation = statistics.stdev(intervals) / average if average > 0 and len(intervals) > 1 else float("inf")
            corroborators = set()
            if rare:
                corroborators.add("destination_novelty")
            if int(metadata.get("reverse_packet_count") or 0) == 0:
                corroborators.add("response_anomaly")
            if int(dport) not in common_ports:
                corroborators.add("protocol_semantic_anomaly")
            if metadata.get("intel_match"):
                corroborators.add("intelligence_match")
            if average > 0.5 and variation < 0.20 and len(corroborators) >= 2 \
                    and self._emit_once((src, "beacon", dst, int(dport)), now, 3600.0):
                alerts.append(_alert(
                    "BEACONING", "MEDIUM", 30.0,
                    "Periodic traffic had multiple independent beaconing corroborators.",
                    {"source": src, "dst_ip": dst, "dst_port": int(dport),
                     "avg_interval": round(average, 4),
                     "coefficient_of_variation": round(variation, 4),
                     "sample_count": len(arrivals),
                     "duration": arrivals[-1] - arrivals[0],
                     "corroborators": sorted(corroborators)}, now,
                ))
        return alerts

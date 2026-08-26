# core/packet_engine/processors.py

import math
import time
import os
from collections import defaultdict
from core.packet_engine.schemas import WindowSnapshot, AlertRecord
from core.constants import (
    INTERNAL_IP_PREFIXES, ALERT_COOLDOWN,
    SCAN_HIGH_SYN_COUNT, ALERT_THRESHOLD, EVIDENCE_TRIGGER
)
from core.packet_engine.utils import get_geoip_info

class StatAggregator:
    def __init__(self):
        self.protocol_distribution = defaultdict(int)
        self.port_distribution = defaultdict(int)
        self.top_talkers = defaultdict(int)
        self.timeline_buckets = {}

    def aggregate(self, flow, window_start):
        # Protocol
        proto = getattr(flow, "protocol", None) or flow.flow_id[4]
        self.protocol_distribution[proto] += flow.packet_count

        # Port
        dst_port = flow.flow_id[3]
        self.port_distribution[dst_port] += flow.packet_count

        # Talker
        src_ip = flow.flow_id[0]
        self.top_talkers[src_ip] += flow.byte_count

        # Timeline
        if getattr(flow, "timeline_buckets", None):
            for ts, bucket in flow.timeline_buckets.items():
                if ts < window_start:
                    continue
                self.timeline_buckets[ts] = {
                    "time": ts,
                    "packets": self.timeline_buckets.get(ts, {}).get("packets", 0) + int(bucket.get("packets", 0)),
                    "bytes": self.timeline_buckets.get(ts, {}).get("bytes", 0) + int(bucket.get("bytes", 0)),
                }
        elif hasattr(flow, "arrival_times"):
            for ts, size in zip(flow.arrival_times, flow.packet_sizes):
                if ts < window_start: continue
                b_time = math.floor(ts)
                if b_time not in self.timeline_buckets:
                    self.timeline_buckets[b_time] = {"time": b_time, "packets": 0, "bytes": 0}
                self.timeline_buckets[b_time]["packets"] += 1
                self.timeline_buckets[b_time]["bytes"] += size

    def compute_entropy(self):
        total = sum(self.protocol_distribution.values())
        if total == 0: return 0
        entropy = 0
        for count in self.protocol_distribution.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

class SecurityScorer:
    def __init__(self, analytics_engine, forensics_engine, behavioral_engine=None):
        self.analytics = analytics_engine
        self.forensics = forensics_engine
        self.behavioral = behavioral_engine

    def score_flow(self, flow):
        b_score = self.analytics.compute_behavior_score(flow) if self.analytics else 0.0
        t_score = 0.0
        forensic_alerts = []

        if self.forensics:
            forensic_alerts = self.forensics.analyze_flow(flow)
            for alert in forensic_alerts:
                t_score += alert.score

        # Destination enrichment is context, never a score by itself.
        dst_ip = flow.flow_id[1]
        if hasattr(flow, "tcp_syn_count") and flow.tcp_syn_count > SCAN_HIGH_SYN_COUNT:
            t_score += 30

        # GeoIP Enrichment (move to separate processor later if needed)
        if dst_ip and not any(dst_ip.startswith(p) for p in INTERNAL_IP_PREFIXES):
            if "geoip" not in flow.l7_metadata:
                flow.l7_metadata["geoip"] = get_geoip_info(dst_ip)

        return b_score, t_score, forensic_alerts

class AlertManager:
    def __init__(self):
        self.alerts = []

    def process_alerts(self, flow, b_score, t_score, forensic_alerts):
        final_score = b_score + t_score
        if final_score <= ALERT_THRESHOLD:
            return []

        now = time.time()
        new_alerts = []

        # Determine dominant threat
        threat_type = "BEHAVIORAL"
        multiplier = 1.0
        if forensic_alerts:
            dominant = max(forensic_alerts, key=lambda a: a.score)
            threat_type = dominant.type
            # Apply Subnet Role Multiplier
            if hasattr(self, 'behavioral') and self.behavioral:
                multiplier = self.behavioral.get_context_multiplier(flow.flow_id[0], threat_type)
        # Re-check threshold after multiplier
        if (final_score * multiplier) <= ALERT_THRESHOLD:
            return []

        # Deduplication
        if (now - flow.alert_history.get(threat_type, 0)) > ALERT_COOLDOWN:
            flow.alert_history[threat_type] = now
            adj_score = final_score * multiplier
            severity = "CRITICAL" if adj_score > 100 else ("HIGH" if adj_score > 80 else "SUSPICIOUS")
            
            # Findings are always attached to a real subject. There is no synthetic
            # "src->dst" entity and no second aggregate alert for the same evidence.
            for fa in forensic_alerts:
                sub_alert = AlertRecord(
                    timestamp=fa.timestamp, entity_type="FORENSIC",
                    entity_id=flow.flow_id[0], behavior_score=0,
                    threat_score=fa.score, final_score=fa.score,
                    severity=fa.severity, explanation=fa.explanation,
                    recommended_action="Run deep-dive"
                )
                new_alerts.append(sub_alert)
                self.alerts.append(sub_alert)

            if not forensic_alerts:
                behavioral_alert = AlertRecord(
                    timestamp=now, entity_type="HOST",
                    entity_id=flow.flow_id[0], behavior_score=b_score,
                    threat_score=t_score, final_score=adj_score, severity=severity,
                    explanation=f"Behavioral threshold exceeded (score: {adj_score:.1f})",
                    recommended_action="Review flow evidence",
                )
                new_alerts.append(behavioral_alert)
                self.alerts.append(behavioral_alert)
        
        return new_alerts

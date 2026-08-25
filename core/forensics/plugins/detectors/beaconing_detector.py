import statistics
from ipaddress import ip_address
from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2

class BeaconingDetector(BaseDetector):
    name = "Beaconing Detector"
    enabled = False
    manifest = DetectorManifestV2(
        detector_id="watchtower.behavior.beacon", name=name, input_kinds=("flow", "session"),
        finding_types=("behavior.beacon.suspected",), signal_family="behavior",
        correlation_group="beacon",
    )
    finding_metadata = {
        "behavior.beacon.suspected": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.75, "mitre_technique": "T1071"},
    }
    MIN_EVENTS = 20
    MIN_DURATION = 120.0
    EXCLUDED_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5353}
    COMMON_SERVICE_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 445, 587, 993, 995, 3389}
    alert_cooldown_seconds = 3600.0

    def detect(self, arrival_times: List[float] = None, flow=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not arrival_times or len(arrival_times) < self.MIN_EVENTS:
            return alerts
        if arrival_times[-1] - arrival_times[0] < self.MIN_DURATION:
            return alerts
        if flow is None:
            return alerts
        src_ip, dst_ip, _src_port, dst_port, protocol = flow.flow_id
        if int(dst_port or 0) in self.EXCLUDED_PORTS:
            return alerts
        if str(protocol).upper() not in {"TCP", "UDP"}:
            return alerts
        if flow.l7_metadata.get("generated_by") == "WatchTower" or flow.l7_metadata.get("known_heartbeat"):
            return alerts
        try:
            destination = ip_address(str(dst_ip))
            if destination.is_multicast or destination.is_unspecified or destination.is_link_local:
                return alerts
            if destination.version == 4 and str(destination).endswith(".255"):
                return alerts
        except ValueError:
            return alerts
            
        intervals = [arrival_times[i] - arrival_times[i-1] for i in range(1, len(arrival_times))]
        
        if len(intervals) < 10:
            return alerts
            
        avg_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals)
        
        coefficient_of_variation = std_dev / avg_interval if avg_interval else float("inf")
        evidence_quality = []
        if flow.packet_size_variance() <= 16.0:
            evidence_quality.append("stable_packet_sizes")
        if flow.byte_count <= max(4096, flow.packet_count * 512):
            evidence_quality.append("low_volume_periodic")
        corroborator_families = []
        if flow.l7_metadata.get("peer_novelty"):
            corroborator_families.append("destination_novelty")
        if int(flow.l7_metadata.get("session_repetitions") or 0) >= 2:
            corroborator_families.append("cross_session_recurrence")
        if int(flow.l7_metadata.get("reverse_packet_count") or 0) == 0:
            corroborator_families.append("response_anomaly")
        if int(dst_port or 0) not in self.COMMON_SERVICE_PORTS:
            corroborator_families.append("protocol_semantic_anomaly")
        if flow.l7_metadata.get("intel_match"):
            corroborator_families.append("intelligence_match")
        if avg_interval > 0.5 and coefficient_of_variation < 0.20 and len(set(corroborator_families)) >= 2:
            alerts.append(ForensicAlert(
                timestamp=arrival_times[-1],
                type="BEACONING",
                severity="MEDIUM",
                score=30.0,
                explanation=f"Periodic traffic detected (avg: {avg_interval:.2f}s, CV: {coefficient_of_variation:.4f})",
                evidence={
                    "avg_interval": avg_interval,
                    "std_dev": std_dev,
                    "coefficient_of_variation": coefficient_of_variation,
                    "sample_count": len(arrival_times),
                    "duration": arrival_times[-1] - arrival_times[0],
                    "corroborators": sorted(set(corroborator_families)),
                    "evidence_quality": evidence_quality,
                }
            ))
            
        return alerts

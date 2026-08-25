from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from ipaddress import ip_address
from core.detection.contracts import DetectorManifestV2

class ExfiltrationDetector(BaseDetector):
    name = "Data Exfiltration Detector"
    enabled = False
    manifest = DetectorManifestV2(
        detector_id="watchtower.exfiltration", name=name, input_kinds=("flow", "session"),
        finding_types=("exfil.volume_anomaly",), signal_family="behavior",
        correlation_group="exfiltration",
    )
    finding_metadata = {
        "exfil.volume_anomaly": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1041"},
    }
    COLD_START_THRESHOLD = 100 * 1024 * 1024

    def detect(self, flow=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not flow:
            return alerts
            
        src_ip, dst_ip = flow.flow_id[0], flow.flow_id[1]
        try:
            src_internal = ip_address(src_ip).is_private
            dst_external = ip_address(dst_ip).is_global
        except ValueError:
            return alerts

        baseline_p99 = float(flow.l7_metadata.get("outbound_bytes_p99") or 0.0)
        threshold = max(self.COLD_START_THRESHOLD, baseline_p99 * 3.0)
        inbound = float(flow.l7_metadata.get("reverse_byte_count") or 0.0)
        ratio = float(flow.byte_count) / max(1.0, inbound)
        rare_destination = bool(flow.l7_metadata.get("peer_novelty", baseline_p99 > 0))
        if src_internal and dst_external and flow.byte_count >= threshold and ratio >= 4.0 and rare_destination:
             alerts.append(ForensicAlert(
                timestamp=flow.last_seen,
                type="EXFILTRATION",
                severity="HIGH",
                score=40.0,
                explanation=f"Outbound transfer exceeded the host baseline ({flow.byte_count / (1024*1024):.1f} MB)",
                evidence={"bytes": flow.byte_count, "dst_ip": dst_ip, "direction": "outbound", "outbound_inbound_ratio": round(ratio, 2), "threshold": threshold, "rare_destination": rare_destination}
            ))
            
        return alerts

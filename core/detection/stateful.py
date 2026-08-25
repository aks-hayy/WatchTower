"""Bounded host/session detections evaluated across a completed flow set."""

from collections import defaultdict
from ipaddress import ip_address
from typing import Dict, List, Tuple

from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2


def _internal(value: str) -> bool:
    try:
        address = ip_address(value)
        return address.is_private or address.is_link_local or address.is_loopback
    except ValueError:
        return False


class StatefulHostDetector:
    """Detect corroborated recon, SYN floods, and directional exfiltration."""

    name = "Stateful Host Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.stateful.host", name=name,
        input_kinds=("session",),
        finding_types=("recon.host_scan", "recon.port_scan", "recon.syn_flood", "exfil.volume_anomaly"),
        signal_family="behavior", correlation_group="stateful-host",
    )
    finding_metadata = {
        "recon.host_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1046", "correlation_group": "recon"},
        "recon.port_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1046", "correlation_group": "recon"},
        "recon.syn_flood": {"category": "THREAT", "impact": "HIGH", "confidence": 0.9, "mitre_technique": "T1498", "correlation_group": "availability"},
        "exfil.volume_anomaly": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1041", "correlation_group": "exfiltration"},
    }

    def __init__(self, horizontal_target_threshold: int = 20, vertical_port_threshold: int = 20,
                 exfiltration_threshold: int = 100 * 1024 * 1024,
                 trusted_scanners=None):
        self.horizontal_target_threshold = horizontal_target_threshold
        self.vertical_port_threshold = vertical_port_threshold
        self.exfiltration_threshold = exfiltration_threshold
        self.trusted_scanners = set(trusted_scanners or ())

    def reset(self, source: str = None) -> None:
        return None

    def finalize(self, **kwargs):
        return []

    def analyze(self, flow_table: Dict[tuple, object]) -> List[Tuple[str, ForensicAlert]]:
        targets_by_host_port = defaultdict(set)
        ports_by_host_target = defaultdict(set)
        external_bytes = defaultdict(int)
        external_reverse_bytes = defaultdict(int)
        destination_novelty = {}
        last_seen = defaultdict(float)

        for flow_id, flow in flow_table.items():
            src_ip, dst_ip, _src_port, dst_port, _protocol = flow_id
            last_seen[src_ip] = max(last_seen[src_ip], float(flow.last_seen or 0.0))
            if _internal(src_ip) and _internal(dst_ip):
                targets_by_host_port[(src_ip, dst_port)].add(dst_ip)
                ports_by_host_target[(src_ip, dst_ip)].add(dst_port)
            elif _internal(src_ip) and not _internal(dst_ip):
                external_bytes[(src_ip, dst_ip)] += int(flow.byte_count or 0)
                external_reverse_bytes[(src_ip, dst_ip)] += int(flow.l7_metadata.get("reverse_byte_count") or 0)
                destination_novelty[(src_ip, dst_ip)] = bool(flow.l7_metadata.get("peer_novelty"))

        alerts = []
        for flow in flow_table.values():
            duration = max(1.0, float(flow.last_seen or 0.0) - float(flow.start_time or 0.0))
            syn_count = int(getattr(flow, "tcp_syn_count", 0) or 0)
            syn_ack_count = int(getattr(flow, "tcp_syn_ack_count", 0) or 0)
            if duration >= 3.0 and syn_count / duration >= 1000.0 and syn_ack_count / max(1, syn_count) < 0.10:
                src_ip, dst_ip = flow.flow_id[0], flow.flow_id[1]
                alerts.append((src_ip, ForensicAlert(
                    timestamp=float(flow.last_seen or 0.0), type="SYN_FLOOD", severity="HIGH", score=55.0,
                    explanation="Sustained SYN rate exceeded 1,000/s with fewer than 10% SYN-ACK responses.",
                    evidence={"dst_ip": dst_ip, "syn_count": syn_count, "duration_seconds": duration,
                              "syn_rate": round(syn_count / duration, 2),
                              "syn_ack_ratio": round(syn_ack_count / max(1, syn_count), 4)},
                )))
        for (src_ip, dst_port), targets in targets_by_host_port.items():
            if src_ip not in self.trusted_scanners and len(targets) >= self.horizontal_target_threshold:
                evidence = {"dst_port": dst_port, "targets": sorted(targets), "target_count": len(targets)}
                alerts.append((src_ip, ForensicAlert(
                    timestamp=last_seen[src_ip],
                    type="HORIZONTAL_SCAN",
                    severity="HIGH",
                    score=45.0,
                    explanation=f"Host contacted {len(targets)} internal targets on port {dst_port}",
                    evidence=evidence,
                )))

        for (src_ip, target), ports in ports_by_host_target.items():
            if src_ip not in self.trusted_scanners and len(ports) >= self.vertical_port_threshold:
                evidence = {"dst_ip": target, "ports": sorted(ports), "port_count": len(ports)}
                alerts.append((src_ip, ForensicAlert(
                    timestamp=last_seen[src_ip],
                    type="SERVICE_ENUMERATION",
                    severity="HIGH",
                    score=40.0,
                    explanation=f"Host contacted {len(ports)} ports on internal target {target}",
                    evidence=evidence,
                )))

        for (src_ip, destination), byte_count in external_bytes.items():
            reverse = external_reverse_bytes[(src_ip, destination)]
            ratio = byte_count / max(1, reverse)
            if byte_count >= self.exfiltration_threshold and ratio >= 4.0 and destination_novelty.get((src_ip, destination), False):
                evidence = {"dst_ip": destination, "bytes": byte_count, "direction": "outbound",
                            "outbound_inbound_ratio": round(ratio, 2), "rare_destination": True,
                            "threshold": self.exfiltration_threshold}
                alerts.append((src_ip, ForensicAlert(
                    timestamp=last_seen[src_ip],
                    type="POTENTIAL_EXFILTRATION",
                    severity="HIGH",
                    score=45.0,
                    explanation=f"Host sent {byte_count / (1024 * 1024):.1f} MB to external destination {destination}",
                    evidence=evidence,
                )))
        return alerts

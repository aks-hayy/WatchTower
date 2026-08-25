from typing import List

from core.detection.behavioral_state import StatefulBehaviorEngine
from core.detection.contracts import DetectorManifestV2
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert


class UnifiedStatefulBehaviorDetector(BaseDetector):
    name = "Unified Stateful Behavior Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.stateful.host", name=name, version="2.1.0",
        input_kinds=("conversation", "flow", "session"),
        finding_types=("recon.port_scan", "recon.host_scan", "recon.syn_flood",
                       "lateral.admin_fanout", "exfil.volume_anomaly",
                       "behavior.beacon.suspected"),
        signal_family="behavior", correlation_group="stateful-host",
    )
    finding_metadata = {
        "recon.port_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1046", "correlation_group": "recon"},
        "recon.host_scan": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.8, "mitre_technique": "T1046", "correlation_group": "recon"},
        "recon.syn_flood": {"category": "THREAT", "impact": "HIGH", "confidence": 0.9, "mitre_technique": "T1498", "correlation_group": "availability"},
        "lateral.admin_fanout": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1021", "correlation_group": "lateral-movement"},
        "exfil.volume_anomaly": {"category": "THREAT", "impact": "HIGH", "confidence": 0.75, "mitre_technique": "T1041", "correlation_group": "exfiltration"},
        "behavior.beacon.suspected": {"category": "ANOMALY", "impact": "MEDIUM", "confidence": 0.75, "mitre_technique": "T1071", "correlation_group": "beacon"},
    }
    alert_cooldown_seconds = 300.0

    def __init__(self, trusted_scanners=None):
        self.engine = StatefulBehaviorEngine(trusted_scanners=trusted_scanners)

    def reset(self, source: str = None) -> None:
        self.engine.reset()

    def detect(self, flow=None, conversation=None, signal=None, **kwargs) -> List[ForensicAlert]:
        if signal:
            self.engine.note_signal(
                str(signal.get("subject") or ""),
                str(signal.get("type") or ""),
                float(signal.get("timestamp") or 0.0),
            )
            return []
        if conversation is not None:
            return self.engine.detect_conversation(conversation)
        return self.engine.detect(flow)

from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2
from core.detection.payload import application_payload as extract_application_payload

class FileTransferDetector(BaseDetector):
    name = "File Transfer Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.file.transfer", name=name, version="2.1.0",
        input_kinds=("packet", "stream"),
        finding_types=("file.executable_transfer",), signal_family="content",
        correlation_group="file-transfer",
    )
    finding_metadata = {
        "file.executable_transfer": {"category": "EXPOSURE", "impact": "LOW", "confidence": 0.9},
    }

    def detect(self, packet=None, stream=None, timestamp=0.0, application_payload=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if packet is None and stream is None:
            return alerts
        payload = bytes(stream[:1024 * 1024]) if stream is not None else (
            application_payload if application_payload is not None else extract_application_payload(packet)
        )
        
        # 1. Search for PE (Portable Executable) header: "MZ"
        if b"MZ" in payload and b"This program cannot be run in DOS mode" in payload:
            signature = b"MZ\x00This program cannot be run in DOS mode"
            alerts.append(ForensicAlert(
                timestamp=float(timestamp if stream is not None else packet.time),
                type="FILE_TRANSFER",
                severity="LOW",
                explanation="Executable file transfer detected (PE header found)",
                score=10.0,
                evidence={
                    "format": "PE",
                    "required_markers": 2,
                    "signature_evidence_hash": __import__("hashlib").sha256(signature).hexdigest(),
                },
            ))
                
        return alerts

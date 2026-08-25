import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import List
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2
from core.detection.payload import application_payload as extract_application_payload

class FTPDetector(BaseDetector):
    name = "Cleartext FTP Credential Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.credential.ftp", name=name, input_kinds=("packet", "stream"),
        finding_types=("credential.cleartext.ftp",), required_evidence={"credential.cleartext.ftp": ("protocol",)},
        signal_family="credential", correlation_group="cleartext-credential",
    )
    finding_metadata = {
        "credential.cleartext.ftp": {"category": "EXPOSURE", "impact": "HIGH", "confidence": 0.98, "mitre_technique": "T1552.001"},
    }

    def detect(self, packet=None, stream=None, flow_id=None, direction=None, timestamp=0.0,
               application_payload=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if packet is None and stream is None:
            return alerts

        if stream is not None:
            bounded = bytes(stream[:1024 * 1024])
            lines = bounded.replace(b"\r\n", b"\n").split(b"\n")
            pass_lines = [line for line in lines if line.upper().startswith(b"PASS ")]
            identified = bool(pass_lines) and (
                any(line.upper().startswith(b"USER ") for line in lines)
                or bool(flow_id and 21 in {int(flow_id[2] or 0), int(flow_id[3] or 0)})
            )
            if identified:
                alerts.append(ForensicAlert(
                    timestamp=float(timestamp or 0.0), type="CLEARTEXT_CREDENTIALS",
                    severity="CRITICAL", score=60.0,
                    explanation="Cleartext FTP password command found in a reassembled client stream",
                    evidence={"protocol": "FTP", "direction": direction or "unknown",
                              "credential_command": "PASS", "credential_count": len(pass_lines),
                              "stream_evidence_hash": __import__("hashlib").sha256(bounded).hexdigest()},
                ))
            return alerts

        if TCP in packet and packet[TCP].dport == 21:
            try:
                payload_bytes = application_payload if application_payload is not None else extract_application_payload(packet, maximum=8192)
                lines = bytes(payload_bytes).replace(b"\r\n", b"\n").split(b"\n")
                pass_lines = [line for line in lines if line.upper().startswith(b"PASS ")]
                if pass_lines:
                    alerts.append(ForensicAlert(
                        timestamp=float(packet.time),
                        type="CLEARTEXT_CREDENTIALS",
                        severity="CRITICAL",
                        score=60.0,
                        explanation="Cleartext FTP password transmitted",
                        evidence={"protocol": "FTP", "direction": "to_server", "credential_command": "PASS",
                                  "credential_count": len(pass_lines),
                                  "packet_evidence_hash": __import__("hashlib").sha256(bytes(payload_bytes)).hexdigest()}
                    ))
            except Exception:
                pass
        return alerts

import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import List
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class FTPDetector(BaseDetector):
    name = "Cleartext FTP Credential Detector"

    def detect(self, packet=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not packet:
            return alerts
            
        if TCP in packet and packet[TCP].dport == 21 and packet[TCP].payload:
            try:
                payload = bytes(packet[TCP].payload).decode('utf-8', errors='ignore')
                if payload.startswith("PASS "):
                    alerts.append(ForensicAlert(
                        timestamp=float(packet.time),
                        type="CLEARTEXT_CREDENTIALS",
                        severity="CRITICAL",
                        score=60.0,
                        explanation="Cleartext FTP password transmitted",
                        evidence={"protocol": "FTP", "payload_snippet": payload[:15] + "..."}
                    ))
            except Exception:
                pass
        return alerts

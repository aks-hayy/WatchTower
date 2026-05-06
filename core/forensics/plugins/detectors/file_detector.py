from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class FileTransferDetector(BaseDetector):
    name = "File Transfer Detector"

    def detect(self, packet=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not packet or not hasattr(packet, 'payload') or not packet.payload:
            return alerts
            
        payload = bytes(packet.payload)
        
        # 1. Search for PE (Portable Executable) header: "MZ"
        if b"MZ" in payload and b"This program cannot be run in DOS mode" in payload:
            alerts.append(ForensicAlert(
                timestamp=float(packet.time),
                type="FILE_TRANSFER",
                severity="CRITICAL",
                explanation="Executable file transfer detected (PE header found)",
                score=60.0
            ))
            
        # 2. Search for common malicious extensions in URLs or SMB
        malicious_exts = [b".exe", b".dll", b".zip", b".rar", b".ps1", b".vbs"]
        for ext in malicious_exts:
            if ext in payload.lower():
                alerts.append(ForensicAlert(
                    timestamp=float(packet.time),
                    type="SUSPICIOUS_FILE",
                    severity="HIGH",
                    explanation=f"Suspicious file extension found in payload: {ext.decode()}",
                    score=30.0
                ))
                
        return alerts

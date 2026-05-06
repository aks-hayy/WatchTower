from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class OSDetector(BaseDetector):
    name = "OS Fingerprinting Detector"

    def detect_os(self, ttl: int) -> Optional[str]:
        if ttl <= 32:
            return "Windows 95/98/ME or older"
        elif ttl <= 64:
            return "Linux / Unix / iOS / Android"
        elif ttl <= 128:
            return "Windows (modern)"
        elif ttl <= 255:
            return "Solaris / Cisco"
        return "Unknown"

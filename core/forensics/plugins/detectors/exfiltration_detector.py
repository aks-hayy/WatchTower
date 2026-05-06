from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class ExfiltrationDetector(BaseDetector):
    name = "Data Exfiltration Detector"

    def detect(self, flow=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not flow:
            return alerts
            
        if flow.byte_count > 10 * 1024 * 1024:
             alerts.append(ForensicAlert(
                timestamp=flow.last_seen,
                type="EXFILTRATION",
                severity="HIGH",
                score=40.0,
                explanation=f"Large data transfer detected ({flow.byte_count / (1024*1024):.1f} MB)",
                evidence={"bytes": flow.byte_count}
            ))
            
        return alerts

import statistics
from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class BeaconingDetector(BaseDetector):
    name = "Beaconing Detector"

    def detect(self, arrival_times: List[float] = None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not arrival_times or len(arrival_times) < 15:
            return alerts
            
        intervals = [arrival_times[i] - arrival_times[i-1] for i in range(1, len(arrival_times))]
        
        if len(intervals) < 10:
            return alerts
            
        avg_interval = statistics.mean(intervals)
        std_dev = statistics.stdev(intervals)
        
        if avg_interval > 0.5 and (std_dev / avg_interval) < 0.07:
            alerts.append(ForensicAlert(
                timestamp=arrival_times[-1],
                type="BEACONING",
                severity="HIGH",
                score=30.0,
                explanation=f"Highly periodic traffic detected (avg: {avg_interval:.2f}s, CV: {std_dev/avg_interval:.4f})",
                evidence={"avg_interval": avg_interval, "std_dev": std_dev}
            ))
            
        return alerts

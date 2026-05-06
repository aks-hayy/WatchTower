import scapy.all as scapy
from typing import Dict, Any, List, Optional
from core.forensics.models import ForensicAlert

class BaseParser:
    """Base class for all Watchtower protocol parsers."""
    
    name: str = "BaseParser"
    enabled: bool = True
    
    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Extract identities or metadata from the packet.
        
        Args:
            packet: The scapy packet to analyze.
            context: Optional dictionary containing context (e.g. current username, decrypted payload)
            
        Returns:
            A dictionary containing the extracted keys. Expected keys:
            - identities: Dict with keys like mac, local_hostname, netbios_name, remote_hostname, username, full_name
            - tls_info: Dict with keys ja3, ja4, library
        """
        return {}


class BaseDetector:
    """Base class for all Watchtower anomaly detectors."""
    
    name: str = "BaseDetector"
    enabled: bool = True

    def detect(self, packet=None, flow=None, arrival_times: List[float]=None, **kwargs) -> List[ForensicAlert]:
        """
        Detect anomalies based on packets, flows, or other metrics.
        
        Args:
            packet: The scapy packet (optional).
            flow: The FlowAggregate object (optional).
            arrival_times: List of packet arrival times (optional).
            kwargs: Additional parameters (e.g. domain, ttl, payload).
            
        Returns:
            A list of ForensicAlert objects.
        """
        return []

    def detect_os(self, ttl: int) -> Optional[str]:
        """
        Detect OS based on TTL. Only implemented by specific detectors.
        """
        return None

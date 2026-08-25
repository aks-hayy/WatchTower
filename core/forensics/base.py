import scapy.all as scapy
from typing import Dict, Any, List, Optional
from core.forensics.models import ForensicAlert

class BaseParser:
    """Base class for all Watchtower protocol parsers."""
    
    name: str = "BaseParser"
    enabled: bool = True
    api_version: int = 1
    supported_link_types = ("ethernet", "raw-ip")
    supported_capture_sources = ("network",)
    watched_ports = ()
    offline_capability = None

    def validate(self) -> List[str]:
        return []

    def reset(self, source: str = None) -> None:
        """Reset source-specific state before an analysis run."""

    def finalize(self, context: Dict[str, Any] = None) -> Dict[str, Any]:
        return {}

    @staticmethod
    def application_payload(packet, context: Dict[str, Any] = None) -> bytes:
        """Return the packet-scoped payload when the analysis engine provides it.

        Third-party parsers may keep calling this helper without opting into the
        offline fast path.  The fallback preserves the legacy Scapy behavior.
        """
        if context and isinstance(context.get("application_payload"), bytes):
            return context["application_payload"]
        from core.detection.payload import application_payload
        return application_payload(packet)
    
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
    api_version: int = 1
    supported_link_types = ("ethernet", "raw-ip")
    supported_capture_sources = ("network",)
    offline_capability = None
    manifest = None
    finding_metadata: Dict[str, Dict[str, Any]] = {}

    def validate(self) -> List[str]:
        if self.manifest is None:
            return []
        errors = list(self.manifest.validate())
        declared = set(self.manifest.finding_types)
        metadata_types = set((self.finding_metadata or {}).keys())
        for finding_type in sorted(declared - metadata_types):
            errors.append(f"missing finding_metadata for {finding_type}")
        for finding_type in sorted(metadata_types - declared):
            errors.append(f"finding_metadata is not declared: {finding_type}")
        for finding_type, metadata in (self.finding_metadata or {}).items():
            if str(metadata.get("category", "")).upper() not in {"THREAT", "ANOMALY", "EXPOSURE", "POLICY_VIOLATION"}:
                errors.append(f"{finding_type}: invalid category")
            if str(metadata.get("impact", "")).upper() not in {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                errors.append(f"{finding_type}: invalid impact")
            confidence = metadata.get("confidence")
            if not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
                errors.append(f"{finding_type}: confidence must be 0..1")
        return errors

    def reset(self, source: str = None) -> None:
        """Reset source-specific state before an analysis run."""

    def finalize(self, context: Dict[str, Any] = None) -> List[ForensicAlert]:
        return []

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

import logging
import logging.handlers
import json
from typing import Dict, Any

class SIEMExporter:
    """
    Exports Watchtower alerts to external SIEM systems.
    Currently supports Syslog (RFC5424/RFC3164).
    """

    def __init__(self, host: str = None, port: int = 514, protocol: str = "UDP"):
        self.host = host
        self.port = port
        self.protocol = protocol.upper()
        self.logger = logging.getLogger("siem_exporter")
        
        if host:
            socktype = socket.SOCK_DGRAM if self.protocol == "UDP" else socket.SOCK_STREAM
            import socket
            self.handler = logging.handlers.SysLogHandler(address=(host, port), socktype=socktype)
            self.logger.addHandler(self.handler)
            self.logger.setLevel(logging.INFO)
            print(f"SIEM Exporter initialized for {host}:{port} ({protocol})")

    def export_alert(self, alert: Dict[str, Any]):
        """Format and send an alert to SIEM."""
        if not self.host:
            return

        # Simple JSON over Syslog
        message = {
            "product": "Watchtower",
            "version": "1.0.0",
            "event": "ForensicAlert",
            "severity": alert.get("severity", "MEDIUM"),
            "type": alert.get("type"),
            "entity": alert.get("entity_ip"),
            "explanation": alert.get("explanation"),
            "timestamp": alert.get("timestamp")
        }
        self.logger.info(json.dumps(message))

    def export_flow(self, flow: Dict[str, Any]):
        """Optionally export high-value flows."""
        # For now, we only export alerts to avoid flooding SIEM
        pass

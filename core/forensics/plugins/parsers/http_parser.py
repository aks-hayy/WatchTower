import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any
from core.forensics.base import BaseParser

class HTTPParser(BaseParser):
    name = "HTTP Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        if TCP in packet and packet[TCP].payload:
            try:
                payload = self.application_payload(packet, context).decode('utf-8', errors='ignore')
                if "Host: " in payload:
                    for line in payload.split("\r\n"):
                        if line.startswith("Host: "):
                            result.setdefault("identities", {})["remote_hostname"] = line.split(": ")[1]
                            break
            except Exception:
                pass
        return result

import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any
from core.forensics.base import BaseParser

class FTPParser(BaseParser):
    name = "FTP Parser"
    watched_ports = (21,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        if TCP in packet and (packet[TCP].dport == 21 or packet[TCP].sport == 21) and packet[TCP].payload:
            try:
                payload = self.application_payload(packet, context).decode('utf-8', errors='ignore')
                if payload.startswith("USER "):
                    username = payload[5:].splitlines()[0].strip()
                    if username:
                        result.setdefault("identities", {})["username"] = f"ftp://{username}"
            except Exception:
                pass
        return result

import scapy.all as scapy
from typing import Dict, Any
from core.forensics.base import BaseParser

class DHCPParser(BaseParser):
    name = "DHCP Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        try:
            from scapy.layers.dhcp import DHCP
            if DHCP in packet:
                options = packet[DHCP].options
                for opt in options:
                    if isinstance(opt, tuple) and opt[0] == 'hostname':
                        hostname = opt[1].decode('utf-8', errors='ignore')
                        result.setdefault("identities", {})["local_hostname"] = hostname
        except Exception:
            pass
        return result

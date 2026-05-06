import scapy.all as scapy
from scapy.layers.inet import UDP
from typing import Dict, Any
from core.forensics.base import BaseParser

class NBNSParser(BaseParser):
    name = "NBNS Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        if UDP in packet and (packet[UDP].dport == 137 or packet[UDP].sport == 137):
            try:
                payload = bytes(packet[UDP].payload)
                if len(payload) > 12:
                    name_encoded = payload[12:44]
                    name = ""
                    for i in range(0, len(name_encoded), 2):
                        char_code = ((name_encoded[i] - 0x41) << 4) | (name_encoded[i+1] - 0x41)
                        name += chr(char_code)
                    
                    hostname = name.strip()
                    if hostname:
                        result.setdefault("identities", {})["local_hostname"] = hostname
                        result.setdefault("identities", {})["netbios_name"] = hostname
            except Exception:
                pass
        return result

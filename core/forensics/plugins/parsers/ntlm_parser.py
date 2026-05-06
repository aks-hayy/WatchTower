import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any
from core.forensics.base import BaseParser

class NTLMParser(BaseParser):
    name = "NTLM Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        if TCP in packet and packet[TCP].payload:
            try:
                payload = bytes(packet[TCP].payload)
                if b"NTLMSSP" in payload:
                    idx = payload.find(b"NTLMSSP\x00\x03\x00\x00\x00")
                    if idx != -1:
                        user_len = (payload[idx+36] | (payload[idx+37] << 8))
                        user_offset = (payload[idx+40] | (payload[idx+41] << 8))
                        user = payload[idx+user_offset : idx+user_offset+user_len].decode('utf-16le', errors='ignore')
                        
                        domain_len = (payload[idx+28] | (payload[idx+29] << 8))
                        domain_offset = (payload[idx+32] | (payload[idx+33] << 8))
                        domain = payload[idx+domain_offset : idx+domain_offset+domain_len].decode('utf-16le', errors='ignore')
                        
                        username = f"{domain}\\{user}" if domain else user
                        if username:
                            result.setdefault("identities", {})["username"] = username
            except Exception:
                pass
        return result

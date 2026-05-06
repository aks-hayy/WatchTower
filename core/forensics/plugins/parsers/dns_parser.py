import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from typing import Dict, Any
from core.forensics.base import BaseParser

class DNSParser(BaseParser):
    name = "DNS Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                domain = query.rstrip('.')
                return {"identities": {"remote_hostname": domain}}
            except Exception:
                pass
        return {}

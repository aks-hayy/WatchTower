import scapy.all as scapy
from scapy.layers.inet import TCP, UDP
from typing import Dict, Any, Optional
import re
import logging
from core.forensics.base import BaseParser

logger = logging.getLogger("KerberosParser")

class KerberosParser(BaseParser):
    name = "Kerberos Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        
        if not (packet.haslayer(UDP) or packet.haslayer(TCP)):
            return result
        
        layer = packet[UDP] if packet.haslayer(UDP) else packet[TCP]
        if layer.sport != 88 and layer.dport != 88:
            return result

        try:
            payload = bytes(layer.payload)
            if not payload: return result
            
            kerb = {}
            
            # 1. Realm
            realm_match = re.search(rb"\x1b([\x03-\x40])([A-Z0-9\._-]{3,64})", payload)
            if realm_match:
                kerb["realm"] = realm_match.group(2)[:realm_match.group(1)[0]].decode('utf-8', errors='ignore')
            
            # 2. CName
            if kerb.get("realm"):
                start_idx = payload.find(kerb["realm"].encode()) + len(kerb["realm"])
                cname_match = re.search(rb"\x1b([\x03-\x40])([a-z0-9\._-]{3,64})", payload[start_idx:])
                if cname_match:
                    kerb["username"] = cname_match.group(2)[:cname_match.group(1)[0]].decode('utf-8', errors='ignore')

            # 3. PAC Extraction
            if b"\x01\x00\x00\x00" in payload:
                pac_idx = payload.find(b"\x01\x00\x00\x00")
                # Safety check for slice
                pac_limit = min(pac_idx + 512, len(payload))
                pac_context = payload[pac_idx : pac_limit]
                name_match = re.search(rb"([A-Z]\x00(?:[a-z]\x00)+ [A-Z]\x00(?:[a-z]\x00)+)", pac_context)
                if name_match:
                    kerb["full_name"] = name_match.group(1).decode('utf-16le', errors='ignore').replace("\x00", "").strip()

            if kerb:
                identities = result.setdefault("identities", {})
                if kerb.get("username"):
                    identities["username"] = kerb["username"]
                if kerb.get("realm") and identities.get("username"):
                    identities["username"] = f"{kerb['realm']}\\{identities['username']}"
                if kerb.get("full_name"):
                    identities["full_name"] = kerb["full_name"]
                    
        except Exception as e:
            logger.debug(f"Kerberos parsing error: {e}")
            
        return result

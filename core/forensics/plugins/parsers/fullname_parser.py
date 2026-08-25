import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any, Optional
import re
from core.forensics.base import BaseParser

class FullNameParser(BaseParser):
    name = "Full Name Scraper"
    watched_ports = (80, 445, 389, 636, 8080)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        
        target_ports = [80, 445, 389, 636, 8080]
        if TCP in packet and (packet[TCP].sport in target_ports or packet[TCP].dport in target_ports):
            username_to_pivot = None
            if context and context.get("username"):
                username_to_pivot = context.get("username")
                if "\\" in username_to_pivot:
                    username_to_pivot = username_to_pivot.split("\\")[-1]

            full_name = self.scrape_full_name_from_data(self.application_payload(packet, context), username_to_pivot)
            if full_name:
                result.setdefault("identities", {})["full_name"] = full_name
                
        return result

    def scrape_full_name_from_data(self, payload: bytes, username: Optional[str] = None) -> Optional[str]:
        try:
            if len(payload) < 20: return None
            
            # 1. Service Account Filter
            if username:
                service_patterns = ["svc_", "system", "adm_", "krbtgt", "guest", "admin"]
                if any(p in username.lower() for p in service_patterns):
                    return None

            # 2. LDAP OID-Based Extraction
            ldap_oid_cn = b"\x06\x03\x55\x04\x03"
            if ldap_oid_cn in payload:
                idx = payload.find(ldap_oid_cn)
                context = payload[idx+5 : idx+40]
                match = re.search(rb"([A-Z][a-z]+ [A-Z][a-z]+)", context)
                if match:
                    name = match.group(1).decode('utf-8', errors='ignore')
                    if self._verify_name_quality(name):
                        return name

            # 3. Protocol-Specific Pivot
            if username:
                potential_last = username[1:] if len(username) > 3 else username
                last_uni = "".join([c + "\x00" for c in potential_last.capitalize()])
                
                patterns = [
                    rb"([A-Z][a-z]+ " + potential_last.capitalize().encode('utf-8') + rb")",
                    rb"([A-Z]\x00(?:[a-z]\x00)+ \x00" + last_uni.encode('utf-8') + rb")"
                ]
                
                for p in patterns:
                    match = re.search(p, payload)
                    if match:
                        name = match.group(1).decode('utf-16le' if b"\x00" in match.group(1) else 'utf-8', errors='ignore')
                        name = name.replace("\x00", "").strip()
                        if self._verify_name_quality(name) and name.lower() != username.lower():
                            return name

            # 4. Unicode fallback. A confirmed username is useful context, but
            # directory display names do not always resemble the account name.
            unicode_pattern = rb"([A-Z]\x00(?:[a-z]\x00)+ \x00[A-Z]\x00(?:[a-z]\x00)+)"
            unicode_match = re.search(unicode_pattern, payload)
            if unicode_match:
                name = unicode_match.group(1).decode('utf-16le', errors='ignore').replace("\x00", "").strip()
                if self._verify_name_quality(name):
                    return name

        except Exception:
            pass
        return None

    def _verify_name_quality(self, name: str) -> bool:
        blacklist = ["Group Policy", "Workstation", "Windows", "Microsoft", "Default", "Policy", "Object", "Service"]
        if any(b in name for b in blacklist):
            return False

        if len(name) < 5 or len(name) > 35: return False
        
        import math
        from collections import Counter
        
        prob = [n/len(name) for n in Counter(name).values()]
        entropy = -sum(p * math.log2(p) for p in prob)
        
        if entropy > 4.2: return False
        if " " not in name: return False
        
        return True

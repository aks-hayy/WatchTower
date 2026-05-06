import scapy.all as scapy
from typing import Dict, Any
from core.forensics.base import BaseParser

class DiscoveryParser(BaseParser):
    """
    Advanced Discovery Parser for Asset Identification.
    Extracts identities and device roles from mDNS, SSDP, and NetBIOS.
    """
    name = "Discovery Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        results = {"identities": {}}
        identities = results["identities"]

        # 1. mDNS (Port 5353) - Apple/IoT Discovery
        if packet.haslayer(scapy.UDP) and (packet[scapy.UDP].dport == 5353 or packet[scapy.UDP].sport == 5353):
            try:
                from scapy.layers.dns import DNS, DNSRR
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                    # Look for PTR/SRV/TXT records
                    for i in range(dns.ancount + dns.nscount + dns.arcount):
                        rr = dns.getlayer(DNSRR, i+1)
                        if not rr: break
                        
                        rr_name = rr.rrname.decode(errors='ignore') if isinstance(rr.rrname, bytes) else str(rr.rrname)
                        
                        # Extract device name from .local
                        if ".local" in rr_name:
                            name = rr_name.split(".")[0]
                            if "_" not in name and len(name) > 2:
                                identities["local_hostname"] = name
                        
                        # Infer device type from service strings
                        if "_airplay" in rr_name or "_raop" in rr_name:
                            identities["device_type"] = "Media Streamer (AirPlay)"
                            identities["asset_role"] = "IOT"
                        elif "_googlecast" in rr_name:
                            identities["device_type"] = "Media Streamer (Google Cast)"
                            identities["asset_role"] = "IOT"
                        elif "_spotify-connect" in rr_name:
                            identities["device_type"] = "Smart Speaker (Spotify)"
                            identities["asset_role"] = "IOT"
                        elif "_printer" in rr_name or "_ipp" in rr_name:
                            identities["device_type"] = "Network Printer"
                            identities["asset_role"] = "OFFICE"
            except Exception:
                pass

        # 2. SSDP (Port 1900) - UPnP/DLNA
        if packet.haslayer(scapy.UDP) and (packet[scapy.UDP].dport == 1900 or packet[scapy.UDP].sport == 1900):
            try:
                payload = bytes(packet[scapy.UDP].payload).decode(errors='ignore')
                if "LOCATION:" in payload or "SERVER:" in payload:
                    import re
                    # Extract Server/User-Agent info
                    server_match = re.search(r"SERVER:\s*(.*)", payload, re.IGNORECASE)
                    if server_match:
                        server_info = server_match.group(1).strip()
                        identities["os_info"] = server_info
                        if "WebOS" in server_info:
                            identities["device_type"] = "Smart TV (WebOS)"
                        elif "Roku" in server_info:
                            identities["device_type"] = "Media Streamer (Roku)"
                        elif "Sonos" in server_info:
                            identities["device_type"] = "Smart Speaker (Sonos)"
            except Exception:
                pass

        # 3. NetBIOS Name Service (Port 137)
        if packet.haslayer(scapy.UDP) and (packet[scapy.UDP].dport == 137 or packet[scapy.UDP].sport == 137):
            try:
                from scapy.layers.netbios import NBNSQueryRequest, NBNSQueryResponse
                if packet.haslayer(NBNSQueryResponse):
                    nbns = packet[NBNSQueryResponse]
                    name = nbns.RR_NAME.decode(errors='ignore').strip()
                    if name and len(name) > 1:
                        identities["netbios_name"] = name
                        identities["device_type"] = "Windows Workstation"
            except Exception:
                pass

        return results

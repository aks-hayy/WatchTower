import scapy.all as scapy
from typing import Dict, Any, List
from core.forensics.base import BaseParser

class InfrastructureParser(BaseParser):
    """
    Signature-Driven Infrastructure Parser.
    Performs active service discovery to resolve asset identities.
    """
    name = "Infrastructure Parser"

    def __init__(self):
        super().__init__()
        self.signatures = self._load_signatures()

    def _load_signatures(self) -> List[Dict]:
        import yaml
        import os
        sig_path = "core/forensics/signatures.yaml"
        try:
            if os.path.exists(sig_path):
                with open(sig_path, "r") as f:
                    return yaml.safe_load(f).get("signatures", [])
        except Exception:
            pass
        return []

    def active_probe(self, ip: str) -> Dict[str, Any]:
        """
        Perform deep service discovery and signature matching.
        """
        results = {"identities": {}, "device_type": "unknown", "asset_role": "unknown"}
        
        open_ports = []
        banners = {}
        certs = []
        titles = []
        
        # 1. Port Scanning & Banner Grabbing
        probe_ports = [135, 137, 139, 443, 445, 631, 1400, 1900, 3000, 5000, 5353, 8008, 8080, 8443, 9100, 62078]
        
        import socket
        import ssl
        import re

        for port in probe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.4)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    
                    # 1a. Certificate Extraction (SSL Ports)
                    if port in [443, 445, 1443, 8443, 5001]:
                        try:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=ip) as ssock:
                                ssock.settimeout(0.5)
                                ssock.connect((ip, port))
                                cert = ssock.getpeercert(True)
                                if cert:
                                    # Very basic extraction of text from binary cert for matching
                                    certs.append(str(cert))
                        except Exception: pass

                    # 1b. HTTP Banner & Title Grabbing
                    if port in [80, 8080, 1400, 1900, 3000, 5000, 8008]:
                        try:
                            sock.send(b"GET / HTTP/1.0\r\n\r\n")
                            data = sock.recv(1024).decode(errors='ignore')
                            banners[port] = data
                            # Extract <title>
                            title_match = re.search(r"<title>(.*?)</title>", data, re.I)
                            if title_match:
                                titles.append(title_match.group(1))
                        except Exception: pass
                sock.close()
            except Exception:
                pass

        # 2. Deep Signature Matching
        for sig in self.signatures:
            match_score = 0
            match_req = sig.get("match", {})
            
            # Port Match
            if any(p in open_ports for p in match_req.get("ports", [])):
                match_score += 1
            
            # Banner Match
            for b_port, pattern in match_req.get("banners", {}).items():
                if int(b_port) in banners and re.search(pattern, banners[int(b_port)], re.I):
                    match_score += 3
            
            # Cert Match
            cert_pattern = match_req.get("cert_regex")
            if cert_pattern and any(re.search(cert_pattern, c, re.I) for c in certs):
                match_score += 5
            
            # Title Match
            title_pattern = match_req.get("title_regex")
            if title_pattern and any(re.search(title_pattern, t, re.I) for t in titles):
                match_score += 5
            
            if match_score >= 1:
                results["device_type"] = sig["type"]
                results["asset_role"] = sig["role"]
                # Store any specific identities found
                if titles: results["identities"]["web_title"] = titles[0]
                break

        return results

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        # Passive parsing logic (minimal, mostly handles active probe results)
        return {"identities": {}}

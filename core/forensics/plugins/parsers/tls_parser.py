import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any, Optional
from core.forensics.base import BaseParser

class TLSParser(BaseParser):
    name = "TLS Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        
        # SNI extraction
        sni = self.extract_tls_sni(packet)
        if sni:
            result.setdefault("identities", {})["remote_hostname"] = sni
            
        # JA3/JA4 fingerprinting
        tls_info = self.extract_ja3_ja4(packet)
        if tls_info:
            result["tls_info"] = tls_info
            
        return result

    def extract_tls_sni(self, packet) -> Optional[str]:
        if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            try:
                payload = bytes(packet[TCP].payload)
                if len(payload) > 43 and payload[0] == 0x16 and payload[1] == 0x03:
                    if payload[5] == 0x01:
                        cursor = 43
                        if cursor < len(payload):
                            session_id_len = payload[cursor]
                            cursor += 1 + session_id_len
                            if cursor + 2 < len(payload):
                                cipher_len = (payload[cursor] << 8) | payload[cursor+1]
                                cursor += 2 + cipher_len
                                if cursor < len(payload):
                                    comp_len = payload[cursor]
                                    cursor += 1 + comp_len
                                    if cursor + 2 < len(payload):
                                        ext_total_len = (payload[cursor] << 8) | payload[cursor+1]
                                        cursor += 2
                                        end = cursor + ext_total_len
                                        while cursor + 4 < end and cursor + 4 < len(payload):
                                            ext_type = (payload[cursor] << 8) | payload[cursor+1]
                                            ext_len = (payload[cursor+2] << 8) | payload[cursor+3]
                                            if ext_type == 0x00: # SNI
                                                if cursor + 9 < len(payload):
                                                    sni_len = (payload[cursor+7] << 8) | payload[cursor+8]
                                                    return payload[cursor+9 : cursor+9+sni_len].decode('utf-8', errors='ignore')
                                            cursor += 4 + ext_len
            except Exception:
                pass
        return None

    def extract_ja3_ja4(self, packet) -> Optional[Dict[str, str]]:
        if not packet.haslayer(TCP):
            return None
        
        tcp = packet[TCP]
        if tcp.dport != 443 and tcp.sport != 443:
            return None

        try:
            payload = bytes(tcp.payload)
            if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
                return None

            from scapy.layers.tls.all import TLS, TLSClientHello
            
            tls_pkt = TLS(payload)
            if not tls_pkt.haslayer(TLSClientHello): return None
            
            hello = tls_pkt[TLSClientHello]
            grease = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa]
            
            version = hello.version
            ciphers = [c for c in hello.ciphers if c not in grease]
            extensions = []
            groups = []
            formats = []
            sni = False
            alpn = ""
            
            if hello.extensions:
                for ext in hello.extensions:
                    etype = ext.type
                    if etype in grease: continue
                    extensions.append(etype)
                    if etype == 0: sni = True
                    if etype == 16:
                        try: alpn = ext.alpn_protocols[0].decode('utf-8', errors='ignore')[:2]
                        except Exception: pass
                    if etype == 10 and hasattr(ext, "groups"):
                        groups = [g for g in ext.groups if g not in grease]
                    if etype == 11 and hasattr(ext, "ec_point_formats"):
                        formats = ext.ec_point_formats

            ja3_str = f"{version}," + "-".join(map(str, ciphers)) + "," + "-".join(map(str, extensions)) + "," + "-".join(map(str, groups)) + "," + "-".join(map(str, formats))
            import hashlib
            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
            
            ja4_a = f"t{version:02x}{'d' if sni else 'i'}{len(ciphers):02d}{len(extensions):02d}{alpn if alpn else '00'}"
            ja4_b = hashlib.sha256(",".join(map(str, sorted(ciphers))).encode()).hexdigest()[:12]
            ja4_c = hashlib.sha256(",".join(map(str, sorted(extensions))).encode()).hexdigest()[:12]
            
            return {
                "ja3": ja3_hash,
                "ja4": f"{ja4_a}_{ja4_b}_{ja4_c}",
                "library": self.identify_tls_client(ja3_hash)
            }
        except Exception: pass
        return None

    def identify_tls_client(self, ja3_hash: str) -> Optional[str]:
        signatures = {
            "66918128f1b9b03303d77c6f2eefd128": "Metasploit / Meterpreter",
            "969966d564ef72d76f8092ecf696d595": "Empire Stager",
            "771aa130080606060606060606060606": "Cobalt Strike Beacon",
            "3d47d488f280a5e89d15c7e1e626e2e5": "Cobalt Strike (Malleable)",
            "a0e9f5d64349fb13191bc781f81f42e1": "Psh-Empire",
            "54773199c0e495f2479e954558e8b093": "Google Chrome (V83+)",
            "4a382e88a0996849929944f247f247f2": "Firefox",
            "06a5bc82846944f12349fb13191bc781": "Python / Requests"
        }
        return signatures.get(ja3_hash)

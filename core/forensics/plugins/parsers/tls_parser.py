import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any, Optional
from core.forensics.base import BaseParser

class TLSParser(BaseParser):
    name = "TLS Parser"
    watched_ports = (443,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        
        # SNI extraction
        payload = self.application_payload(packet, context)
        sni = self.extract_tls_sni(packet, payload)
        if sni:
            result.setdefault("identities", {})["remote_hostname"] = sni
            
        # JA3/JA4 fingerprinting
        tls_info = self.extract_ja3_ja4(packet, payload)
        if tls_info:
            result["tls_info"] = tls_info
            
        return result

    def extract_tls_sni(self, packet, payload: bytes = None) -> Optional[str]:
        if TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            try:
                payload = payload if payload is not None else bytes(packet[TCP].payload)
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

    def extract_ja3_ja4(self, packet, payload: bytes = None) -> Optional[Dict[str, str]]:
        if not packet.haslayer(TCP):
            return None
        
        tcp = packet[TCP]
        if tcp.dport != 443 and tcp.sport != 443:
            return None

        try:
            payload = payload if payload is not None else bytes(tcp.payload)
            return self._extract_client_hello_fingerprint(payload)
        except Exception:
            return None

    @staticmethod
    def _is_grease(value: int) -> bool:
        return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)

    def _extract_client_hello_fingerprint(self, payload: bytes) -> Optional[Dict[str, str]]:
        """Parse a complete TLS ClientHello without constructing Scapy TLS layers."""
        if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        record_end = min(len(payload), 5 + int.from_bytes(payload[3:5], "big"))
        hello_end = min(record_end, 9 + int.from_bytes(payload[6:9], "big"))
        if hello_end < 43:
            return None
        cursor = 9
        version = int.from_bytes(payload[cursor:cursor + 2], "big")
        cursor += 34  # version plus Random
        if cursor >= hello_end:
            return None
        session_length = payload[cursor]
        cursor += 1 + session_length
        if cursor + 2 > hello_end:
            return None
        cipher_length = int.from_bytes(payload[cursor:cursor + 2], "big")
        cursor += 2
        cipher_end = cursor + cipher_length
        if cipher_length % 2 or cipher_end > hello_end:
            return None
        ciphers = [
            int.from_bytes(payload[index:index + 2], "big")
            for index in range(cursor, cipher_end, 2)
            if not self._is_grease(int.from_bytes(payload[index:index + 2], "big"))
        ]
        cursor = cipher_end
        if cursor >= hello_end:
            return None
        compression_length = payload[cursor]
        cursor += 1 + compression_length
        if cursor == hello_end:
            extension_end = cursor
        elif cursor + 2 <= hello_end:
            extension_end = cursor + 2 + int.from_bytes(payload[cursor:cursor + 2], "big")
            cursor += 2
            if extension_end > hello_end:
                return None
        else:
            return None

        extensions, groups, formats = [], [], []
        sni, alpn = False, ""
        while cursor + 4 <= extension_end:
            extension_type = int.from_bytes(payload[cursor:cursor + 2], "big")
            extension_length = int.from_bytes(payload[cursor + 2:cursor + 4], "big")
            cursor += 4
            extension_data_end = cursor + extension_length
            if extension_data_end > extension_end:
                return None
            data = payload[cursor:extension_data_end]
            cursor = extension_data_end
            if self._is_grease(extension_type):
                continue
            extensions.append(extension_type)
            if extension_type == 0:
                sni = True
            elif extension_type == 10 and len(data) >= 2:
                length = min(len(data), 2 + int.from_bytes(data[:2], "big"))
                groups.extend(
                    int.from_bytes(data[index:index + 2], "big")
                    for index in range(2, length - 1, 2)
                    if not self._is_grease(int.from_bytes(data[index:index + 2], "big"))
                )
            elif extension_type == 11 and data:
                formats.extend(data[1:1 + data[0]])
            elif extension_type == 16 and len(data) >= 3:
                protocol_length = data[2]
                alpn = data[3:3 + protocol_length].decode("utf-8", errors="ignore")[:2]

        ja3_string = (
            f"{version}," + "-".join(map(str, ciphers)) + "," +
            "-".join(map(str, extensions)) + "," + "-".join(map(str, groups)) +
            "," + "-".join(map(str, formats))
        )
        import hashlib
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        ja4_a = f"t{version:02x}{'d' if sni else 'i'}{len(ciphers):02d}{len(extensions):02d}{alpn or '00'}"
        ja4_b = hashlib.sha256(",".join(map(str, sorted(ciphers))).encode()).hexdigest()[:12]
        ja4_c = hashlib.sha256(",".join(map(str, sorted(extensions))).encode()).hexdigest()[:12]
        return {
            "ja3": ja3_hash,
            "ja4": f"{ja4_a}_{ja4_b}_{ja4_c}",
            "library": self.identify_tls_client(ja3_hash),
        }

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

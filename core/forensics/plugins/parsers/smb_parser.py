import struct
import re
import logging
import scapy.all as scapy
from scapy.layers.inet import TCP
from typing import Dict, Any

from core.forensics.base import BaseParser

logger = logging.getLogger(__name__)

class SMBParser(BaseParser):
    name = "SMB Stateful Parser"

    def __init__(self):
        super().__init__()
        # State tracking dictionaries. Safe since we instantiate one loader per capture session.
        self.sessions = {}     # Tracks SessionID -> Username
        self.open_files = {}   # Tracks FileID -> Filename

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        result = {}
        
        # We also maintain the legacy string carving for NetBIOS
        if packet.haslayer(TCP) and (packet.sport == 445 or packet.dport == 445):
            try:
                payload = bytes(packet[TCP].payload)
                if not payload:
                    return result
                
                # 1. Legacy NetBIOS Fallback
                match = re.search(rb"Windows [0-9.]+ ([A-Z0-9-]{3,15})", payload)
                if match:
                    hostname = match.group(1).decode('utf-8', errors='ignore')
                    result.setdefault("identities", {})["local_hostname"] = hostname

                # 2. Stateful SMB2 Parsing
                if len(payload) >= 64:
                    # Often payload starts with NetBIOS Session Service 4-byte header on 445
                    smb_offset = 0
                    if payload[0] == 0x00 and len(payload) >= 68 and payload[4:8] == b'\xfeSMB':
                        smb_offset = 4
                    elif payload[0:4] == b'\xfeSMB':
                        smb_offset = 0
                    else:
                        return result # Not a valid SMB2 header
                    
                    smb_data = payload[smb_offset:]
                    carved, ident = self._process_smb2(smb_data)
                    
                    if ident:
                        result.setdefault("identities", {}).update(ident)
                    if carved:
                        result.setdefault("carved_files", []).append(carved)

            except Exception as e:
                # Catch indexing or unpacking errors from malformed packets
                logger.debug(f"SMB parsing error: {e}")
                
        return result

    def _process_smb2(self, data: bytes):
        carved_file = None
        identities = {}
        
        try:
            # SMB2 Header (64 bytes)
            if len(data) < 64:
                return None, {}

            # Validate Protocol ID
            if data[0:4] != b'\xfeSMB':
                return None, {}

            # Extract Command and Session ID
            command = struct.unpack('<H', data[12:14])[0]
            session_id = struct.unpack('<Q', data[40:48])[0]

            # 1. Identity Attribution (Session Setup)
            if command == 0x0001:  # SESSION_SETUP
                user = self._extract_ntlm_user(data)
                if user:
                    self.sessions[session_id] = user
                    identities["username"] = user

            # 2. File Tracking (Create / Open)
            elif command == 0x0005: # CREATE
                # The Create Request starts after the 64-byte header
                req_offset = 64
                if len(data) >= req_offset + 56:
                    # Offset 44 in Create Request (64+44=108) is NameOffset
                    # Offset 46 in Create Request (64+46=110) is NameLength
                    name_offset = struct.unpack('<H', data[108:110])[0]
                    name_len = struct.unpack('<H', data[110:112])[0]
                    
                    if name_offset > 0 and name_len > 0 and name_offset + name_len <= len(data):
                        try:
                            filename_bytes = data[name_offset:name_offset + name_len]
                            filename = filename_bytes.decode('utf-16le', errors='ignore').strip('\x00')
                            if len(data) >= 168:
                                file_id = data[152:168]
                                self.open_files[file_id] = filename
                        except Exception:
                            pass

            # 3. Artifact Extraction (Write Request)
            elif command == 0x0009: # WRITE
                # Write Request: Data offset is at 16 (64+16=80)
                if len(data) >= 82:
                    data_offset = struct.unpack('<H', data[80:82])[0]
                    file_id = data[112:128] # FileID at 48 (64+48=112)
                    
                    if file_id in self.open_files and data_offset > 0 and data_offset < len(data):
                        filename = self.open_files[file_id]
                        content = data[data_offset:]
                        if content:
                            carved_file = {"filename": filename, "content": content}
                                    
        except Exception as e:
            logger.debug(f"SMB processing exception: {e}")
            
        return carved_file, identities

    def _extract_ntlm_user(self, data: bytes):
        """Extracts username from NTLMSSP Authenticate messages."""
        if b"NTLMSSP" in data:
            idx = data.find(b"NTLMSSP\x00\x03\x00\x00\x00")
            if idx != -1:
                try:
                    user_len = (data[idx+36] | (data[idx+37] << 8))
                    user_offset = (data[idx+40] | (data[idx+41] << 8))
                    user = data[idx+user_offset : idx+user_offset+user_len].decode('utf-16le', errors='ignore')
                    
                    domain_len = (data[idx+28] | (data[idx+29] << 8))
                    domain_offset = (data[idx+32] | (data[idx+33] << 8))
                    domain = data[idx+domain_offset : idx+domain_offset+domain_len].decode('utf-16le', errors='ignore')
                    
                    username = f"{domain}\\{user}" if domain else user
                    return username
                except Exception:
                    pass
        return None

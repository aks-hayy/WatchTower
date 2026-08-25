"""
Lateral movement simulation modules.

Tests against Watchtower detectors:
- watchtower.recon (lateral.admin_fanout)
- watchtower.stateful.host (lateral.admin_fanout)
- watchtower.application.abuse (auth.failure_burst)
- watchtower.smb.parser (username extraction)
- watchtower.rdp.parser (mstshash username)
"""

import os
import random
import socket
import struct
import time
from typing import Optional

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, AUTH_FAILURE_COUNT, AUTH_FAILURE_INTERVAL


class SMBBruteForce(BaseAttack):
    USERNAMES = ["admin", "administrator", "root", "guest", "user", "test"]
    PASSWORDS = ["password", "123456", "admin", "Password1", "pass", "guest"]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("smb_brute_force", "lateral_movement", target_ip)

    def execute(self) -> None:
        for username in self.USERNAMES:
            if self._stop_event.is_set():
                break
            for password in self.PASSWORDS:
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((self.target_ip, 445))
                    smb_negotiate = self._build_smb_negotiate()
                    s.send(smb_negotiate)
                    try:
                        s.recv(4096)
                    except socket.timeout:
                        pass
                    session_setup = self._build_smb_session_setup(username, password)
                    s.send(session_setup)
                    try:
                        response = s.recv(4096)
                        status = "attempted"
                    except socket.timeout:
                        status = "timeout"
                    self.log_packet({
                        "protocol": "SMB",
                        "dst_ip": self.target_ip,
                        "dst_port": 445,
                        "username": username,
                        "password_length": len(password),
                        "status": status,
                        "test_for": "auth.failure_burst",
                    })
                    s.close()
                except Exception as e:
                    self.log_packet({
                        "protocol": "SMB",
                        "dst_ip": self.target_ip,
                        "dst_port": 445,
                        "error": str(e),
                    })
                time.sleep(AUTH_FAILURE_INTERVAL)

    def _build_smb_negotiate(self) -> bytes:
        smb_header = b"\xff\x53\x4d\x42"
        command = b"\x72"
        flags = b"\x18"
        flags2 = b"\x00\x00"
        extra = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        tree_id = b"\x00\x00"
        process_id = os.urandom(2)
        user_id = b"\x00\x00"
        multiplex_id = b"\x00\x00"
        header = smb_header + command + flags + flags2 + extra + tree_id + process_id + user_id + multiplex_id
        dialects = b"\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"
        word_count = b"\x00"
        byte_count = struct.pack("<H", len(dialects))
        return header + word_count + byte_count + dialects

    def _build_smb_session_setup(self, username: str, password: str) -> bytes:
        smb_header = b"\xff\x53\x4d\x42"
        command = b"\x73"
        flags = b"\x18"
        flags2 = b"\x00\x00"
        extra = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        tree_id = b"\x00\x00"
        process_id = os.urandom(2)
        user_id = b"\x00\x00"
        multiplex_id = b"\x00\x00"
        header = smb_header + command + flags + flags2 + extra + tree_id + process_id + user_id + multiplex_id
        word_count = b"\x0c"
        andx_command = b"\xff"
        andx_reserved = b"\x00"
        andx_offset = b"\x00\x00"
        max_buf = b"\xff\xff"
        max_mpx = b"\x00\x02"
        vc_num = b"\x00\x00"
        session_key = b"\x00\x00\x00\x00"
        security_blob_len = b"\x00\x00"
        reserved = b"\x00\x00\x00\x00"
        capabilities = b"\x00\x00\x00\x00"
        oem_domain = b"WORKGROUP\x00"
        native_os = b"Windows\x00"
        native_lan = b"Windows\x2010\x00"
        oem_native = native_os + native_lan
        security_blob = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2"
        security_blob += struct.pack("<I", len(security_blob) + 16)
        security_blob += b"\x00\x00\x00\x00\x00\x00\x00\x00"
        security_blob += struct.pack("<I", len(security_blob) + 8)
        security_blob += b"\x01\x00\x00\x00"
        data = word_count + andx_command + andx_reserved + andx_offset
        data += max_buf + max_mpx + vc_num + session_key
        data += security_blob_len + reserved + capabilities
        data += oem_domain + security_blob + native_os + native_lan
        byte_count = struct.pack("<H", len(data))
        return header + byte_count + data


class RDPBruteForce(BaseAttack):
    USERNAMES = ["admin", "administrator", "root", "guest"]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("rdp_brute_force", "lateral_movement", target_ip)

    def execute(self) -> None:
        for username in self.USERNAMES:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 3389))
                tpkt = b"\x03\x00"
                x224 = b"\xe0\x00\x00\x00"
                s.send(tpkt + struct.pack(">H", 8) + x224)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "RDP",
                    "dst_ip": self.target_ip,
                    "dst_port": 3389,
                    "username": username,
                    "cookie": f"mstshash={username}",
                    "test_for": "rdp.username_extraction",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "RDP",
                    "dst_ip": self.target_ip,
                    "dst_port": 3389,
                    "error": str(e),
                })
            time.sleep(AUTH_FAILURE_INTERVAL)


class WMIExecution(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("wmi_execution", "lateral_movement", target_ip)

    def execute(self) -> None:
        for i in range(10):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 135))
                rpc_bind = self._build_rpc_bind()
                s.send(rpc_bind)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "MSRPC",
                    "dst_ip": self.target_ip,
                    "dst_port": 135,
                    "interface": "IWbemLocator",
                    "operation": "WMI_exec",
                    "note": "Simulated WMI lateral movement",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "MSRPC",
                    "dst_ip": self.target_ip,
                    "dst_port": 135,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_rpc_bind(self) -> bytes:
        return (b"\x05\x00\x0b\x00\x10\x00\x00\x00"
                b"\x48\x00\x00\x00\x00\x00\x00\x00"
                b"\xd0\x16\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x02\x00"
                + os.urandom(64))


class PowerShellRemoting(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("powershell_remoting", "lateral_movement", target_ip)

    def execute(self) -> None:
        for i in range(5):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 5985))
                http_request = (
                    f"POST /wsman HTTP/1.1\r\n"
                    f"Host: {self.target_ip}:5985\r\n"
                    f"Content-Type: application/soap+xml;charset=UTF-8\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: Keep-Alive\r\n\r\n"
                )
                s.send(http_request.encode())
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": 5985,
                    "operation": "WinRM/PowerShellRemoting",
                    "note": "Simulated PS remoting lateral movement",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": 5985,
                    "error": str(e),
                })
            time.sleep(1.0)


class LateralAdminFanout(BaseAttack):
    def __init__(self, base_ip: str = "127.0.0.1", admin_ports: Optional[list] = None):
        super().__init__("lateral_admin_fanout", "lateral_movement", base_ip)
        self.admin_ports = admin_ports or [22, 135, 139, 445, 3389, 5985]

    def execute(self) -> None:
        octets = self.target_ip.split(".")
        base = ".".join(octets[:3]) + "."
        targets = [f"{base}{i}" for i in range(2, 12)]
        for target in targets:
            if self._stop_event.is_set():
                break
            port = random.choice(self.admin_ports)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex((target, port))
                self.log_packet({
                    "protocol": "TCP",
                    "dst_ip": target,
                    "dst_port": port,
                    "flags": "SYN",
                    "test_for": "lateral.admin_fanout",
                    "note": f"Admin port {port} on {target}",
                })
                s.close()
            except Exception:
                pass
            time.sleep(0.5)


class Kerberoasting(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("kerberoasting", "lateral_movement", target_ip)

    def execute(self) -> None:
        for i in range(10):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 88))
                ap_req = self._build_kerberos_tgs_req()
                s.send(ap_req)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "Kerberos",
                    "dst_ip": self.target_ip,
                    "dst_port": 88,
                    "operation": "TGS-REQ",
                    "service": f"HTTP/node{i}.local",
                    "test_for": "kerberoasting_detection",
                    "note": "Requesting service tickets for offline cracking",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "Kerberos",
                    "dst_ip": self.target_ip,
                    "dst_port": 88,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_kerberos_tgs_req(self) -> bytes:
        msg_type = struct.pack(">I", 14)
        pvno = struct.pack(">I", 5)
        body = pvno + msg_type + os.urandom(64)
        length = struct.pack(">I", len(body) + 4)
        return length + body

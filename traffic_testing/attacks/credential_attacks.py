"""
Credential attack and exposure simulation modules.

Tests against Watchtower detectors:
- watchtower.credential.ftp (FTP PASS command)
- watchtower.application.abuse (credential.cleartext.generic)
- watchtower.application.abuse (auth.failure_burst)
- watchtower.ntlm.parser (domain\\username extraction)
- watchtower.mail.parser (SMTP/POP3/IMAP credentials)
"""

import os
import random
import socket
import time

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, FTP_PORT, HTTP_PORT, AUTH_FAILURE_INTERVAL


class FTPCredentialExposure(BaseAttack):
    CREDENTIALS = [
        ("fixture-user-1", "WATCHTOWER_TEST_PLACEHOLDER_1"),
        ("fixture-user-2", "WATCHTOWER_TEST_PLACEHOLDER_2"),
        ("fixture-user-3", "WATCHTOWER_TEST_PLACEHOLDER_3"),
        ("fixture-user-4", "WATCHTOWER_TEST_PLACEHOLDER_4"),
        ("fixture-user-5", "WATCHTOWER_TEST_PLACEHOLDER_5"),
    ]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("ftp_credential_exposure", "credential", target_ip)

    def execute(self) -> None:
        for username, password in self.CREDENTIALS:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, FTP_PORT))
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                user_cmd = f"USER {username}\r\n".encode()
                s.send(user_cmd)
                self.log_packet({
                    "protocol": "FTP",
                    "dst_ip": self.target_ip,
                    "dst_port": FTP_PORT,
                    "command": "USER",
                    "username": username,
                    "test_for": "credential.cleartext.ftp",
                })
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                pass_cmd = f"PASS {password}\r\n".encode()
                s.send(pass_cmd)
                self.log_packet({
                    "protocol": "FTP",
                    "dst_ip": self.target_ip,
                    "dst_port": FTP_PORT,
                    "command": "PASS",
                    "password_length": len(password),
                    "test_for": "credential.cleartext.ftp",
                })
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "FTP",
                    "dst_ip": self.target_ip,
                    "dst_port": FTP_PORT,
                    "error": str(e),
                })
            time.sleep(1.0)


class HTTPBasicAuthExposure(BaseAttack):
    CREDENTIALS = [
        ("fixture-user-1", "WATCHTOWER_TEST_PLACEHOLDER_1"),
        ("fixture-user-2", "WATCHTOWER_TEST_PLACEHOLDER_2"),
        ("fixture-user-3", "WATCHTOWER_TEST_PLACEHOLDER_3"),
        ("fixture-user-4", "WATCHTOWER_TEST_PLACEHOLDER_4"),
    ]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("http_basic_auth_exposure", "credential", target_ip)

    def execute(self) -> None:
        import base64
        for username, password in self.CREDENTIALS:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, HTTP_PORT))
                creds = base64.b64encode(f"{username}:{password}".encode()).decode()
                http_request = (
                    f"GET /api/admin/panel HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Authorization: Basic {creds}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.send(http_request.encode())
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": HTTP_PORT,
                    "header": "Authorization: Basic",
                    "username": username,
                    "test_for": "credential.cleartext.generic",
                    "regex_match": "authorization:\\s*basic",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": HTTP_PORT,
                    "error": str(e),
                })
            time.sleep(1.0)


class HTTPPasswordParamExposure(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("http_password_param", "credential", target_ip)

    def execute(self) -> None:
        import urllib.parse
        params_list = [
            {"user": "fixture-user-1", "password": "WATCHTOWER_TEST_PLACEHOLDER_1"},
            {"login": "fixture-user-2", "passwd": "WATCHTOWER_TEST_PLACEHOLDER_2"},
            {"username": "fixture-user-3", "pass": "WATCHTOWER_TEST_PLACEHOLDER_3"},
        ]
        for params in params_list:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, HTTP_PORT))
                query = urllib.parse.urlencode(params)
                http_request = (
                    f"POST /login HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {len(query)}\r\n"
                    f"Connection: close\r\n\r\n{query}"
                )
                s.send(http_request.encode())
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "dst_port": HTTP_PORT,
                    "method": "POST",
                    "content_type": "form-urlencoded",
                    "test_for": "credential.cleartext.generic",
                    "regex_match": "password\\s*[=:]",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "HTTP",
                    "dst_ip": self.target_ip,
                    "error": str(e),
                })
            time.sleep(1.0)


class SMTPCredentialExposure(BaseAttack):
    CREDENTIALS = [
        ("fixture-user-1-at-example-invalid", "WATCHTOWER_TEST_PLACEHOLDER_1"),
        ("fixture-user-2-at-example-invalid", "WATCHTOWER_TEST_PLACEHOLDER_2"),
    ]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("smtp_credential_exposure", "credential", target_ip)

    def execute(self) -> None:
        for username, password in self.CREDENTIALS:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 25))
                try:
                    banner = s.recv(1024)
                except socket.timeout:
                    banner = b""
                s.send(b"EHLO test.local\r\n")
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                auth_cmd = f"AUTH LOGIN\r\n".encode()
                s.send(auth_cmd)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                import base64
                s.send(base64.b64encode(username.encode()) + b"\r\n")
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                s.send(base64.b64encode(password.encode()) + b"\r\n")
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "SMTP",
                    "dst_ip": self.target_ip,
                    "dst_port": 25,
                    "command": "AUTH LOGIN",
                    "username": username,
                    "test_for": "credential.cleartext.generic",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "SMTP",
                    "dst_ip": self.target_ip,
                    "dst_port": 25,
                    "error": str(e),
                })
            time.sleep(1.0)


class AuthFailureBurst(BaseAttack):
    USERNAMES = ["fixture-user-1", "fixture-user-2", "fixture-user-3", "fixture-user-4", "fixture-user-5", "fixture-user-6", "fixture-user-7", "fixture-user-8"]
    PASSWORDS = ["WATCHTOWER_TEST_PLACEHOLDER_1", "WATCHTOWER_TEST_PLACEHOLDER_2", "WATCHTOWER_TEST_PLACEHOLDER_3", "WATCHTOWER_TEST_PLACEHOLDER_4", "WATCHTOWER_TEST_PLACEHOLDER_5"]

    def __init__(self, target_ip: str = TARGET_IP, port: int = 22, protocol: str = "SSH"):
        super().__init__("auth_failure_burst", "credential", target_ip)
        self.port = port
        self.protocol = protocol

    def execute(self) -> None:
        failures = 0
        for username in self.USERNAMES:
            if self._stop_event.is_set():
                break
            for password in self.PASSWORDS:
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((self.target_ip, self.port))
                    if self.protocol == "SSH":
                        try:
                            banner = s.recv(1024)
                        except socket.timeout:
                            pass
                        s.send(f"SSH-2.0-TestClient\r\n".encode())
                        auth_payload = (
                            f"password {password}\r\nauthentication failed\r\n"
                        ).encode()
                        s.send(auth_payload)
                    elif self.protocol == "FTP":
                        try:
                            s.recv(1024)
                        except socket.timeout:
                            pass
                        s.send(f"USER {username}\r\n".encode())
                        try:
                            s.recv(1024)
                        except socket.timeout:
                            pass
                        s.send(f"PASS {password}\r\n".encode())
                        try:
                            s.recv(1024)
                        except socket.timeout:
                            pass
                        s.send(b"530 authentication failed\r\n")
                    failures += 1
                    self.log_packet({
                        "protocol": self.protocol,
                        "dst_ip": self.target_ip,
                        "dst_port": self.port,
                        "username": username,
                        "status": "failure",
                        "failure_count": failures,
                        "test_for": "auth.failure_burst",
                    })
                    s.close()
                except Exception as e:
                    self.log_packet({
                        "protocol": self.protocol,
                        "dst_ip": self.target_ip,
                        "dst_port": self.port,
                        "error": str(e),
                    })
                time.sleep(AUTH_FAILURE_INTERVAL)
        if failures >= 5:
            self.log_packet({
                "protocol": self.protocol,
                "dst_ip": self.target_ip,
                "dst_port": self.port,
                "total_failures": failures,
                "trigger": "auth.failure_burst (5+ failures in window)",
            })


class NTLMCredentialExposure(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("ntlm_credential_exposure", "credential", target_ip)

    def execute(self) -> None:
        for i in range(10):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 445))
                negotiate = self._build_ntlm_negotiate()
                s.send(negotiate)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                authenticate = self._build_ntlm_authenticate(
                    domain="CORP",
                    username=f"jsmith{i}",
                    workstation="WORKSTATION1"
                )
                s.send(authenticate)
                self.log_packet({
                    "protocol": "SMB/NTLM",
                    "dst_ip": self.target_ip,
                    "dst_port": 445,
                    "ntlm_type": "Type3_Authenticate",
                    "domain": "CORP",
                    "username": f"jsmith{i}",
                    "workstation": "WORKSTATION1",
                    "test_for": "ntlm.username_extraction",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "SMB/NTLM",
                    "dst_ip": self.target_ip,
                    "dst_port": 445,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_ntlm_negotiate(self) -> bytes:
        ntlmssp = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 1)
        flags = struct.pack("<I", 0xA2888206)
        return ntlmssp + msg_type + flags

    def _build_ntlm_authenticate(self, domain: str, username: str, workstation: str) -> bytes:
        import struct
        ntlmssp = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 3)
        lm_challenge = os.urandom(24)
        nt_challenge = os.urandom(24)
        domain_bytes = domain.encode("utf-16-le")
        user_bytes = username.encode("utf-16-le")
        ws_bytes = workstation.encode("utf-16-le")
        domain_offset = 64
        user_offset = domain_offset + len(domain_bytes)
        ws_offset = user_offset + len(user_bytes)
        lm_offset = ws_offset + len(ws_bytes)
        nt_offset = lm_offset + 24
        total_len = nt_offset + 24
        msg = ntlmssp + msg_type
        msg += struct.pack("<HHI", len(lm_challenge), len(lm_challenge), lm_offset)
        msg += struct.pack("<HHI", len(nt_challenge), len(nt_challenge), nt_offset)
        msg += struct.pack("<HHI", len(domain_bytes), len(domain_bytes), domain_offset)
        msg += struct.pack("<HHI", len(user_bytes), len(user_bytes), user_offset)
        msg += struct.pack("<HHI", len(ws_bytes), len(ws_bytes), ws_offset)
        msg += struct.pack("<I", 0)
        msg += struct.pack("<I", 0xA2888206)
        msg += b"\x00" * 16
        msg += domain_bytes + user_bytes + ws_bytes + lm_challenge + nt_challenge
        return msg


class LDAPAnonymousBind(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("ldap_anonymous_bind", "credential", target_ip)

    def execute(self) -> None:
        for i in range(5):
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, 389))
                bind_req = self._build_ldap_bind_request()
                s.send(bind_req)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                search_req = self._build_ldap_search_request()
                s.send(search_req)
                try:
                    s.recv(4096)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "LDAP",
                    "dst_ip": self.target_ip,
                    "dst_port": 389,
                    "operation": "Bind + Search",
                    "bind_dn": "",
                    "search_base": "dc=corp,dc=local",
                    "test_for": "ldap.anonymous_bind",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "LDAP",
                    "dst_ip": self.target_ip,
                    "dst_port": 389,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_ldap_bind_request(self) -> bytes:
        msg_id = b"\x02\x01\x01"
        bind_choice = b"\x60"
        version = b"\x02\x01\x03"
        dn = b"\x04\x00"
        auth_choice = b"\x80\x00"
        bind_content = version + dn + auth_choice
        bind_seq = bytes([0x30]) + bytes([len(bind_content)]) + bind_content
        content = msg_id + bind_seq
        return bytes([0x30]) + bytes([len(content)]) + content

    def _build_ldap_search_request(self) -> bytes:
        msg_id = b"\x02\x01\x03"
        search_body = (
            b"\x63\x82\x00\x20"
            b"\x04\x11dc=corp,dc=local"
            b"\x0a\x01\x00"
            b"\x0a\x01\x00"
            b"\x02\x01\x00"
            b"\x02\x01\x00"
            b"\x01\x00"
            b"\x30\x00"
        )
        content = msg_id + search_body
        return bytes([0x30]) + bytes([len(content)]) + content


class SNMPCommunityStringExposure(BaseAttack):
    COMMUNITIES = ["public", "private", "manager", "admin", "community", "snmp123"]

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("snmp_community_exposure", "credential", target_ip)

    def execute(self) -> None:
        for community in self.COMMUNITIES:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.0)
                snmp_get = self._build_snmp_get(community, "1.3.6.1.2.1.1.1.0")
                s.sendto(snmp_get, (self.target_ip, 161))
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "SNMP",
                    "dst_ip": self.target_ip,
                    "dst_port": 161,
                    "community_string": community,
                    "oid": "1.3.6.1.2.1.1.1.0",
                    "test_for": "snmp.community_string_exposure",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "SNMP",
                    "dst_ip": self.target_ip,
                    "dst_port": 161,
                    "error": str(e),
                })
            time.sleep(0.5)

    def _build_snmp_get(self, community: str, oid: str) -> bytes:
        version = b"\x02\x01\x00"
        community_bytes = community.encode()
        community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes
        oid_parts = [int(x) for x in oid.split(".")]
        oid_encoded = bytes([0x06, len(oid_parts) - 1])
        for i, part in enumerate(oid_parts):
            if i == 0:
                oid_encoded += bytes([part * 40 + oid_parts[1]] if i == 0 else [0])
            elif i == 1:
                continue
            else:
                oid_encoded += bytes([part]) if part < 128 else bytes([0x80 | (part >> 7), part & 0x7F])
        get_request = b"\xa0\x00\x02\x01\x00\x02\x01\x00" + oid_encoded + b"\x05\x00"
        content = version + community_tlv + get_request
        return bytes([0x30]) + bytes([len(content)]) + content

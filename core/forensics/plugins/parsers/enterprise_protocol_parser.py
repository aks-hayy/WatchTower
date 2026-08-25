"""Enterprise administration, directory, and messaging protocol metadata."""

from typing import Any, Dict
import re

import scapy.all as scapy

from core.forensics.base import BaseParser


def _transport_payload(packet, context=None):
    if context and context.get("transport") is not None and "application_payload" in context:
        return context["transport"], context["application_payload"]
    for layer in (scapy.TCP, scapy.UDP):
        if layer in packet:
            return packet[layer], bytes(packet[layer].payload)
    return None, b""


class SSHParser(BaseParser):
    name = "SSH Parser"

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None or not payload.startswith(b"SSH-"):
            return {}
        banner = payload.splitlines()[0][:255].decode("ascii", errors="replace")
        software = banner.split("-", 2)[2] if banner.count("-") >= 2 else banner
        return {"metadata": {"application_protocol": "SSH", "ssh_banner": banner, "ssh_software": software}}


class LDAPParser(BaseParser):
    name = "LDAP Parser"
    watched_ports = (389, 636, 3268, 3269)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None or {int(transport.sport), int(transport.dport)}.isdisjoint({389, 636, 3268, 3269}):
            return {}
        if len(payload) < 7 or payload[0] != 0x30:
            return {"metadata": {"application_protocol": "LDAPS" if 636 in {transport.sport, transport.dport} else "LDAP"}}
        operation = next((value for value in payload[2:16] if value in {0x60, 0x61, 0x63, 0x64, 0x66, 0x67}), None)
        operation_names = {0x60: "bind-request", 0x61: "bind-response", 0x63: "search-request", 0x64: "search-entry", 0x66: "modify-request", 0x67: "modify-response"}
        return {"metadata": {"application_protocol": "LDAP", "ldap_operation": operation_names.get(operation, "unknown")}}


class RDPParser(BaseParser):
    name = "RDP Parser"
    watched_ports = (3389,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None or 3389 not in {int(transport.sport), int(transport.dport)}:
            return {}
        result = {"application_protocol": "RDP"}
        cookie = re.search(rb"Cookie:\s*mstshash=([^\r\n;]{1,128})", payload, re.I)
        if cookie:
            username = cookie.group(1).decode("utf-8", errors="replace")
            result["rdp_cookie_user"] = username
            return {"metadata": result, "identities": {"username": username}}
        if payload.startswith(b"\x03\x00"):
            result["rdp_transport"] = "TPKT"
        return {"metadata": result}


class MailProtocolParser(BaseParser):
    name = "Mail Protocol Parser"
    PORTS = {25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S"}
    watched_ports = tuple(PORTS)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None:
            return {}
        port = int(transport.dport) if int(transport.dport) in self.PORTS else int(transport.sport)
        if port not in self.PORTS:
            return {}
        text = payload[:1024].decode("utf-8", errors="replace")
        metadata = {"application_protocol": self.PORTS[port]}
        identity = {}
        user = re.search(r"(?:^|\r?\n)(?:USER|AUTH\s+PLAIN|LOGIN)\s+([^\s]+)", text, re.I)
        if user and not text.upper().startswith("AUTH PLAIN"):
            identity["username"] = user.group(1)[:128]
        sender = re.search(r"MAIL FROM:\s*<?([^>\s]+)", text, re.I)
        recipient = re.search(r"RCPT TO:\s*<?([^>\s]+)", text, re.I)
        if sender: metadata["mail_from"] = sender.group(1)[:254]
        if recipient: metadata["mail_to"] = recipient.group(1)[:254]
        result = {"metadata": metadata}
        if identity: result["identities"] = identity
        return result


class SNMPParser(BaseParser):
    name = "SNMP Parser"
    watched_ports = (161, 162)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None or {int(transport.sport), int(transport.dport)}.isdisjoint({161, 162}):
            return {}
        metadata = {"application_protocol": "SNMP"}
        if packet.haslayer("SNMP"):
            layer = packet.getlayer("SNMP")
            metadata["snmp_version"] = int(getattr(layer, "version", 0)) + 1
            community = getattr(layer, "community", b"")
            if community:
                metadata["snmp_community"] = bytes(community).decode("utf-8", errors="replace")[:128]
        elif payload:
            metadata["snmp_ber_length"] = len(payload)
        return {"metadata": metadata}


class NTPParser(BaseParser):
    name = "NTP Parser"
    watched_ports = (123,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        transport, payload = _transport_payload(packet, context)
        if transport is None or 123 not in {int(transport.sport), int(transport.dport)} or len(payload) < 4:
            return {}
        return {"metadata": {
            "application_protocol": "NTP", "ntp_leap": payload[0] >> 6,
            "ntp_version": (payload[0] >> 3) & 0x07, "ntp_mode": payload[0] & 0x07,
            "ntp_stratum": payload[1],
        }}

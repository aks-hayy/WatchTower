"""IoT and operational-technology protocol metadata parsers."""

from typing import Any, Dict

import scapy.all as scapy

from core.forensics.base import BaseParser


class MQTTParser(BaseParser):
    name = "MQTT Parser"
    watched_ports = (1883, 8883)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if scapy.TCP not in packet or {int(packet[scapy.TCP].sport), int(packet[scapy.TCP].dport)}.isdisjoint({1883, 8883}):
            return {}
        payload = self.application_payload(packet, context)
        if len(payload) < 2:
            return {}
        packet_type = payload[0] >> 4
        names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 8: "SUBSCRIBE", 12: "PINGREQ", 14: "DISCONNECT"}
        metadata = {"application_protocol": "MQTT", "mqtt_packet_type": names.get(packet_type, str(packet_type))}
        if packet_type == 1 and len(payload) >= 10:
            metadata["mqtt_username_flag"] = bool(payload[9] & 0x80)
            metadata["mqtt_password_flag"] = bool(payload[9] & 0x40)
            metadata["mqtt_clean_session"] = bool(payload[9] & 0x02)
        return {"metadata": metadata}


class CoAPParser(BaseParser):
    name = "CoAP Parser"
    watched_ports = (5683, 5684)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if scapy.UDP not in packet or {int(packet[scapy.UDP].sport), int(packet[scapy.UDP].dport)}.isdisjoint({5683, 5684}):
            return {}
        payload = self.application_payload(packet, context)
        if len(payload) < 4 or payload[0] >> 6 != 1:
            return {}
        return {"metadata": {
            "application_protocol": "CoAP", "coap_type": (payload[0] >> 4) & 0x03,
            "coap_code": payload[1], "coap_message_id": int.from_bytes(payload[2:4], "big"),
        }}


class ModbusParser(BaseParser):
    name = "Modbus TCP Parser"
    watched_ports = (502,)

    def parse(self, packet, context: Dict[str, Any] = None) -> Dict[str, Any]:
        if scapy.TCP not in packet or 502 not in {int(packet[scapy.TCP].sport), int(packet[scapy.TCP].dport)}:
            return {}
        payload = self.application_payload(packet, context)
        if len(payload) < 8 or payload[2:4] != b"\x00\x00":
            return {}
        return {"metadata": {
            "application_protocol": "ModbusTCP",
            "modbus_transaction_id": int.from_bytes(payload[0:2], "big"),
            "modbus_unit_id": payload[6], "modbus_function": payload[7],
        }}

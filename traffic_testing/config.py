"""
Shared configuration for Watchtower traffic injection tests.

All tests target localhost by default. Change TARGET_IP to test against
a real host on your network. All traffic is generated from this machine
so Watchtower can capture it on the local interface.
"""

import os
import socket
import time

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

TARGET_IP = os.environ.get("TT_TARGET_IP", "127.0.0.1")
LOCAL_IP = get_local_ip()
DNS_SERVER = os.environ.get("TT_DNS_SERVER", "8.8.8.8")
GATEWAY_IP = os.environ.get("TT_GATEWAY_IP", "192.168.1.1")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
LOG_DIR = os.path.join(RESULTS_DIR, "logs")
PCAP_DIR = os.path.join(RESULTS_DIR, "pcaps")

PHASE_LOG = os.path.join(RESULTS_DIR, "phase_log.json")

BEACON_INTERVAL = 3.0
BEACON_JITTER = 0.1
BEACON_DURATION = 5400

DNS_TUNNEL_DURATION = 3600
DNS_TUNNEL_CHUNK_SIZE = 32
DNS_TUNNEL_INTERVAL = 0.5

EXFIL_SLOW_DURATION = 1800
EXFIL_SLOW_CHUNK_SIZE = 1024
EXFIL_SLOW_INTERVAL = 2.0

EXFIL_FAST_SIZE = 50 * 1024 * 1024
EXFIL_FAST_CHUNK = 1024 * 1024

SYN_FLOOD_RATE = 50
SYN_FLOOD_DURATION = 30

SCAN_RATE = 0.1
SCAN_PORT_RANGE = (1, 1024)
SCAN_HOST_COUNT = 25

AUTH_FAILURE_COUNT = 10
AUTH_FAILURE_INTERVAL = 0.3

ICMP_TUNNEL_PAYLOAD_SIZE = 1024
ICMP_TUNNEL_COUNT = 50

MQTT_BROKER_PORT = 1883
MODBUS_PORT = 502
FTP_PORT = 21
HTTP_PORT = 8080
HTTPS_PORT = 443

C2_PORTS = [4444, 5555, 6666, 8888, 1337]

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

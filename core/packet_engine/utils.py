import urllib.request
import json
from functools import lru_cache
import psutil
import socket

@lru_cache(maxsize=1024)
def get_reverse_dns(ip):
    """Perform reverse DNS lookup."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

@lru_cache(maxsize=4096)
def get_geoip_info(ip):
    """Real GeoIP lookup using ip-api.com with local LRU caching."""
    # Check common private/local subnets
    if (ip.startswith("192.168.") or 
        ip.startswith("10.") or 
        ip.startswith("127.") or 
        ip.startswith("169.254.")):
        return {"country": "Local Network", "city": "Internal", "asn": "Private", "lat": 0.0, "lng": 0.0}
    
    # Very rudimentary check for 172.16.0.0/12
    if ip.startswith("172.") and len(ip.split('.')) > 1:
        try:
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return {"country": "Local Network", "city": "Internal", "asn": "Private", "lat": 0.0, "lng": 0.0}
        except ValueError:
            pass
    
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={'User-Agent': 'Mozilla/5.0 (Watchtower)'})
        with urllib.request.urlopen(req, timeout=1.5) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"), 
                    "city": data.get("city", "Unknown"), 
                    "asn": data.get("as", "Unknown ASN"),
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", "Unknown Org"),
                    "lat": data.get("lat", 0.0),
                    "lng": data.get("lon", 0.0)
                }
    except Exception as e:
        # print(f"[utils] GeoIP fetch failed for {ip}: {e}")
        pass
        
    return {"country": "International", "city": "Remote", "asn": "Unknown ASN", "lat": 0.0, "lng": 0.0}

def get_process_info(port):
    """Correlate a local port with a process name on Windows."""
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    return f"{proc.name()} ({conn.pid})"
    except Exception:
        pass
    return "Unknown"

def is_internal(ip: str) -> bool:
    """Check if an IP is internal/private."""
    return (ip.startswith("192.168.") or ip.startswith("10.") or
            ip.startswith("127.") or ip.startswith("169.254.") or
            (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31))

def normalize_packet(packet):
    """
    Peels encapsulation layers (VLAN, GRE, IP-in-IP) to find the innermost IP payload.
    Shared by capture engine, forensic engine, and parser plugins.
    """
    import scapy.all as scapy
    current = packet
    while True:
        if current.haslayer(scapy.Dot1Q):
            current = current[scapy.Dot1Q].payload
        elif current.haslayer(scapy.GRE):
            current = current[scapy.GRE].payload
        else:
            # Handle nested IP in IP (IP protocol 4)
            if current.haslayer(scapy.IP) and current[scapy.IP].payload.name == "IP":
                current = current[scapy.IP].payload
            else:
                break
    return current

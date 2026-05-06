import sys
import os
import multiprocessing
import logging

# Ensure local imports work when spawned in a new process on Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from scapy.all import sniff, IP, TCP, UDP
import time
from core.packet_engine.schemas import PacketEvent
import scapy.all as scapy
from core.packet_engine.utils import normalize_packet

logger = logging.getLogger("capture")


def packet_to_event(packet):
    import scapy.all as scapy
    
    # Automated Decapsulation (Peel the Onion)
    packet = normalize_packet(packet)

    if scapy.IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    flags = ""
    l7_info = {}

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Layer 7 identity extraction (Now handled by forensics engine plugins)
    l7_info = {}

    # Ensure raw bytes are passed reliably to schemas for evidence triggers
    try:
        raw_bytes = bytes(packet)
    except Exception:
        raw_bytes = None

    return PacketEvent(
        timestamp=float(packet.time),
        src_ip=ip_layer.src,
        dst_ip=ip_layer.dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=len(packet),
        flags=flags,
        l7_info=l7_info,
        raw=raw_bytes
    )


def start_capture(interface, queue, silent=False, stop_event=None):
    """Start sniffing packets on the specified interface and push events.
    
    Args:
        interface: Interface name or 'auto'
        queue: multiprocessing.Queue to push PacketEvents into
        silent: If True, redirect stdout/stderr to log file
        stop_event: multiprocessing.Event — when set, sniff() will stop cleanly
    """
    if silent:
        log_path = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data")),
            "engine.log"
        )
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        log_file = open(log_path, "a", buffering=1)
        sys.stdout = log_file
        sys.stderr = log_file

    def process_packet(packet):
        event = packet_to_event(packet)
        if event:
            event.interface = str(interface)
            queue.put(event)

    def should_stop(packet):
        """stop_filter for sniff() — returns True to stop sniffing."""
        if stop_event is not None and stop_event.is_set():
            return True
        return False

    # Resolve the actual iface value for scapy.sniff
    iface_arg = interface
    if interface == "auto":
        from core.packet_engine.config import auto_detect_interface
        iface_arg = auto_detect_interface()
    else:
        try:
            # if interface is numeric, convert to name
            idx = int(interface)
            iface_arg = scapy.conf.ifaces.dev_from_index(idx)
        except (ValueError, TypeError):
            # On Windows, handle GUID without WinPcap prefix
            if sys.platform == "win32" and isinstance(interface, str) and "{" in interface and "}" in interface:
                if not interface.startswith("\\Device\\"):
                    iface_arg = f"\\Device\\NPF_{interface}"
                else:
                    iface_arg = interface
            else:
                iface_arg = interface

    print(f"[capture] sniffing on {iface_arg}")
    try:
        # Use stop_filter for clean shutdown — polled every packet
        sniff(
            iface=iface_arg,
            prn=process_packet,
            store=False,
            promisc=True,
            stop_filter=should_stop if stop_event is not None else None
        )
    except Exception as e:
        print(f"[capture] sniff failed on {iface_arg}: {e}")
        sys.exit(1)

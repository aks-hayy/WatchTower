import sys
import os
import multiprocessing
import logging
import queue as queue_module

# Ensure local imports work when spawned in a new process on Windows
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from scapy.all import sniff, ARP, IP, IPv6, TCP, UDP
import time
from core.packet_engine.schemas import PacketEvent
import scapy.all as scapy
from core.packet_engine.utils import normalize_packet

logger = logging.getLogger("capture")


def packet_to_event(packet):
    import scapy.all as scapy
    
    # Automated Decapsulation (Peel the Onion)
    packet = normalize_packet(packet)

    if scapy.IP not in packet and scapy.IPv6 not in packet and scapy.ARP not in packet:
        return None

    if ARP in packet:
        ip_layer = packet[ARP]
        source_address = ip_layer.psrc
        destination_address = ip_layer.pdst
    else:
        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        source_address = ip_layer.src
        destination_address = ip_layer.dst
    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    flags = ""
    l7_info = {}

    if ARP in packet:
        protocol = "ARP"
    elif TCP in packet:
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
        src_ip=source_address,
        dst_ip=destination_address,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        size=len(packet),
        flags=flags,
        l7_info=l7_info,
        raw=raw_bytes
    )


def start_capture(interface, queue, silent=False, stop_event=None, origin=None, metrics=None):
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
        if metrics is not None:
            with metrics["received_packets"].get_lock():
                metrics["received_packets"].value += 1
        event = packet_to_event(packet)
        if event:
            event.interface = str(interface)
            if origin:
                event.session_id = origin.get("session_id")
                event.source_type = origin.get("source_type", "network")
                event.backend = origin.get("backend", "python")
                event.link_type = origin.get("link_type", "ethernet")
                event.sensor_node_id = origin.get("sensor_node_id")
                event.source = origin.get("source")
            try:
                queue.put(event, timeout=0.05)
                if metrics is not None:
                    with metrics["emitted_packets"].get_lock():
                        metrics["emitted_packets"].value += 1
                    metrics["last_packet_at"].value = event.timestamp
            except queue_module.Full:
                if metrics is not None:
                    with metrics["dropped_packets"].get_lock():
                        metrics["dropped_packets"].value += 1
                    with metrics["queue_full_events"].get_lock():
                        metrics["queue_full_events"].value += 1

    def should_stop(packet):
        """stop_filter for sniff() — returns True to stop sniffing."""
        if stop_event is not None and stop_event.is_set():
            return True
        return False

    # Resolve friendly names to Scapy's concrete adapter object. On Windows this
    # ensures "Wi-Fi" reaches the matching Npcap device rather than relying on
    # backend-specific string matching.
    from core.capture_sources.network import NetworkInterfaceSource

    try:
        iface_arg = NetworkInterfaceSource.resolve_interface(interface)
    except ValueError as exc:
        print(f"[capture] interface resolution failed: {exc}")
        sys.exit(1)

    capture_name = getattr(iface_arg, "network_name", None) or str(iface_arg)
    print(f"[capture] sniffing on {capture_name}")
    try:
        # Use stop_filter for clean shutdown — polled every packet
        while stop_event is None or not stop_event.is_set():
            sniff(
                iface=iface_arg,
                prn=process_packet,
                store=False,
                promisc=True,
                timeout=1.0 if stop_event is not None else None,
                stop_filter=should_stop if stop_event is not None else None,
            )
            if stop_event is None:
                break
    except Exception as e:
        print(f"[capture] sniff failed on {iface_arg}: {e}")
        sys.exit(1)

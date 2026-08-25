"""Linux BlueZ HCI discovery and observation capture."""

from pathlib import Path
import queue as queue_module
import re
import sys
import time
from typing import Iterable

from core.capture_sources.base import CaptureDevice, CaptureSource
from core.packet_engine.schemas import CaptureOrigin, HardwareObservation


class BluetoothHCISource(CaptureSource):
    source_type = "bluetooth"

    def list_devices(self) -> Iterable[CaptureDevice]:
        if not sys.platform.startswith("linux"):
            return [CaptureDevice(
                source_type=self.source_type, device_id="hci0", name="Bluetooth HCI",
                description="Linux BlueZ HCI capture", backends=[], available=False,
                unavailable_reason="Bluetooth HCI capture is unavailable on Windows; use a Linux BlueZ sensor",
            )]
        try:
            devices = sorted(path.name for path in Path("/sys/class/bluetooth").glob("hci*"))
        except OSError:
            devices = []
        if not devices:
            return [CaptureDevice(
                source_type=self.source_type, device_id="hci0", name="Bluetooth HCI",
                description="Linux BlueZ HCI capture", backends=[], available=False,
                unavailable_reason="No BlueZ HCI controller was discovered",
            )]
        return [CaptureDevice(
            source_type=self.source_type, device_id=device, name=device,
            description="Linux BlueZ Bluetooth HCI controller", backends=["python"],
        ) for device in devices]


def _printable_name(raw: bytes):
    candidates = re.findall(rb"[ -~]{3,64}", raw)
    return max(candidates, key=len).decode("utf-8", errors="replace") if candidates else None


def parse_hci_observation(packet, origin: CaptureOrigin) -> HardwareObservation:
    raw = bytes(packet)
    timestamp = float(getattr(packet, "time", time.time()))
    metadata = {"packet_class": packet.__class__.__name__, "length": len(raw)}
    subject, peer, kind = "controller", None, "hci_event"

    for layer_name, event_kind in (
        ("HCI_LE_Meta_Advertising_Report", "advertisement"),
        ("HCI_LE_Meta_Extended_Advertising_Report", "advertisement"),
        ("HCI_LE_Meta_Connection_Complete", "connection"),
        ("HCI_Event_Encryption_Change", "encryption_change"),
        ("HCI_Event_Link_Key_Request", "pairing"),
    ):
        if packet.haslayer(layer_name):
            layer = packet.getlayer(layer_name)
            kind = event_kind
            address = getattr(layer, "addr", None) or getattr(layer, "paddr", None)
            if address: subject = str(address)
            for field in ("atype", "type", "event_type", "role", "status", "handle", "rssi", "enabled"):
                value = getattr(layer, field, None)
                if value is not None: metadata[field] = int(value) if isinstance(value, (int, bool)) else str(value)
            break

    name = _printable_name(raw)
    if name: metadata["visible_name"] = name
    uuid16 = sorted({f"{value:02x}{raw[index + 1]:02x}" for index, value in enumerate(raw[:-1])
                     if value in {0x00, 0x18} and raw[index + 1] in range(0x18, 0x19)})
    if uuid16: metadata["visible_gatt_uuid16"] = uuid16[:32]
    if kind == "advertisement" and len(raw) >= 4:
        metadata["manufacturer_data_hint"] = raw[-16:].hex()
    return HardwareObservation(timestamp, origin, kind, subject, peer, metadata)


def start_bluetooth_capture(device, packet_queue, silent=False, stop_event=None, origin=None, metrics=None):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Bluetooth HCI capture is unavailable on Windows; use a Linux BlueZ sensor")
    import scapy.all as scapy
    capture_origin = CaptureOrigin(
        session_id=origin["session_id"], source_type="bluetooth", device_id=str(device),
        backend="python", link_type="bluetooth-hci",
    )
    monitor = scapy.BluetoothMonitorSocket()
    try:
        while not (stop_event and stop_event.is_set()):
            packet = monitor.recv()
            if packet is None: continue
            if metrics is not None: metrics["received_packets"].value += 1
            observation = parse_hci_observation(packet, capture_origin)
            try:
                packet_queue.put(observation, timeout=0.05)
                if metrics is not None:
                    metrics["emitted_packets"].value += 1
                    metrics["last_packet_at"].value = observation.timestamp
            except queue_module.Full:
                if metrics is not None:
                    metrics["dropped_packets"].value += 1
                    metrics["queue_full_events"].value += 1
    finally:
        monitor.close()

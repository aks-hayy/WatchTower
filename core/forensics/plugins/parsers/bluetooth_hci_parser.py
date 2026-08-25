"""Bluetooth HCI observation parser for recorded Linux monitor fixtures."""

from core.capture_sources.bluetooth import parse_hci_observation
from core.forensics.base import BaseParser
from core.packet_engine.schemas import CaptureOrigin


class BluetoothHCIParser(BaseParser):
    name = "Bluetooth HCI Parser"
    supported_link_types = ("bluetooth-hci",)
    supported_capture_sources = ("bluetooth",)

    def parse(self, packet, context=None):
        if not packet.haslayer("HCI_Hdr"):
            return {}
        context = context or {}
        origin = context.get("origin") or CaptureOrigin(
            session_id=context.get("session_id", "offline-hci"), source_type="bluetooth",
            device_id=context.get("device_id", "hci0"), backend="python", link_type="bluetooth-hci",
        )
        observation = parse_hci_observation(packet, origin)
        return {"observations": [{
            "capture_session_id": observation.origin.session_id,
            "timestamp": observation.timestamp, "source_type": "bluetooth",
            "device_id": observation.origin.device_id,
            "observation_type": observation.observation_type,
            "subject": observation.subject, "peer": observation.peer,
            "metadata": observation.metadata,
        }]}

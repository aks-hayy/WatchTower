"""Windows Sysmon ingestion with durable cursors and strict redaction."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import platform
import threading
import time
from typing import Any, Dict, Iterable, List, Optional
from xml.etree import ElementTree

from core.endpoint.attribution import ServiceResolver


CHANNEL = "Microsoft-Windows-Sysmon/Operational"
BOOKMARK_KEY = "endpoint.sysmon.last_record_id"


def _tag_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _as_timestamp(value: Optional[str]) -> float:
    if not value:
        return time.time()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _hashes(value: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for part in str(value or "").split(","):
        name, separator, digest = part.partition("=")
        if separator and name.strip() and digest.strip():
            result[name.strip().upper()] = digest.strip()[:256]
    return result


def parse_sysmon_event(xml_text: str) -> Optional[Dict[str, Any]]:
    """Parse only event fields required for process/flow attribution."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None
    system = next((node for node in root if _tag_name(node.tag) == "System"), None)
    event_data = next((node for node in root if _tag_name(node.tag) == "EventData"), None)
    if system is None or event_data is None:
        return None
    values = {str(node.attrib.get("Name") or ""): (node.text or "").strip() for node in event_data if _tag_name(node.tag) == "Data"}
    event_id = next((node.text for node in system if _tag_name(node.tag) == "EventID"), "")
    record_id = next((node.text for node in system if _tag_name(node.tag) == "EventRecordID"), "")
    time_node = next((node for node in system if _tag_name(node.tag) == "TimeCreated"), None)
    if str(event_id) not in {"1", "3"}:
        return None
    event_type = "process_create" if str(event_id) == "1" else "network_connect"
    protocol = str(values.get("Protocol") or "").upper() or None
    command_line = values.get("CommandLine") or ""
    return {
        "event_record_id": str(record_id or ""),
        "event_type": event_type,
        "observed_at": _as_timestamp(time_node.attrib.get("SystemTime") if time_node is not None else None),
        "process_guid": values.get("ProcessGuid") or None,
        "pid": _as_int(values.get("ProcessId")),
        "parent_pid": _as_int(values.get("ParentProcessId")),
        "image": values.get("Image") or None,
        "command_line_hash": sha256(command_line.encode("utf-8", errors="ignore")).hexdigest() if command_line else None,
        "user_name": values.get("User") or None,
        "hashes": _hashes(values.get("Hashes") or ""),
        "protocol": protocol,
        "local_ip": values.get("SourceIp") or None,
        "local_port": _as_int(values.get("SourcePort")),
        "remote_ip": values.get("DestinationIp") or None,
        "remote_port": _as_int(values.get("DestinationPort")),
        "initiated": str(values.get("Initiated") or "").lower() == "true" if event_type == "network_connect" else None,
        "details": {"rule_name": values.get("RuleName") or None, "event_id": str(event_id)},
    }


class SysmonCollector:
    """Polls the Windows Event Log without making Sysmon a hard dependency."""

    def __init__(self, db, sensor_node_id: Optional[str] = None, interval_seconds: float = 1.0):
        self.db = db
        self.sensor_node_id = sensor_node_id or db.local_sensor_node_id()
        self.interval_seconds = max(0.25, float(interval_seconds))
        self.services = ServiceResolver()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_error: Optional[str] = None
        self._last_poll: Optional[float] = None
        self._availability_checked_at = 0.0
        self._availability = False
        self._availability_reason = ""

    @staticmethod
    def supported() -> bool:
        return os.name == "nt" and platform.system().lower() == "windows"

    def status(self, include_counts: bool = True) -> Dict[str, Any]:
        now = time.monotonic()
        if now - self._availability_checked_at >= 30.0:
            available = self.supported()
            if available:
                try:
                    import win32evtlog  # type: ignore
                    win32evtlog.EvtOpenLog(CHANNEL, win32evtlog.EvtOpenChannelPath)
                except Exception as exc:
                    available = False
                    reason = f"Sysmon channel or pywin32 unavailable: {exc}"
                else:
                    reason = ""
            else:
                reason = "Sysmon endpoint telemetry is available only on Windows."
            self._availability = available
            self._availability_reason = reason
            self._availability_checked_at = now
        available = self._availability
        reason = self._availability_reason
        status = (
            self.db.endpoint_telemetry_status(self.sensor_node_id)
            if include_counts else {
                "sensor_node_id": self.sensor_node_id,
                "observations": None,
                "coverage": None,
            }
        )
        status.update({
            "available": available,
            "running": bool(self._thread and self._thread.is_alive()),
            "channel": CHANNEL,
            "reason": self._last_error or reason,
            "last_poll_at": self._last_poll,
        })
        return status

    def start(self) -> bool:
        if not self.status()["available"]:
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="watchtower-sysmon", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    def poll_once(self) -> int:
        if not self.supported():
            return 0
        try:
            import win32evtlog  # type: ignore
            query = win32evtlog.EvtQuery(CHANNEL, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection)
            handles = win32evtlog.EvtNext(query, 128)
            bookmark = int(self.db.get_metadata(BOOKMARK_KEY, "0") or 0)
            parsed = []
            newest = bookmark
            for handle in handles:
                item = parse_sysmon_event(win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml))
                if item is None:
                    continue
                record = _as_int(item.get("event_record_id")) or 0
                newest = max(newest, record)
                if record <= bookmark:
                    continue
                item["id"] = f"sysmon:{self.sensor_node_id}:{item['event_type']}:{record}"
                item["sensor_node_id"] = self.sensor_node_id
                item["evidence_ref"] = f"sysmon:{record}"
                item["service_names"] = self.services.services_for_pid(item.get("pid"))
                parsed.append(item)
            if parsed:
                self.db.upsert_endpoint_process_observations(parsed)
            if newest > bookmark:
                self.db.set_metadata(BOOKMARK_KEY, str(newest))
            self._last_error = None
            self._last_poll = time.time()
            return len(parsed)
        except Exception as exc:
            self._last_error = str(exc)[:500]
            self._last_poll = time.time()
            return 0

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval_seconds)

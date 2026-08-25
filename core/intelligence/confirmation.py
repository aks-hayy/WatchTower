"""Bounded, auditable confirmation of live private-network targets."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address, ip_interface
import threading
import time
import uuid
from typing import Any, Dict, Iterable, List


class IdentityConfirmationService:
    MAX_TARGETS = 100
    MAX_WORKERS = 8
    ATTEMPTS = 2
    SPACING_SECONDS = 0.1  # 10 packets/second across the operation
    COOLDOWN_SECONDS = 900

    def __init__(self, db):
        self.db = db
        self._rate_lock = threading.Lock()
        self._last_probe = 0.0

    @staticmethod
    def _attached_networks() -> List[tuple[str, str]]:
        networks = []
        try:
            import psutil
            import socket
            for interface, addresses in psutil.net_if_addrs().items():
                for item in addresses:
                    if getattr(item, "family", None) != socket.AF_INET or not item.address or not item.netmask:
                        continue
                    try:
                        network = ip_interface(f"{item.address}/{item.netmask}").network
                    except ValueError:
                        continue
                    if network.is_private:
                        networks.append((interface, str(network)))
        except Exception:
            return []
        return networks

    @classmethod
    def _eligible(cls, target: str, interface: str | None, networks: Iterable[tuple[str, str]]) -> bool:
        try:
            address = ip_address(str(target))
        except ValueError:
            return False
        if not address.is_private or address.is_multicast or address.is_loopback or address.is_unspecified:
            return False
        for attached_interface, network_text in networks:
            if interface and attached_interface != interface:
                continue
            try:
                network = ip_interface(f"{address}/{network_text.split('/', 1)[1]}").network
            except (ValueError, IndexError):
                continue
            if address in network and address not in {network.network_address, network.broadcast_address}:
                return True
        return False

    @staticmethod
    def _probe(interface: str, target: str, operation_id: str) -> Dict[str, Any]:
        try:
            from scapy.all import ARP, Ether, srp
        except ImportError as exc:
            return {"ip": target, "confirmed": False, "error": f"Scapy unavailable: {exc}"}
        try:
            answered, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                iface=interface, timeout=0.5, retry=0, verbose=False,
            )
        except Exception as exc:
            return {"ip": target, "confirmed": False, "error": str(exc)}
        for _sent, received in answered:
            mac = str(getattr(received, "hwsrc", "") or "").lower()
            if mac:
                return {"ip": target, "confirmed": True, "mac": mac, "operation_id": operation_id}
        return {"ip": target, "confirmed": False, "operation_id": operation_id}

    def _scopes(self, source: str | None, interface: str | None,
                capture_session_id: str | None) -> List[tuple[str | None, str | None]]:
        """Resolve aggregate filters to the concrete flow scopes they cover."""
        from core.storage.models import Flow

        with self.db.session_scope() as session:
            query = session.query(Flow.source, Flow.capture_session_id).distinct()
            if source:
                if source == "live":
                    query = query.filter(Flow.source.like("live%"))
                elif source.startswith("live_") and "#" not in source:
                    query = query.filter(Flow.source.like(f"{source}#%"))
                else:
                    query = query.filter(Flow.source == source)
            if interface:
                query = query.filter(Flow.capture_interface == interface)
            if capture_session_id:
                query = query.filter(Flow.capture_session_id == capture_session_id)
            scopes = [(row[0], row[1]) for row in query.all() if row[0]]
        return scopes or [(source or "live", capture_session_id)]

    def confirm(self, *, ips: Iterable[str] = (), source: str | None = None,
                interface: str | None = None, session: str | None = None,
                dry_run: bool = False) -> Dict[str, Any]:
        operation_id = str(uuid.uuid4())
        networks = self._attached_networks()
        pending = list(ips)
        if not pending:
            pending = [row.get("subject_ip") for row in self.db.get_unconfirmed_identity_observations(
                source=source, interface=interface, capture_session_id=session, limit=self.MAX_TARGETS,
            ) if row.get("subject_ip")]
        targets = sorted({str(item) for item in pending})[: self.MAX_TARGETS]
        eligible = [item for item in targets if self._eligible(item, interface, networks)]
        result = {
            "operation_id": operation_id, "dry_run": dry_run, "requested": len(targets),
            "eligible": len(eligible), "excluded": sorted(set(targets) - set(eligible)),
            "interface": interface, "results": [],
        }
        if dry_run or not eligible:
            return result
        # Requests are deliberately serialized by a small global rate gate,
        # while replies may be awaited concurrently.
        def run_target(target: str) -> Dict[str, Any]:
            last = None
            for _attempt in range(self.ATTEMPTS):
                with self._rate_lock:
                    delay = self.SPACING_SECONDS - (time.monotonic() - self._last_probe)
                    if delay > 0:
                        time.sleep(delay)
                    self._last_probe = time.monotonic()
                last = self._probe(interface or "", target, operation_id)
                if last.get("confirmed"):
                    break
            return last or {"ip": target, "confirmed": False}

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS, thread_name_prefix="watchtower-identity") as executor:
            futures = [executor.submit(run_target, target) for target in eligible]
            result["results"] = [future.result() for future in as_completed(futures)]
        scopes = self._scopes(source, interface, session)
        confirmations = []
        for item in result["results"]:
            if not item.get("confirmed"):
                continue
            for scope_source, scope_session in scopes:
                confirmations.append({
                    "subject_ip": item["ip"], "source": scope_source or "live", "capture_interface": interface,
                    "capture_session_id": scope_session, "observation_type": "active_arp_confirmation",
                    "confidence": 0.99, "evidence_ref": f"probe:{operation_id}:{scope_source}:{scope_session}", "first_seen": time.time(),
                    "last_seen": time.time(), "occurrence_count": 1, "fresh_until": time.time() + self.COOLDOWN_SECONDS,
                    "value": {"mac": item["mac"], "operation_id": operation_id},
                })
        if confirmations:
            self.db.upsert_identity_observations(confirmations)
        result["confirmed"] = len(confirmations)
        result["responses"] = confirmations
        return result

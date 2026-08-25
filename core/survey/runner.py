from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from ipaddress import ip_address, ip_network
from pathlib import Path
import socket
import ssl
import threading
import time
from typing import Dict, List
import uuid

import psutil

from core.backend_policy import backend_policy
from core.investigation.export import CaseExporter
from core.survey.probe_registry import ProbeRegistry


SAFE_PORTS = (22, 53, 80, 443, 445, 3389, 8080)
DEEP_PORTS = SAFE_PORTS + (21, 23, 25, 110, 123, 135, 139, 143, 389, 502, 636, 993, 995, 1883, 5900, 5985, 5986, 8883)


def parse_duration(value: str) -> int:
    value = str(value).strip().lower()
    units = {"s": 1, "m": 60, "h": 3600}
    if value[-1:] in units: return int(float(value[:-1]) * units[value[-1]])
    return int(value)


@dataclass(frozen=True)
class SurveyConfig:
    duration_seconds: int = 3600
    active: str = "deep"
    packets_per_second: int = 100
    concurrency: int = 32
    max_hosts_per_network: int = 1024
    connect_timeout: float = 0.5
    capture_backend: str = field(default_factory=backend_policy.capture_backend)


@dataclass
class SurveyReport:
    id: str
    started_at: float
    completed_at: float = 0.0
    networks: List[Dict] = field(default_factory=list)
    devices: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)
    external_peers: List[Dict] = field(default_factory=list)
    dns_tls_activity: List[Dict] = field(default_factory=list)
    anomalies: List[Dict] = field(default_factory=list)
    risks: List[Dict] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    visibility_limitations: List[str] = field(default_factory=list)
    probe_count: int = 0
    case_path: str = ""


class RateLimiter:
    def __init__(self, rate):
        self.interval = 1.0 / max(1, rate)
        self.next_at = time.monotonic()
        self.lock = threading.Lock()
    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = self.next_at - now
            if delay > 0: time.sleep(delay)
            self.next_at = max(now, self.next_at) + self.interval


class SurveyRunner:
    def __init__(self, db, data_dir="data", probe_registry=None):
        self.db = db
        self.data_dir = Path(data_dir)
        self.registry = probe_registry or ProbeRegistry(data_dir)
        self._port_counter = 0
        self._port_lock = threading.Lock()

    @staticmethod
    def directly_connected_networks():
        stats = psutil.net_if_stats()
        found = []
        for interface, addresses in psutil.net_if_addrs().items():
            if interface not in stats or not stats[interface].isup: continue
            for address in addresses:
                if address.family not in {socket.AF_INET, socket.AF_INET6} or not address.netmask: continue
                value = address.address.split("%")[0]
                try:
                    ip = ip_address(value)
                    network = ip_network(f"{value}/{address.netmask}", strict=False)
                except ValueError:
                    continue
                if ip.is_loopback or ip.is_link_local or not ip.is_private: continue
                found.append({"interface": interface, "address": value, "network": str(network), "version": ip.version})
        unique = {(item["interface"], item["network"]): item for item in found}
        return list(unique.values())

    def run(self, config=SurveyConfig(), capture=False, sleep=time.sleep):
        if config.active not in {"none", "safe", "deep"}: raise ValueError("active must be none, safe, or deep")
        if config.packets_per_second > 100 or config.concurrency > 32:
            raise ValueError("survey safety limits are 100 packets/s and 32 concurrent operations")
        report = SurveyReport(str(uuid.uuid4()), time.time(), networks=self.directly_connected_networks())
        started_interfaces = []
        if capture and config.duration_seconds:
            from core.daemon.client import DaemonClient
            client = DaemonClient()
            client.heartbeat(config.duration_seconds + 300)
            for network in report.networks:
                interface = network["interface"]
                if interface in started_interfaces: continue
                result = client.start_engine(interface, config.capture_backend, "network")
                if result.get("status") in {"ok", "started", "already_running"}:
                    started_interfaces.append(interface)
                else: report.visibility_limitations.append(f"Capture unavailable on {interface}: {result.get('message', result)}")
            sleep(config.duration_seconds)
            for interface in started_interfaces: client.stop_engine(interface)
        self._passive(report)
        if config.active != "none": self._active(report, config)
        report.completed_at = time.time()
        report.visibility_limitations.extend([
            "Switched traffic not mirrored to this sensor is outside passive visibility.",
            "Encrypted payload contents remain opaque without session keys.",
            "Hosts that did not answer bounded discovery may be present but unconfirmed.",
        ])
        report.case_path = str(self._export(report))
        return report

    def _passive(self, report):
        scopes = [ip_network(item["network"]) for item in report.networks]
        entities = [item for item in self.db.get_all_entities()
                    if any(self._usable_host(item.get("ip", ""), network) for network in scopes)]
        flows = self.db.get_flows(limit=100_000)
        report.devices.extend(entities)
        external_peers = {}
        for flow in flows:
            src, dst = flow.get("src_ip"), flow.get("dst_ip")
            if not any(self._inside(src or "", network) or self._inside(dst or "", network) for network in scopes):
                continue
            report.relationships.append({"src": src, "dst": dst, "protocol": flow.get("protocol"),
                                         "dst_port": flow.get("dst_port"), "evidence_ref": f"flow:{flow.get('id')}"})
            try:
                destination = ip_address(dst) if dst else None
                if destination and destination.is_global and not destination.is_multicast:
                    key = (src, dst)
                    peer = external_peers.setdefault(key, {"local": src, "external": dst, "bytes": 0,
                                                           "flow_count": 0, "evidence_refs": []})
                    peer["bytes"] += int(flow.get("byte_count") or 0); peer["flow_count"] += 1
                    if len(peer["evidence_refs"]) < 20: peer["evidence_refs"].append(f"flow:{flow.get('id')}")
            except ValueError: pass
            metadata = flow.get("l7_metadata") or {}
            if isinstance(metadata, dict) and any(key in metadata for key in ("remote_hostname", "tls_sni", "ja3_hash")):
                report.dns_tls_activity.append({"flow_id": flow.get("id"), **metadata})
        report.external_peers.extend(external_peers.values())
        local_ips = {item.get("ip") for item in entities}
        alerts = [item for item in self.db.get_alerts(limit=100_000) if item.get("entity_ip") in local_ips]
        grouped = {}
        for alert in alerts:
            key = (alert.get("entity_ip"), alert.get("type"))
            group = grouped.setdefault(key, {"entity_ip": key[0], "type": key[1], "count": 0,
                "max_score": 0.0, "max_severity": "LOW", "latest": 0.0, "alert_refs": []})
            group["count"] += int(alert.get("occurrence_count") or 1)
            group["max_score"] = max(group["max_score"], float(alert.get("score") or 0))
            group["latest"] = max(group["latest"], float(alert.get("timestamp") or 0))
            if {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(alert.get("severity"), 0) > {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(group["max_severity"], 0):
                group["max_severity"] = alert.get("severity")
            if len(group["alert_refs"]) < 20: group["alert_refs"].append(f"alert:{alert.get('id')}")
        report.anomalies.extend(grouped.values())
        report.risks.extend({"entity_ip": item["entity_ip"], "severity": item["max_severity"],
                             "score": item["max_score"], "alert_refs": item["alert_refs"]} for item in grouped.values())

    def _active(self, report, config):
        limiter = RateLimiter(config.packets_per_second)
        known = {item.get("ip") for item in report.devices if item.get("ip")}
        targets = set()
        source_for_target = {}
        for network_info in report.networks:
            network = ip_network(network_info["network"])
            if network.version != 4: continue
            candidates = [ip for ip in known if self._inside(ip, network)]
            if config.active == "deep":
                candidates.extend(str(ip) for index, ip in enumerate(network.hosts()) if index < config.max_hosts_per_network)
            for target in candidates:
                if target != network_info["address"]:
                    targets.add(target); source_for_target[target] = network_info["address"]
        ports = DEEP_PORTS if config.active == "deep" else SAFE_PORTS
        with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
            futures = []
            failures = {}
            for target in sorted(targets, key=lambda value: int(ip_address(value))):
                futures.append(executor.submit(self._resolve, source_for_target[target], target, limiter))
                futures.append(executor.submit(self._arp_probe, source_for_target[target], target, config, limiter))
                futures.append(executor.submit(self._icmp_probe, source_for_target[target], target, config, limiter))
                for port in ports:
                    futures.append(executor.submit(self._tcp_probe, source_for_target[target], target, port, config, limiter))
            for network_info in report.networks:
                if network_info["version"] == 4:
                    futures.append(executor.submit(self._udp_discovery, network_info["address"], "mdns", config, limiter))
                    if config.active == "deep":
                        futures.append(executor.submit(self._udp_discovery, network_info["address"], "ssdp", config, limiter))
                else:
                    network = ip_network(network_info["network"])
                    for target in known:
                        if self._inside(target, network):
                            futures.append(executor.submit(self._ndp_probe, network_info["address"], target, config, limiter))
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    key = f"{type(exc).__name__}: {str(exc)[:240]}"
                    failures[key] = failures.get(key, 0) + 1
                    continue
                report.probe_count += 1
                if not result: continue
                results = result if isinstance(result, list) else [result]
                for result in results:
                    if result.get("kind") == "identity":
                        existing = next((item for item in report.devices if item.get("ip") == result["ip"]), None)
                        if existing: existing.update(result)
                        else: report.devices.append(result)
                    elif result.get("kind") == "service": report.services.append(result)
                    report.evidence.append({"evidence_type": "survey_probe", "evidence_ref": result["evidence_ref"],
                                            "timestamp": result["timestamp"], "summary": result})
            report.visibility_limitations.extend(f"{count} probe(s) failed: {reason}" for reason, count in failures.items())

    def _resolve(self, source, target, limiter):
        limiter.wait()
        self._audit(source, target, "PTR", 53)
        try: hostname = socket.gethostbyaddr(target)[0]
        except (socket.herror, socket.gaierror, TimeoutError): return None
        return {"kind": "identity", "ip": target, "hostname": hostname, "timestamp": time.time(),
                "evidence_ref": f"ptr:{target}", "generated_by": "WatchTower"}

    def _tcp_probe(self, source, target, port, config, limiter):
        limiter.wait()
        with self._port_lock:
            source_port = 49152 + self._port_counter % 11847
            self._port_counter += 1
        self.registry.register(source, target, source_port, port, "TCP")
        self.db.insert_hardware_observation({"timestamp": time.time(), "source_type": "survey", "device_id": source,
            "observation_type": "survey_probe", "subject": source, "peer": target,
            "metadata": {"protocol": "TCP", "src_port": source_port, "dst_port": port, "generated_by": "WatchTower"}})
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(config.connect_timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((source, source_port))
            if sock.connect_ex((target, port)) != 0: return None
            result = {"kind": "service", "ip": target, "port": port, "protocol": "TCP", "timestamp": time.time(),
                      "evidence_ref": f"probe:{target}:{port}", "generated_by": "WatchTower"}
            if port == 443:
                context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=target) as tls:
                    certificate = tls.getpeercert(binary_form=True) or b""
                    result.update({"tls_version": tls.version(), "cipher": tls.cipher()[0] if tls.cipher() else None,
                                   "certificate_sha256": sha256(certificate).hexdigest() if certificate else None})
                    sock = None
            else:
                try: result["banner"] = sock.recv(256).decode("utf-8", errors="replace").strip()
                except socket.timeout: pass
            return result
        except (OSError, ssl.SSLError): return None
        finally:
            if sock is not None: sock.close()

    def _arp_probe(self, source, target, config, limiter):
        limiter.wait()
        self._audit(source, target, "ARP", 0)
        try:
            import scapy.all as scapy
            response = scapy.srp1(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target),
                                  timeout=config.connect_timeout, verbose=False)
            if not response or scapy.ARP not in response: return None
            return {"kind": "identity", "ip": target, "mac": str(response[scapy.ARP].hwsrc),
                    "timestamp": time.time(), "evidence_ref": f"arp:{target}", "generated_by": "WatchTower"}
        except (OSError, PermissionError): return None

    def _icmp_probe(self, source, target, config, limiter):
        limiter.wait()
        self._audit(source, target, "ICMP", 0)
        try:
            import scapy.all as scapy
            response = scapy.sr1(scapy.IP(src=source, dst=target)/scapy.ICMP(type=8),
                                 timeout=config.connect_timeout, verbose=False)
            if not response: return None
            return {"kind": "identity", "ip": target, "icmp_reachable": True,
                    "ttl": int(response[scapy.IP].ttl) if scapy.IP in response else None,
                    "timestamp": time.time(), "evidence_ref": f"icmp:{target}", "generated_by": "WatchTower"}
        except (OSError, PermissionError): return None

    def _ndp_probe(self, source, target, config, limiter):
        limiter.wait()
        self._audit(source, target, "NDP", 0)
        try:
            import scapy.all as scapy
            mac = scapy.getmacbyip6(target)
            if not mac: return None
            return {"kind": "identity", "ip": target, "mac": str(mac), "timestamp": time.time(),
                    "evidence_ref": f"ndp:{target}", "generated_by": "WatchTower"}
        except (OSError, PermissionError): return None

    def _udp_discovery(self, source, protocol, config, limiter):
        limiter.wait()
        destination, port, payload = (
            ("224.0.0.251", 5353, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
            if protocol == "mdns" else
            ("239.255.255.250", 1900, b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n")
        )
        with self._port_lock:
            source_port = 49152 + self._port_counter % 11847; self._port_counter += 1
        self.registry.register(source, destination, source_port, port, "UDP")
        self._audit(source, destination, "UDP", port, source_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(config.connect_timeout)
        try:
            sock.bind((source, source_port)); sock.sendto(payload, (destination, port))
            data, peer = sock.recvfrom(2048)
            return {"kind": "service", "ip": peer[0], "port": peer[1], "protocol": protocol.upper(),
                    "banner": data.decode("utf-8", errors="replace")[:1024], "timestamp": time.time(),
                    "evidence_ref": f"{protocol}:{peer[0]}:{peer[1]}", "generated_by": "WatchTower"}
        except (OSError, socket.timeout): return None
        finally: sock.close()

    def _audit(self, source, target, protocol, dst_port, src_port=0):
        self.db.insert_hardware_observation({"timestamp": time.time(), "source_type": "survey", "device_id": source,
            "observation_type": "survey_probe", "subject": source, "peer": target,
            "metadata": {"protocol": protocol, "src_port": src_port, "dst_port": dst_port, "generated_by": "WatchTower"}})

    def _export(self, report):
        data = asdict(report)
        investigation = {
            "target": "directly-connected-networks", "source": f"survey:{report.id}",
            "generated_at": report.completed_at, "summary": f"{len(report.devices)} devices and {len(report.services)} services observed",
            "timeline": [{"timestamp": item.get("timestamp"), "type": item.get("evidence_type"),
                          "ref": item.get("evidence_ref"), "summary": str(item.get("summary"))} for item in report.evidence],
            "evidence": report.evidence, "survey": data,
        }
        return CaseExporter(self.data_dir / "cases").export(investigation, f"network-survey-{report.id[:8]}")

    @staticmethod
    def _inside(value, network):
        try: return ip_address(value) in network
        except ValueError: return False

    @staticmethod
    def _usable_host(value, network):
        try:
            ip = ip_address(value)
            return ip in network and ip not in {network.network_address, network.broadcast_address}
        except ValueError:
            return False

import math
import re
from collections import defaultdict, deque
from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert
from core.detection.contracts import DetectorManifestV2

try:
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
except ImportError:  # pragma: no cover
    DNS = DNSQR = IP = IPv6 = None

class DNSDetector(BaseDetector):
    name = "DNS Anomaly Detector"
    manifest = DetectorManifestV2(
        detector_id="watchtower.dns.tunnel", name=name, input_kinds=("packet", "session"),
        finding_types=("dns.tunnel.suspected",), required_evidence={"dns.tunnel.suspected": ("domain", "query_count", "unique_labels")},
        signal_family="behavior", correlation_group="dns-tunnel",
    )
    finding_metadata = {
        "dns.tunnel.suspected": {"category": "THREAT", "impact": "HIGH", "confidence": 0.8, "mitre_technique": "T1071.004"},
    }
    WINDOW_SECONDS = 300.0
    MAX_EVENTS_PER_SOURCE = 2048

    def __init__(self, **kwargs):
        super().__init__()
        self.whitelist = self._load_whitelist()
        self.reset()

    def reset(self, source: str = None) -> None:
        self.events = defaultdict(lambda: deque(maxlen=self.MAX_EVENTS_PER_SOURCE))
        self.responses = defaultdict(lambda: deque(maxlen=self.MAX_EVENTS_PER_SOURCE))
        self.last_alert = {}

    @staticmethod
    def _registrable_domain(domain: str) -> str:
        labels = domain.rstrip(".").split(".")
        if len(labels) < 2:
            return domain
        common_two_level = {"co.uk", "com.au", "co.in", "co.jp", "com.br", "com.sg"}
        suffix = ".".join(labels[-2:])
        if suffix in common_two_level and len(labels) >= 3:
            return ".".join(labels[-3:])
        return suffix

    def _load_whitelist(self) -> List[str]:
        """Load the DNS whitelist from the centralized threat intel file."""
        import yaml
        import os
        intel_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "threat_intel.yaml")
        try:
            if os.path.exists(intel_path):
                with open(intel_path, "r") as f:
                    data = yaml.safe_load(f)
                    return data.get("dns_whitelist", [])
        except Exception:
            pass
        # Fallback to hardcoded defaults if YAML is missing/corrupt
        return ["google.com", "microsoft.com", "live.com", "office.com"]

    def detect(self, domain: str = None, packet=None, metadata=None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not domain:
            return alerts
            
        metadata = metadata or {}
        domain_lower = str(metadata.get("dns_domain") or domain).lower().rstrip(".")
        
        # 1. Skip whitelisted domains
        if any(domain_lower == white.lower() or domain_lower.endswith("." + white.lower()) for white in self.whitelist):
            return alerts
            
        labels = domain_lower.split(".")
        if len(labels) < 3:
            return alerts
        root = self._registrable_domain(domain_lower)
        left = domain_lower[:-(len(root) + 1)].split(".")[0] if domain_lower != root else ""
        entropy = self.calculate_entropy(left)
        src = "unknown"
        now = 0.0
        qtype = metadata.get("dns_qtype")
        nxdomain = bool(metadata.get("dns_nxdomain"))
        is_response = bool(metadata.get("dns_is_response"))
        if packet is not None:
            now = float(getattr(packet, "time", 0.0) or 0.0)
            if IP is not None and IP in packet: src = str(packet[IP].src)
            elif IPv6 is not None and IPv6 in packet: src = str(packet[IPv6].src)
            if DNS is not None and DNS in packet:
                qtype = int(packet[DNSQR].qtype) if DNSQR in packet else qtype
                nxdomain = int(packet[DNS].rcode or 0) == 3
                is_response = bool(int(packet[DNS].qr or 0))
        if is_response:
            client = dst = "unknown"
            if packet is not None:
                if IP is not None and IP in packet: dst = str(packet[IP].dst)
                elif IPv6 is not None and IPv6 in packet: dst = str(packet[IPv6].dst)
            response_queue = self.responses[(dst, root)]
            response_queue.append((now, nxdomain))
            while response_queue and now - response_queue[0][0] > self.WINDOW_SECONDS:
                response_queue.popleft()
            return []
        queue = self.events[src]
        queue.append((now, root, left, entropy, qtype, nxdomain, int(metadata.get("dns_query_name_bytes") or len(domain_lower))))
        while queue and now - queue[0][0] > self.WINDOW_SECONDS:
            queue.popleft()
        related = [event for event in queue if event[1] == root]
        unique_labels = {event[2] for event in related}
        suspicious_labels = [event for event in related if self._suspicious_label(event[2], event[3])]
        responses = self.responses[(src, root)]
        while responses and now - responses[0][0] > self.WINDOW_SECONDS:
            responses.popleft()
        nxdomain_ratio = sum(event[1] for event in responses) / len(responses) if responses else 0.0
        has_txt = any(event[4] == 16 for event in related)
        volume = sum(event[6] for event in related)
        corroborated = nxdomain_ratio >= 0.5 or has_txt or volume >= 4096
        key = (src, root)
        if len(related) >= 20 and len(unique_labels) >= 10 and len(suspicious_labels) >= 10 and corroborated and now - self.last_alert.get(key, -10000) >= self.WINDOW_SECONDS:
            self.last_alert[key] = now
            alerts.append(ForensicAlert(
                timestamp=now,
                type="SUSPICIOUS_DNS",
                severity="HIGH",
                score=55.0,
                explanation=f"Sustained encoded DNS labels were observed below {root}",
                evidence={"domain": root, "query_count": len(related), "unique_labels": len(unique_labels), "nxdomain_ratio": round(nxdomain_ratio, 3), "txt_queries": has_txt, "query_name_bytes": volume}
            ))
            
        return alerts

    @staticmethod
    def _suspicious_label(label: str, entropy: float) -> bool:
        if len(label) < 20:
            return False
        # Hex encodings have a four-bit alphabet, so realistic random samples
        # cluster below the generic 3.8 bits/character threshold.
        if re.fullmatch(r"[0-9a-fA-F]{32,}", label):
            return entropy >= 3.4
        return entropy >= 3.8

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            entropy -= p_x * math.log2(p_x)
        return entropy

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ─── Minimum sample counts before statistical scoring activates ───────────────
# Z-scores are meaningless with <10 observations (Welford's needs warm-up)
_MIN_ZSCORE_SAMPLES = 10

class OnlineStats:
    """ Numerically stable online variance algorithm (Welford's). """
    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, x: float):
        self.count += 1
        delta = x - self.mean
        self.mean += delta / self.count
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / self.count if self.count > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        if self.count < _MIN_ZSCORE_SAMPLES:
            return 0.0  # Not enough data to score reliably
        sd = self.std_dev
        if sd == 0:
            return 0.0
        return (x - self.mean) / sd

@dataclass
class HostBaseline:
    packet_count: OnlineStats = field(default_factory=OnlineStats)
    byte_count: OnlineStats = field(default_factory=OnlineStats)
    flow_count: OnlineStats = field(default_factory=OnlineStats)
    unique_dests: OnlineStats = field(default_factory=OnlineStats)

class BehavioralEngine:
    """
    Tracks long-term historical baselines using the Database.
    Focuses on 'Who talks to Who' (Peer Matrix) and Subnet Roles.
    """
    def __init__(self, db):
        self.db = db
        self._peer_cache = set() # (src_ip, dst_ip)
        self._subnet_roles = {}
        self._load_subnet_roles()

    def _load_subnet_roles(self):
        import yaml
        import os
        try:
            intel_path = "core/threat_intel.yaml"
            if os.path.exists(intel_path):
                with open(intel_path, "r") as f:
                    data = yaml.safe_load(f)
                    self._subnet_roles = data.get("subnets", {})
        except Exception:
            pass

    def check_peer_anomaly(self, src_ip, dst_ip) -> float:
        """
        Returns a score based on whether this peer pair has been seen before.
        """
        pair = (src_ip, dst_ip)
        if pair in self._peer_cache:
            return 0.0
            
        if self.db.behavioral_peer_seen(src_ip, dst_ip):
            self._peer_cache.add(pair)
            return 0.0
        
        # New relationship!
        return 20.0 # Initial anomaly score

    def get_context_multiplier(self, ip: str, alert_type: str) -> float:
        """
        Adjusts sensitivity based on subnet roles.
        """
        import ipaddress
        for cidr, cfg in self._subnet_roles.items():
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    # If IoT zone and local discovery, suppress
                    if cfg.get("role") == "IOT" and alert_type == "SUSPICIOUS_DNS" and cfg.get("trust_local_discovery"):
                        return 0.2
                    return cfg.get("sensitivity", 1.0)
            except Exception:
                continue
        return 1.0

class AnalyticsEngine:
    def __init__(self):
        # Global baselines
        self.global_bps = OnlineStats()
        self.global_pps = OnlineStats()
        
        # Per-host baselines
        self.host_baselines: Dict[str, HostBaseline] = {}

    def get_host_baseline(self, ip: str) -> HostBaseline:
        if ip not in self.host_baselines:
            self.host_baselines[ip] = HostBaseline()
        return self.host_baselines[ip]

    def compute_behavior_score(self, flow, host_stats=None) -> float:
        """
        Computes a combined behavioral anomaly score (0-100+).
        Uses Z-scores from global and per-host baselines.
        Requires minimum sample counts to avoid cold-start false positives.
        """
        score = 0.0
        
        # 1. Flow-level anomalies
        f_duration = flow.duration()
        if f_duration > 0.1: # Only score PPS for established flows
            pps = flow.packet_count / f_duration
            if pps > 5000: score += 15 # High volume burst
            
        # Refined Scanning behavior: High SYNs relative to total packets
        # Require more evidence to avoid triggering on mDNS/SSDP discovery
        if flow.tcp_syn_count > 20 and flow.packet_count < 30:
            score += 35 # Potential scanning
        elif flow.tcp_syn_count > 10 and flow.packet_count < 15:
            score += 15 # Suspiciously low response rate

        # 2. Host-level Z-score deviations
        # Only fires after _MIN_ZSCORE_SAMPLES observations (warm-up period)
        if host_stats and flow.src_ip in self.host_baselines:
            hb = self.host_baselines[flow.src_ip]
            
            # Cap Z-score contribution to prevent single-outlier explosions
            z_bytes = min(abs(hb.byte_count.z_score(flow.byte_count)), 5.0)
            z_packets = min(abs(hb.packet_count.z_score(flow.packet_count)), 5.0)
            
            score += z_bytes * 5
            score += z_packets * 5
            
        return min(max(score, 0.0), 150.0)


    def update_baselines(self, snapshot):
        """ Update rolling averages from a window snapshot. """
        self.global_bps.update(snapshot.total_bytes / 10.0) # assuming 10s window
        self.global_pps.update(snapshot.total_packets / 10.0)
        
        # Update host baselines if per-host data exists in snapshot
        # (This will be expanded as we add host tracking to snapshots)
        pass


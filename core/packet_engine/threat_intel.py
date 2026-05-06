#Not Used.Will Cleanup later
import re
from typing import Dict, List, Set, Optional
from dataclasses import dataclass

@dataclass
class ThreatRule:
    id: str
    name: str
    description: str
    weight: float

class ThreatIntelEngine:
    def __init__(self):
        # Phase 1: Basic signature-based matchers
        self.malicious_ips: Set[str] = set()
        self.malicious_ports: Set[int] = {6667, 9999, 4444} # Example suspicious ports
        
        # In a real scenario, these would be loaded from a feed/DB
        self.malicious_ips.add("1.2.3.4") 

    def check_flow(self, flow, forensics_engine=None) -> float:
        """ Returns a threat score based on matching IOCs and rules. """
        score = 0.0
        
        # Pull fields from flow_id tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
        src_ip, dst_ip, src_port, dst_port, protocol = flow.flow_id

        # 1. IOC Matching (IPs)
        if src_ip in self.malicious_ips or dst_ip in self.malicious_ips:
            score += 50
            
        # 2. Port Matching
        if dst_port in self.malicious_ports:
            score += 20

        # 3. Dynamic Forensic Analysis
        if forensics_engine:
            alerts = forensics_engine.analyze_flow(flow)
            for alert in alerts:
                score += alert.score
            
        # 5. Legacy Signatures
        if hasattr(flow, "tcp_syn_count") and flow.tcp_syn_count > 30 and flow.byte_count < 2000:
            score += 30
        elif hasattr(flow, "tcp_syn_count") and flow.tcp_syn_count > 15 and flow.byte_count < 1000:
            score += 15
            
        return score


    def get_explanation(self, flow) -> str:
        src_ip, dst_ip, src_port, dst_port, protocol = flow.flow_id
        
        if src_ip in self.malicious_ips:
            return f"Source IP {src_ip} matches known malicious IOC."
        if dst_port in self.malicious_ports:
            return f"Traffic to suspicious port {dst_port} detected."
        if hasattr(flow, "tcp_syn_count") and flow.tcp_syn_count > 10 and flow.byte_count < 1000:
            return "Potential SYN scanning behavior detected."
        return ""

import math
from typing import List, Optional
from core.forensics.base import BaseDetector
from core.forensics.models import ForensicAlert

class DNSDetector(BaseDetector):
    name = "DNS Anomaly Detector"

    def __init__(self, **kwargs):
        super().__init__()
        self.whitelist = self._load_whitelist()

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

    def detect(self, domain: str = None, **kwargs) -> List[ForensicAlert]:
        alerts = []
        if not domain:
            return alerts
            
        domain_lower = domain.lower()
        
        # 1. Skip whitelisted domains
        if any(white in domain_lower for white in self.whitelist):
            return alerts
            
        # 2. Basic Entropy Check
        entropy = self.calculate_entropy(domain)
        
        # 3. Refined Randomness Heuristics
        # DGA domains often have low vowel ratios and high digit counts
        vowels = sum(1 for c in domain_lower if c in "aeiou")
        vowel_ratio = vowels / len(domain) if len(domain) > 0 else 1.0
        digits = sum(1 for c in domain_lower if c.isdigit())
        
        # Alert if:
        # - High entropy AND long domain
        # - AND (Low vowel ratio OR high digit count)
        is_suspicious = False
        if len(domain) > 25 and entropy >= 3.9:
            if vowel_ratio < 0.25 or digits > 4:
                is_suspicious = True
        elif len(domain) > 15 and entropy >= 4.2:
             is_suspicious = True

        if is_suspicious:
            alerts.append(ForensicAlert(
                timestamp=0.0,
                type="SUSPICIOUS_DNS",
                severity="MEDIUM",
                score=25.0,
                explanation=f"Potential DGA or Data Exfiltration domain detected (entropy: {entropy:.2f}, vowel_ratio: {vowel_ratio:.2f})",
                evidence={"domain": domain, "entropy": entropy, "vowel_ratio": vowel_ratio, "digits": digits}
            ))
            
        return alerts

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            entropy -= p_x * math.log2(p_x)
        return entropy

import os
import yaml
import logging
from typing import List, Dict, Any
from core.storage.database import WatchtowerDB
from core.forensics.models import ForensicAlert
from core.forensics.forwarder import AlertForwarder

logger = logging.getLogger(__name__)

class SigmaEngine:
    """Lightweight Sigma rule parser and execution engine for Watchtower network data."""
    
    def __init__(self, plugins_dir="core/forensics/plugins/sigma"):
        self.plugins_dir = plugins_dir
        self.rules = []
        self.db = WatchtowerDB()
        self.forwarder = AlertForwarder(config={"enabled": False}) # Future integration
        self.load_rules()

    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            return

        for filename in os.listdir(self.plugins_dir):
            if filename.endswith(".yml") or filename.endswith(".yaml"):
                path = os.path.join(self.plugins_dir, filename)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        if rule and "detection" in rule:
                            self.rules.append(rule)
                except Exception as e:
                    logger.error(f"Failed to load Sigma rule {filename}: {e}")

    def run_hunt(self, source: str = None, specific_rule: str = None) -> List[ForensicAlert]:
        """
        Runs the loaded Sigma rules against the stored database flows and entities.
        If `source` is provided, filters the historical data to only match that capture session.
        """
        alerts = []
        
        # 1. Fetch data
        flows = self.db.get_flows(limit=100000) # Arbitrary large limit for hunting
        entities = self.db.get_all_entities()

        if source:
            flows = [f for f in flows if f.get("source") == source]
            entities = [e for e in entities if e.get("source") == source]

        # 2. Evaluate rules
        for rule in self.rules:
            title = rule.get("title", "Unknown Rule")
            if specific_rule and title != specific_rule:
                continue
                
            level = rule.get("level", "medium").upper()
            if level == "MEDIUM": level = "HIGH" # Map to our severity
            if level == "INFORMATIONAL": level = "LOW"
                
            score = {"CRITICAL": 85.0, "HIGH": 60.0, "MEDIUM": 40.0, "LOW": 10.0}.get(level, 50.0)
            
            category = rule.get("logsource", {}).get("category", "")
            detection = rule.get("detection", {}).get("selection", {})
            
            if not detection:
                continue

            if category == "network_connection":
                # Evaluate against Flows
                for flow in flows:
                    if self._match(flow, detection):
                        alert = ForensicAlert(
                            timestamp=flow.get("start_time", 0.0),
                            type="SIGMA_MATCH",
                            severity=level,
                            score=score,
                            explanation=f"Sigma Rule Match: {title}",
                            evidence={"rule": title, "flow": f"{flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}"}
                        )
                        alerts.append((alert, flow.get("src_ip", "0.0.0.0"), flow.get("source", "live")))
            
            elif category == "network_identity":
                # Evaluate against Entities
                for entity in entities:
                    if self._match(entity, detection):
                        alert = ForensicAlert(
                            timestamp=entity.get("timestamp", 0.0),
                            type="SIGMA_MATCH",
                            severity=level,
                            score=score,
                            explanation=f"Sigma Rule Match: {title}",
                            evidence={"rule": title, "entity_ip": entity.get("ip")}
                        )
                        alerts.append((alert, entity.get("ip", "0.0.0.0"), entity.get("source", "live")))

        # 3. Store and forward matched alerts
        final_alerts = []
        for alert, src_ip, alert_source in alerts:
            self.db.insert_alert(
                entity_ip=src_ip, timestamp=alert.timestamp,
                alert_type=alert.type, severity=alert.severity,
                score=alert.score, explanation=alert.explanation,
                evidence=alert.evidence, source=alert_source
            )
            self.forwarder.forward(alert, src_ip)
            final_alerts.append(alert)

        return final_alerts

    def _match(self, record: dict, selection: dict) -> bool:
        """Simple subset matching. Returns True if all key-values in selection match the record."""
        for key, expected in selection.items():
            actual = record.get(key)
            if actual is None:
                return False
                
            # If expected is a list, check if actual is in it (OR condition)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            # Otherwise simple equality
            elif str(actual).lower() != str(expected).lower():
                return False
                
        return True

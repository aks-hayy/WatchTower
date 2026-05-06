import requests
import json
import logging
import threading
import queue
from core.forensics.models import ForensicAlert

logger = logging.getLogger(__name__)

class AlertForwarder:
    """Forwards ForensicAlert objects to external SIEMs (Splunk, ElasticSearch, Webhooks)."""

    def __init__(self, config=None):
        import os
        self.config = config or {}
        # Read from config dict, fallback to environment variables
        self.siem_type = self.config.get("siem_type", os.environ.get("WT_SIEM_TYPE", "")).lower()
        self.target_url = self.config.get("target_url", os.environ.get("WT_SIEM_URL", ""))
        self.auth_token = self.config.get("auth_token", os.environ.get("WT_SIEM_TOKEN", ""))
        self.enabled = self.config.get("enabled", bool(self.target_url and self.siem_type))
        self.queue = queue.Queue()
        
        if self.enabled:
            self._worker_thread = threading.Thread(target=self._forward_loop, daemon=True)
            self._worker_thread.start()

    def forward(self, alert: ForensicAlert, entity_ip: str):
        if not self.enabled:
            return
        
        payload = {
            "timestamp": alert.timestamp,
            "entity_ip": entity_ip,
            "alert_type": alert.type,
            "severity": alert.severity,
            "score": alert.score,
            "explanation": alert.explanation,
            "evidence": alert.evidence
        }
        self.queue.put(payload)

    def _forward_loop(self):
        while True:
            try:
                payload = self.queue.get()
                self._send(payload)
                self.queue.task_done()
            except Exception as e:
                logger.error(f"Error in AlertForwarder loop: {e}")

    def _send(self, payload: dict):
        try:
            headers = {"Content-Type": "application/json"}
            
            if self.siem_type == "splunk":
                headers["Authorization"] = f"Splunk {self.auth_token}"
                # Splunk HEC requires specific format
                data = {"event": payload, "sourcetype": "watchtower:alert"}
            elif self.siem_type == "elastic":
                if self.auth_token:
                    headers["Authorization"] = f"ApiKey {self.auth_token}"
                data = payload
            elif self.siem_type == "slack":
                color = "#ff0000" if payload["severity"].upper() in ["HIGH", "CRITICAL"] else "#ffcc00"
                data = {
                    "attachments": [
                        {
                            "color": color,
                            "title": f"Watchtower Alert: {payload['alert_type']}",
                            "text": payload["explanation"],
                            "fields": [
                                {"title": "Entity IP", "value": payload["entity_ip"], "short": True},
                                {"title": "Severity", "value": payload["severity"], "short": True},
                                {"title": "Risk Score", "value": str(payload["score"]), "short": True}
                            ],
                            "footer": "Watchtower Forensic Engine"
                        }
                    ]
                }
            else:
                # Generic webhook
                if self.auth_token:
                    headers["Authorization"] = f"Bearer {self.auth_token}"
                data = payload

            requests.post(self.target_url, json=data, headers=headers, timeout=5)
        except Exception as e:
            logger.error(f"Failed to forward alert to {self.target_url}: {e}")

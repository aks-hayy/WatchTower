import os
import requests
import hashlib
from typing import Dict, Optional

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self._cache = {}

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        
        if file_hash in self._cache:
            return self._cache[file_hash]
        
        headers = {
            "x-apikey": self.api_key
        }
        
        try:
            result = None
            response = requests.get(f"{self.base_url}/files/{file_hash}", headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values())
                }
            elif response.status_code == 404:
                result = {"status": "not_found"}
            elif response.status_code == 429:
                print("VirusTotal API rate limit reached (Public API: 4 reqs/min).")
                result = {"status": "rate_limited"}
            else:
                result = {"status": "error", "code": response.status_code}
            
            if result:
                self._cache[file_hash] = result
                return result
        except Exception as e:
            print(f"Error checking VirusTotal: {e}")
        
        return None

def get_file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

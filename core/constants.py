# core/constants.py
# Centralized thresholds and magic numbers for Watchtower.

# --- Alert & Scoring Thresholds ---
ALERT_THRESHOLD = 60          # Generate an alert when final_score exceeds this
EVIDENCE_TRIGGER = 90         # Auto-PCAP carving when score exceeds this
HIGH_RISK_ENTITY = 50         # Entity flagged as high-risk in reports
SIEM_FORWARD_THRESHOLD = 70   # Future: SIEM forwarding threshold

# --- Beaconing Detection ---
BEACON_MIN_PACKETS = 15       # Minimum packets to evaluate periodicity
BEACON_CV_THRESHOLD = 0.1     # Coefficient of variation threshold for beaconing
BEACON_MIN_INTERVAL = 0.5     # Minimum average interval (seconds) to flag

# --- DNS Entropy ---
DNS_ENTROPY_THRESHOLD = 4.0   # Shannon entropy above this is suspicious
DNS_MIN_LENGTH = 12           # Minimum domain length to check entropy

# --- Scanning Detection ---
SCAN_HIGH_SYN_COUNT = 20      # SYN count indicating scanning
SCAN_LOW_PACKET_RATIO = 30    # If packet_count < this with high SYNs → scan

# --- Flow Worker ---
FLOW_TIMEOUT = 30             # Seconds before a flow is considered expired
SNAPSHOT_INTERVAL = 5         # Seconds between snapshots (step_size default)

# --- Data Exfiltration ---
EXFIL_BYTE_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# --- File Carving ---
MIN_CARVED_FILE_SIZE = 100    # Minimum bytes for a carved file to be kept
MAX_CARVED_FILE_STORE = 1024 * 1024  # 1 MB — only store in DB if smaller
MAX_STREAM_BYTES = 16 * 1024 * 1024  # Per direction, per flow
MAX_STREAM_SEGMENTS = 10000
MAX_REASSEMBLY_GAP = 64 * 1024

# --- Forensic Ports (high-value for topology graph) ---
FORENSIC_PORTS = {88, 135, 139, 389, 443, 445, 636, 3389, 5985, 5986, 8080}
FORENSIC_TERMINAL_STATES = frozenset(
    {"complete", "partial", "cancelled", "failed"}
)

# --- C2 & Suspect Traffic ---
def _load_intel_config():
    import yaml
    import os
    intel_path = os.path.join(os.path.dirname(__file__), "threat_intel.yaml")
    if os.path.exists(intel_path):
        try:
            with open(intel_path, "r") as f:
                return yaml.safe_load(f)
        except Exception:
            pass
    return {}

_intel = _load_intel_config()

C2_PORTS = set(_intel.get("c2_ports", [6667, 9999, 4444, 1337]))
INTERNAL_IP_PREFIXES = tuple(_intel.get("internal_prefixes", ["192.168.", "10.", "127.", "172."]))

# --- Alert Cooldowns ---
ALERT_COOLDOWN = 300  # 5 minutes

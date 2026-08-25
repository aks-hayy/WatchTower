import sys
import argparse
import multiprocessing
from pathlib import Path
import time
from core.context import context
from core.daemon.manager import DaemonManager
from core.daemon.client import DaemonClient
from rich.console import Console

if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass

console = Console()

ASCII_ART = r"""
[bold cyan]
  █████   ███   █████   █████████   ███████████   █████████  █████   █████ ███████████    ███████    █████   ███   █████ ██████████ ███████████  
▒▒███   ▒███  ▒▒███   ███▒▒▒▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███▒▒███   ▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███ ▒▒███   ▒███  ▒▒███ ▒▒███▒▒▒▒▒█▒▒███▒▒▒▒▒███ 
 ▒███   ▒███   ▒███  ▒███    ▒███ ▒   ▒███  ▒  ███     ▒▒▒  ▒███    ▒███ ▒   ▒███  ▒  ███     ▒▒███ ▒███   ▒███   ▒███  ▒███  █ ▒  ▒███    ▒███ 
 ▒███   ▒███   ▒███  ▒███████████     ▒███    ▒███          ▒███████████     ▒███    ▒███      ▒███ ▒███   ▒███   ▒███  ▒██████    ▒██████████  
 ▒▒███  █████  ███   ▒███▒▒▒▒▒███     ▒███    ▒███          ▒███▒▒▒▒▒███     ▒███    ▒███      ▒███ ▒▒███  █████  ███   ▒███▒▒█    ▒███▒▒▒▒▒███ 
  ▒▒▒█████▒█████▒    ▒███    ▒███     ▒███    ▒▒███     ███ ▒███    ▒███     ▒███    ▒▒███     ███   ▒▒▒█████▒█████▒    ▒███ ▒   █ ▒███    ▒███ 
    ▒▒███ ▒▒███      █████   █████    █████    ▒▒█████████  █████   █████    █████    ▒▒▒███████▒      ▒▒███ ▒▒███      ██████████ █████   █████
     ▒▒▒   ▒▒▒      ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒      ▒▒▒▒▒▒▒▒▒  ▒▒▒▒▒   ▒▒▒▒▒    ▒▒▒▒▒       ▒▒▒▒▒▒▒         ▒▒▒   ▒▒▒      ▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒ 
[/bold cyan]
"""

# Keep startup reliable in redirected and legacy Windows terminals.
ASCII_ART = r"""
[bold cyan]
 __        __    _       _     _____
 \ \      / /_ _| |_ ___| |__ |_   _|____      _____ _ __
  \ \ /\ / / _` | __/ __| '_ \  | |/ _ \ \ /\ / / _ \ '__|
   \ V  V / (_| | || (__| | | | | | (_) \ V  V /  __/ |
    \_/\_/ \__,_|\__\___|_| |_| |_|\___/ \_/\_/ \___|_|
[/bold cyan]
"""

def main():
    parser = argparse.ArgumentParser(
        prog="tower",
        description="Watchtower — Network Forensics & Traffic Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Core Commands
    subparsers.add_parser("shell", help="Enter interactive shell (default)")
    ui_parser = subparsers.add_parser("ui", help="Launch the local Web Dashboard and API")
    ui_parser.add_argument("--port", type=int, default=4173, help="Dashboard port (default: 4173)")
    ui_parser.add_argument("--api-port", type=int, default=8000, help="Local API port (default: 8000)")
    ui_parser.add_argument("--no-open", action="store_true", help="Do not open the dashboard in a browser")
    auth_parser = subparsers.add_parser("auth", help="Manage local operator authentication")
    auth_commands = auth_parser.add_subparsers(dest="auth_command", required=True)
    auth_setup = auth_commands.add_parser("setup", help="Configure the first local operator")
    auth_setup.add_argument("--disable", action="store_true", help="Explicitly disable application authentication")
    auth_setup.add_argument("--name", default="Local Operator")
    auth_commands.add_parser("unlock", help="Create an eight-hour CLI session")
    auth_lock = auth_commands.add_parser("lock", help="Lock this CLI session")
    auth_lock.add_argument("--all", action="store_true", dest="all_sessions")
    auth_commands.add_parser("status", help="Show authentication and session state")
    auth_commands.add_parser("factors", help="Show configured PIN and passkey factors")
    auth_settings = auth_commands.add_parser("settings", help="Enable or disable application authentication")
    auth_setting_group = auth_settings.add_mutually_exclusive_group(required=True)
    auth_setting_group.add_argument("--enable", action="store_true")
    auth_setting_group.add_argument("--disable", action="store_true")
    auth_recovery = auth_commands.add_parser("recovery", help="Recover local operator access")
    auth_recovery_commands = auth_recovery.add_subparsers(dest="auth_recovery_command", required=True)
    auth_reset = auth_recovery_commands.add_parser("reset", help="Reset the operator PIN and recovery code")
    auth_reset.add_argument("--os-admin", action="store_true")
    auth_reset.add_argument("--reason", default="")
    chat_parser = subparsers.add_parser("chat", help="Open the shared WatchTower analyst conversation")
    chat_parser.add_argument("--conversation", help="Existing analyst conversation ID")
    chat_parser.add_argument("--source", help="Capture source scope")
    chat_parser.add_argument("--interface", help="Capture interface scope")
    chat_parser.add_argument("--session", help="Capture session scope")
    chat_parser.add_argument("--node", help="Sensor mesh node scope")
    chat_parser.add_argument("--provider", choices=["ollama", "openai"], default="ollama")
    chat_parser.add_argument("--research", choices=["auto", "off"], default="auto")
    chat_parser.add_argument("--mode", choices=["auto", "general", "investigate", "action"], default="auto")
    chat_parser.add_argument("--prompt", help="Run one prompt without entering the interactive chat")
    ai_parser = subparsers.add_parser("ai", help="Manage local analyst providers and conversations")
    ai_commands = ai_parser.add_subparsers(dest="ai_command", required=True)
    ai_commands.add_parser("status", help="Show analyst providers, tools, and readiness")
    ai_providers = ai_commands.add_parser("providers", help="Show configured model providers")
    ai_providers.add_argument("action", choices=["list"], default="list", nargs="?")
    ai_provider = ai_commands.add_parser("provider", help="Connect, test, or disconnect a model provider")
    ai_provider_commands = ai_provider.add_subparsers(dest="ai_provider_command", required=True)
    ai_provider_connect = ai_provider_commands.add_parser("connect", help="Connect a model provider")
    ai_provider_connect.add_argument("provider", choices=["ollama", "openai"])
    ai_provider_connect.add_argument("--model")
    ai_provider_connect.add_argument("--base-url")
    ai_provider_test = ai_provider_commands.add_parser("test", help="Test provider connectivity")
    ai_provider_test.add_argument("provider", choices=["ollama", "openai"])
    ai_provider_disconnect = ai_provider_commands.add_parser("disconnect", help="Remove provider credentials and disable it")
    ai_provider_disconnect.add_argument("provider", choices=["ollama", "openai"])
    ai_models = ai_commands.add_parser("models", help="List compatible provider models")
    ai_models.add_argument("action", choices=["list"], default="list", nargs="?")
    ai_models.add_argument("--provider", choices=["ollama", "openai"], default="ollama")
    ai_models.add_argument("--refresh", action="store_true")
    ai_model = ai_commands.add_parser("model", help="Select a default provider model")
    ai_model_commands = ai_model.add_subparsers(dest="ai_model_command", required=True)
    ai_model_set = ai_model_commands.add_parser("set", help="Select the default model")
    ai_model_set.add_argument("model")
    ai_model_set.add_argument("--provider", choices=["ollama", "openai"], default="ollama")
    ai_chatgpt = ai_commands.add_parser("chatgpt", help="Friendly OpenAI API connection alias")
    ai_chatgpt.add_argument("action", choices=["auth"], default="auth", nargs="?")
    ai_chatgpt.add_argument("--model")
    ai_research = ai_commands.add_parser("research", help="Show controlled research sources")
    ai_research.add_argument("action", choices=["sources", "status"], default="sources", nargs="?")
    ai_conversations = ai_commands.add_parser("conversations", help="List stored analyst conversations")
    ai_conversations.add_argument("action", choices=["list"], default="list", nargs="?")
    ai_credentials = ai_commands.add_parser("credentials", help="Manage Windows Credential Manager references")
    ai_credentials.add_argument("action", choices=["set", "delete", "status"])
    ai_credentials.add_argument("reference", nargs="?")
    
    # Engine Control
    start_parser = subparsers.add_parser("start", help="Start packet capture engine")
    start_parser.add_argument("-i", "--interface", help="Network interface to monitor")
    start_parser.add_argument("-b", "--background", action="store_true", help="Start in persistent background mode")
    start_parser.add_argument("--backend", choices=["python", "rust"], help="Capture core")
    start_parser.add_argument("--source-type", choices=["network", "bluetooth"], default="network", help="Capture source type")
    
    stop_parser = subparsers.add_parser("stop", help="Stop packet capture engine")
    stop_parser.add_argument("-i", "--interface", help="Specific interface to stop")
    
    # Forensic Commands
    analyze_parser = subparsers.add_parser("analyze", help="Analyze offline PCAP files")
    analyze_parser.add_argument("filename", help="Path to PCAP file")
    analyze_parser.add_argument("--mode", choices=["auto", "memory", "streaming"], default="auto")
    analyze_parser.add_argument("--backend", choices=["python", "rust"])
    analyze_parser.add_argument("--keylog", help="TLS key log file")
    
    # Daemon Control
    daemon_parser = subparsers.add_parser("daemon", help="Manage background service")
    daemon_parser.add_argument("action", choices=["start", "stop", "restart", "repair", "status", "bg"])
    
    # Background Mode (Global)
    bg_parser = subparsers.add_parser("background", help="Interactive background mode setup")



    # Direct Forensic Commands (Exposed for AI/CLI parity)
    flows_parser = subparsers.add_parser("flows", help="Show recent network flows")
    flows_parser.add_argument("ip", nargs="?", help="IP to filter")
    flows_parser.add_argument("limit", type=int, nargs="?", help="Max results")
    flows_parser.add_argument("--limit", dest="limit_option", type=int, help="Max results")
    flows_parser.add_argument("--source", help="Source filter")
    flows_parser.add_argument("--interface", help="Capture interface filter")
    flows_parser.add_argument("--session", help="Capture session filter")
    alerts_parser = subparsers.add_parser("alerts", help="Show recent security alerts")
    alerts_parser.add_argument("arguments", nargs="*", help="IP/limit or disposition ID")
    alerts_parser.add_argument("--limit", dest="limit_option", type=int, help="Max results")
    alerts_parser.add_argument("--source", help="Source filter")
    alerts_parser.add_argument("--interface", help="Capture interface filter")
    alerts_parser.add_argument("--session", help="Capture session filter")
    alerts_parser.add_argument("--verdict", choices=["true_positive", "false_positive", "benign_expected", "unknown"], help=argparse.SUPPRESS)
    alerts_parser.add_argument("--reason", default="", help=argparse.SUPPRESS)
    alerts_parser.add_argument("--actor", default="local-analyst", help=argparse.SUPPRESS)
    stats_parser = subparsers.add_parser("stats", help="Show live traffic stats")
    stats_parser.add_argument("--interface", help="Capture interface filter")
    subparsers.add_parser("sources", help="List pluggable capture sources")
    endpoint_parser = subparsers.add_parser("endpoint", help="Inspect endpoint telemetry and process attribution")
    endpoint_commands = endpoint_parser.add_subparsers(dest="endpoint_command", required=True)
    endpoint_sysmon = endpoint_commands.add_parser("sysmon", help="Inspect Sysmon endpoint telemetry")
    endpoint_sysmon.add_argument("action", choices=["status"], default="status", nargs="?")
    endpoint_processes = endpoint_commands.add_parser("processes", help="List redacted endpoint process observations")
    endpoint_processes.add_argument("--ip")
    endpoint_processes.add_argument("--limit", type=int, default=50)
    mesh_parser = subparsers.add_parser("mesh", help="Manage secure WatchTower sensor mesh")
    mesh_commands = mesh_parser.add_subparsers(dest="mesh_command", required=True)
    mesh_controller = mesh_commands.add_parser("controller", help="Initialize or serve the mesh controller")
    mesh_controller_commands = mesh_controller.add_subparsers(dest="mesh_controller_command", required=True)
    mesh_controller_init = mesh_controller_commands.add_parser("init", help="Create the local mesh certificate authority")
    mesh_controller_init.add_argument("--host", default="127.0.0.1")
    mesh_controller_setup = mesh_controller_commands.add_parser("setup", help="Configure the mesh controller connectivity profile")
    mesh_controller_setup.add_argument("--mode", choices=["local", "vpn", "public"], default="local")
    mesh_controller_setup.add_argument("--address", help="Address remote sensors use to reach this controller")
    mesh_controller_setup.add_argument("--enrollment-port", type=int, default=9443)
    mesh_controller_setup.add_argument("--ingest-port", type=int, default=9444)
    mesh_controller_setup.add_argument("--acknowledge-public-risk", action="store_true")
    mesh_controller_commands.add_parser("start", help="Start the configured controller in the background")
    mesh_controller_commands.add_parser("stop", help="Drain and stop the controller")
    mesh_controller_commands.add_parser("restart", help="Drain and restart the controller")
    mesh_controller_commands.add_parser("rotate-certificate", help="Rotate the controller listener certificate")
    mesh_controller_commands.add_parser("status", help="Show controller health and registered nodes")
    mesh_controller_serve = mesh_controller_commands.add_parser("serve", help="Start mTLS enrollment and ingest listeners")
    mesh_controller_serve.add_argument("--host", default="127.0.0.1")
    mesh_controller_serve.add_argument("--enrollment-port", type=int, default=9443)
    mesh_controller_serve.add_argument("--ingest-port", type=int, default=9444)
    mesh_enroll = mesh_commands.add_parser("enroll", help="Create a one-time agent enrollment token")
    mesh_enroll.add_argument("--name")
    mesh_enroll.add_argument("--ttl", type=int, default=3600)
    mesh_enroll.add_argument("--max-uses", type=int, default=1)
    mesh_nodes = mesh_commands.add_parser("nodes", help="Add, inspect, or remove sensor nodes")
    mesh_node_commands = mesh_nodes.add_subparsers(dest="mesh_nodes_command")
    mesh_node_commands.add_parser("list", help="List registered mesh nodes")
    mesh_nodes_add = mesh_node_commands.add_parser("add", help="Create a short-lived node join package")
    mesh_nodes_add.add_argument("--name")
    mesh_nodes_add.add_argument("--ttl", type=int, default=3600)
    mesh_nodes_add.add_argument("--output", help="Write the unattended enrollment package to a file")
    mesh_nodes_show = mesh_node_commands.add_parser("show", help="Show one sensor node")
    mesh_nodes_show.add_argument("node_id")
    mesh_nodes_remove = mesh_node_commands.add_parser("remove", help="Revoke and decommission a sensor node")
    mesh_nodes_remove.add_argument("node_id")
    mesh_nodes_remove.add_argument("--reason", required=True)
    mesh_revoke = mesh_commands.add_parser("revoke", help="Revoke a mesh node certificate")
    mesh_revoke.add_argument("node_id")
    mesh_revoke.add_argument("--reason", required=True)
    mesh_agent = mesh_commands.add_parser("agent", help="Enroll and operate this sensor node")
    mesh_agent_commands = mesh_agent.add_subparsers(dest="mesh_agent_command", required=True)
    mesh_agent_enroll = mesh_agent_commands.add_parser("enroll", help="Enroll this node with a controller")
    mesh_agent_enroll.add_argument("--controller", required=True)
    mesh_agent_enroll.add_argument("--token", required=True)
    mesh_agent_enroll.add_argument("--ca", required=True, help="Controller CA PEM file")
    mesh_agent_enroll.add_argument("--name")
    mesh_agent_enroll.add_argument("--enrollment-port", type=int, default=9443)
    mesh_agent_enroll.add_argument("--ingest-port", type=int, default=9444)
    mesh_agent_join = mesh_agent_commands.add_parser("join", help="Join a controller using a verified enrollment package")
    mesh_agent_join.add_argument("package", nargs="?", help="WTJ1 enrollment package; prompted securely when omitted")
    mesh_agent_join.add_argument("--package-file", help="Read the enrollment package from a regular file")
    mesh_agent_join.add_argument("--name")
    mesh_agent_join.add_argument("--yes", action="store_true", help="Accept the displayed controller fingerprint")
    mesh_agent_start = mesh_agent_commands.add_parser("start", help="Start this sensor agent in the background")
    mesh_agent_start.add_argument("--interval", type=int, default=10)
    mesh_agent_start.add_argument("--limit", type=int, default=250)
    mesh_agent_commands.add_parser("stop", help="Flush and stop this sensor agent")
    mesh_agent_restart = mesh_agent_commands.add_parser("restart", help="Flush and restart this sensor agent")
    mesh_agent_restart.add_argument("--interval", type=int, default=10)
    mesh_agent_restart.add_argument("--limit", type=int, default=250)
    mesh_agent_leave = mesh_agent_commands.add_parser("leave", help="Revoke this node and remove local mesh credentials")
    mesh_agent_leave.add_argument("--reason", default="Operator removed this sensor")
    mesh_agent_leave.add_argument("--force", action="store_true")
    mesh_agent_commands.add_parser("status", help="Show this node's enrollment and spool health")
    mesh_agent_sync = mesh_agent_commands.add_parser("sync", help="Collect and flush one bounded telemetry batch")
    mesh_agent_sync.add_argument("--limit", type=int, default=250)
    mesh_agent_run = mesh_agent_commands.add_parser("run", help="Continuously collect and flush telemetry")
    mesh_agent_run.add_argument("--interval", type=int, default=10)
    mesh_agent_run.add_argument("--limit", type=int, default=250)
    
    dive_parser = subparsers.add_parser("dive", help="Deep dive investigation into an IP")
    dive_parser.add_argument("ip", help="IP address to investigate")
    dive_parser.add_argument("--source", help="Data source filter")
    dive_parser.add_argument("--export", nargs="?", const="", metavar="CASE_NAME", help="Export a hashed case bundle")
    
    lookup_parser = subparsers.add_parser("lookup", help="IP intelligence lookup")
    lookup_parser.add_argument("ip", help="IP address to lookup")
    lookup_parser.add_argument("--source", help="Capture source filter")
    
    graph_parser = subparsers.add_parser("graph", help="Generate network topology visualization")
    graph_commands = graph_parser.add_subparsers(dest="graph_command")
    graph_commands.add_parser("status", help="Show Neo4j graph availability and materialization lag")
    graph_materialize = graph_commands.add_parser("materialize", help="Materialize pending SQLite graph events")
    graph_materialize.add_argument("--limit", type=int, default=250)
    plugins_parser = subparsers.add_parser("plugins", help="Manage forensic plugins")
    plugin_commands = plugins_parser.add_subparsers(dest="plugin_command")
    plugin_commands.add_parser("list", help="List active forensic plugins")
    plugin_commands.add_parser("test", help="Validate and smoke-test forensic plugins")
    scaffold_plugins = plugin_commands.add_parser("scaffold", help="Create a calibration-ready plugin skeleton")
    scaffold_commands = scaffold_plugins.add_subparsers(dest="scaffold_type", required=True)
    scaffold_detector = scaffold_commands.add_parser("detector", help="Create a detector, tests, and corpus skeleton")
    scaffold_detector.add_argument("--id", required=True, dest="detector_id")
    scaffold_detector.add_argument("--finding-type", required=True)
    scaffold_detector.add_argument("--input", required=True, choices=["packet", "flow", "stream", "session", "metadata"], dest="input_kind")
    calibration_plugins = plugin_commands.add_parser("calibration", help="Measure and promote detector calibration")
    calibration_commands = calibration_plugins.add_subparsers(dest="calibration_command", required=True)
    calibration_run = calibration_commands.add_parser("run", help="Run the deterministic calibration corpus")
    calibration_run.add_argument("detector")
    calibration_run.add_argument("--finding-type")
    calibration_run.add_argument("--backend", choices=["all", "python", "rust"], default="all")
    calibration_status = calibration_commands.add_parser("status", help="Show per-finding calibration status")
    calibration_status.add_argument("detector", nargs="?")
    calibration_status.add_argument("--format", choices=["rich", "json"], default="rich", dest="output_format")
    calibration_export = calibration_commands.add_parser("field-export", help="Export redacted field exposure evidence")
    calibration_export.add_argument("--since", required=True)
    calibration_export.add_argument("--output", required=True)
    calibration_ingest = calibration_commands.add_parser("ingest", help="Ingest a redacted field evidence bundle")
    calibration_ingest.add_argument("field_bundle")
    calibration_promote = calibration_commands.add_parser("promote", help="Review and promote a passing report")
    calibration_promote.add_argument("report")
    calibration_promote.add_argument("--reviewer", required=True)
    calibration_promote.add_argument("--reason", required=True)
    calibration_commands.add_parser("verify", help="Verify profile attestations and staleness")
    calibration_commands.add_parser(
        "invalidate-stale",
        help="Demote stale trust claims to uncalibrated without granting new trust",
    )
    sigma_plugins = plugin_commands.add_parser("sigma", help="Manage synchronized Sigma rules")
    sigma_commands = sigma_plugins.add_subparsers(dest="sigma_command", required=True)
    sigma_commands.add_parser("status", help="Show synchronized Sigma corpus status")
    sigma_commands.add_parser("list", help="List loaded Sigma rules and compatibility")
    sigma_preview = sigma_commands.add_parser("preview", help="Preview and validate a remote Sigma rule")
    sigma_preview.add_argument("url", help="HTTPS GitHub or raw.githubusercontent.com YAML URL")
    sigma_load = sigma_commands.add_parser("load", help="Load a previously previewed remote Sigma rule")
    sigma_load.add_argument("url", help="HTTPS GitHub or raw.githubusercontent.com YAML URL")
    sigma_load.add_argument("--sha256", required=True, help="SHA-256 returned by preview")
    sigma_commands.add_parser("sync", help="Synchronize compatible rules from SigmaHQ/sigma")
    sigma_commands.add_parser("rollback", help="Restore the previous Sigma corpus")
    subparsers.add_parser("status", help="Show unified system health and status")
    doctor_parser = subparsers.add_parser("doctor", help="Run backend operational diagnostics")
    doctor_parser.add_argument("--json", action="store_true", help="Emit a machine-readable diagnostic report")
    
    hunt_parser = subparsers.add_parser("hunt", help="Run Sigma rules hunt")
    hunt_parser.add_argument("rule", nargs="?", help="Specific rule to hunt for")
    hunt_parser.add_argument("--list", action="store_true", help="List all carved files in evidence vault")
    hunt_parser.add_argument("--source", help="Historical capture source")
    hunt_parser.add_argument("--interface", help="Capture interface")
    survey_parser = subparsers.add_parser("survey", help="Capture and survey directly connected private networks")
    survey_parser.add_argument("--duration", default="60m", help="Passive capture duration, e.g. 60m")
    survey_parser.add_argument("--active", choices=["none", "safe", "deep"], default="deep")
    survey_parser.add_argument("--backend", choices=["python", "rust"])

    scoring_parser = subparsers.add_parser("scoring", help="Validate and operate behavioral scoring V2")
    scoring_commands = scoring_parser.add_subparsers(dest="scoring_command", required=True)
    scoring_commands.add_parser("status", help="Show model, mode, and finding status")
    scoring_commands.add_parser("validate", help="Validate profiles, plugins, and storage")
    scoring_explain = scoring_commands.add_parser("explain", help="Explain an entity priority score")
    scoring_explain.add_argument("ip")
    scoring_explain.add_argument("--source")
    scoring_explain.add_argument("--interface")
    scoring_explain.add_argument("--session")
    scoring_recompute = scoring_commands.add_parser("recompute", help="Deterministically recompute V2 risk")
    scoring_recompute.add_argument("--source")
    scoring_recompute.add_argument("--interface")
    scoring_recompute.add_argument("--session")
    scoring_recompute.add_argument("--as-of", type=float)
    scoring_recompute.add_argument("--dry-run", action="store_true")
    scoring_migrate = scoring_commands.add_parser("migrate", help="Backup then purge legacy alerts and scores")
    scoring_migrate.add_argument("--backup-and-purge", action="store_true", required=True)
    scoring_migrate.add_argument("--rebuild-available", action="store_true")
    scoring_restore = scoring_commands.add_parser("restore-backup", help="Restore a verified pre-migration backup")
    scoring_restore.add_argument("file")

    enrich_parser = subparsers.add_parser("enrich", help="Inspect and safely rebuild evidence-backed IP enrichment")
    enrich_commands = enrich_parser.add_subparsers(dest="enrich_command", required=True)
    enrich_status = enrich_commands.add_parser("status", help="Show enrichment coverage for stored traffic")
    enrich_rebuild = enrich_commands.add_parser("rebuild", help="Back up then repair historical enrichment from capture evidence")
    for command in (enrich_status, enrich_rebuild):
        command.add_argument("--source")
        command.add_argument("--interface")
        command.add_argument("--session")
    enrich_rebuild.add_argument("--dry-run", action="store_true")
    identity_parser = subparsers.add_parser("identity", help="Inspect and safely rebuild endpoint identity cards")
    identity_commands = identity_parser.add_subparsers(dest="identity_command", required=True)
    identity_status = identity_commands.add_parser("status", help="Show endpoint identity coverage for stored traffic")
    identity_rebuild = identity_commands.add_parser("rebuild", help="Back up then rebuild endpoint identities from capture evidence")
    identity_confirm = identity_commands.add_parser("confirm", help="Run bounded confirmation for directly connected private targets")
    identity_enrich = identity_commands.add_parser("enrich", help="Refresh cached public ownership enrichment")
    for command in (identity_status, identity_rebuild, identity_confirm, identity_enrich):
        command.add_argument("--source", help="Capture source filter")
        command.add_argument("--interface", help="Capture interface filter")
        command.add_argument("--session", help="Capture session filter")
    identity_rebuild.add_argument("--dry-run", action="store_true")
    identity_confirm.add_argument("--ip", action="append", default=[], dest="ips")
    identity_confirm.add_argument("--pending", action="store_true", help="Use all pending target observations")
    identity_confirm.add_argument("--dry-run", action="store_true")
    identity_enrich.add_argument("--ip", action="append", default=[], dest="ips")

    args = parser.parse_args()

    # Read-only installation diagnostics are intentionally available before
    # first-run auth setup; mutating graph operations remain protected.
    diagnostic_command = args.command == "doctor" or (
        args.command == "graph" and getattr(args, "graph_command", None) == "status"
    )
    if args.command not in {"auth", "ui"} and not diagnostic_command:
        from core.cli.modules.auth import AuthModule

        auth_module = AuthModule(console=console)
        sensitive = (
            args.command == "plugins"
            and getattr(args, "plugin_command", None) == "calibration"
            and getattr(args, "calibration_command", None) == "promote"
        ) or (
            args.command == "mesh"
            and getattr(args, "mesh_command", None) == "controller"
            and getattr(args, "mesh_controller_command", None) in {"init", "setup", "rotate-certificate"}
        ) or (
            args.command == "mesh"
            and getattr(args, "mesh_command", None) == "nodes"
            and getattr(args, "mesh_nodes_command", None) == "remove"
        ) or (
            args.command == "ai"
            and (
                getattr(args, "ai_command", None) == "chatgpt"
                or (
                    getattr(args, "ai_command", None) == "provider"
                    and getattr(args, "ai_provider_command", None) in {"connect", "disconnect"}
                )
            )
        )
        try:
            if not auth_module.ensure_unlocked(step_up=sensitive, interactive=sys.stdin.isatty()):
                raise SystemExit(4)
        finally:
            auth_module.close()

    # 1. Dispatch
    if not args.command or args.command == "shell":
        from core.cli.shell import WatchtowerShell
        
        try:
            console.print(ASCII_ART)
        except Exception:
            console.print("[bold cyan]WATCHTOWER - Network Monitoring & Forensics[/bold cyan]")
        DaemonManager.ensure_running()
        WatchtowerShell().cmdloop()
        sys.exit(0)

    if args.command == "start":
        from core.mesh.hybrid import hybrid_enabled
        if hybrid_enabled():
            from core.mesh.hybrid import start_capture
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                result = start_capture(db, args.interface or "", args.backend, args.source_type)
                console.print("[green]Native sensor capture command queued.[/green]")
                console.print_json(data=result)
            finally:
                db.close()
        else:
            DaemonManager.ensure_running()
            from core.cli.modules.capture import CaptureModule
            opts = {"backend": args.backend, "source_type": args.source_type}
            if args.interface:
                opts["interface"] = args.interface
            CaptureModule(opts).run(background=args.background)

    elif args.command == "ui":
        from core.ui_launcher import launch_ui
        try:
            launch_ui(console, port=args.port, api_port=args.api_port, open_browser=not args.no_open)
        except RuntimeError as exc:
            console.print(f"[bold red]UI launch failed:[/bold red] {exc}")

    elif args.command == "auth":
        from core.cli.modules.auth import AuthModule

        module = AuthModule(console=console)
        try:
            if args.auth_command == "setup":
                ok = module.setup(args.disable, args.name)
            elif args.auth_command == "unlock":
                ok = module.unlock()
            elif args.auth_command == "lock":
                module.lock(args.all_sessions)
                ok = True
            elif args.auth_command == "status":
                module.status()
                ok = True
            elif args.auth_command == "factors":
                module.factors()
                ok = True
            elif args.auth_command == "settings":
                ok = module.settings(args.enable and not args.disable)
            else:
                ok = module.recovery_reset(args.os_admin, args.reason)
        finally:
            module.close()
        if not ok:
            raise SystemExit(4)

    elif args.command == "chat":
        from core.cli.modules.ai import AIModule
        AIModule(console=console).chat(
            conversation_id=args.conversation, source=args.source, interface=args.interface, session=args.session,
            node=args.node, provider=args.provider, research_mode=args.research, prompt=args.prompt,
            mode=args.mode,
        )

    elif args.command == "ai":
        from core.cli.modules.ai import AIModule
        module = AIModule(console=console)
        if args.ai_command in {"status", "providers"}:
            module.status()
        elif args.ai_command == "provider":
            if args.ai_provider_command == "connect":
                module.provider_connect(args.provider, args.model, args.base_url)
            elif args.ai_provider_command == "test":
                module.provider_test(args.provider)
            else:
                module.provider_disconnect(args.provider)
        elif args.ai_command == "models":
            module.models(args.provider, args.refresh)
        elif args.ai_command == "model":
            module.model_set(args.provider, args.model)
        elif args.ai_command == "chatgpt":
            module.provider_connect("openai", args.model, None, chatgpt_alias=True)
        elif args.ai_command == "research":
            module.research_sources()
        elif args.ai_command == "conversations":
            module.conversations()
        elif args.ai_command == "credentials":
            if args.action == "status":
                module.status()
            elif not args.reference:
                parser.error("tower ai credentials set|delete requires REFERENCE")
            elif args.action == "set":
                module.credential_set(args.reference)
            else:
                module.credential_delete(args.reference)
        
    elif args.command == "stop":
        from core.mesh.hybrid import hybrid_enabled
        if hybrid_enabled():
            from core.mesh.hybrid import stop_capture
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                queued = stop_capture(db, args.interface)
                if queued:
                    console.print("[yellow]Native sensor stop command queued.[/yellow]")
                    console.print_json(data=queued)
                else:
                    console.print("[yellow]No active native sensor captures were found.[/yellow]")
            finally:
                db.close()
        else:
            from core.cli.modules.capture import CaptureModule
            CaptureModule({}).stop(args.interface)
        
    elif args.command == "background":
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).background()


        
    elif args.command == "daemon":
        if args.action == "start":
            if not DaemonManager.ensure_running():
                raise SystemExit(1)
        elif args.action == "stop":
            result = DaemonClient().shutdown()
            console.print_json(data=result)
            if result.get("status") == "error":
                raise SystemExit(1)
        elif args.action == "restart":
            result = DaemonManager.restart_daemon()
            console.print_json(data=result)
            if result.get("status") == "error":
                raise SystemExit(1)
        elif args.action == "repair":
            result = DaemonManager.repair_state()
            console.print_json(data=result)
            if result.get("status") == "blocked":
                raise SystemExit(1)
        elif args.action == "status":
            result = DaemonClient().get_status()
            console.print_json(data=result)
            if not result.get("running"):
                raise SystemExit(1)
        elif args.action == "bg":
             from core.cli.modules.capture import CaptureModule
             CaptureModule({}).background()
             
    elif args.command == "analyze":
        from core.cli.modules.forensics import ForensicsModule
        command = f'"{args.filename}" --mode {args.mode}'
        if args.backend: command += f" --backend {args.backend}"
        if args.keylog: command += f' --keylog "{args.keylog}"'
        ForensicsModule({}).analyze(command)



    elif args.command == "flows":
        from core.cli.modules.forensics import ForensicsModule
        ip, limit = args.ip, args.limit_option or args.limit
        if ip and ip.isdigit() and args.limit is None and args.limit_option is None:
            ip, limit = None, int(ip)
        ForensicsModule({
            "source": args.source, "interface": args.interface, "session": args.session,
        }).show("flows", ip=ip, limit=limit)

    elif args.command == "alerts":
        if args.arguments and args.arguments[0] == "disposition":
            if len(args.arguments) != 2 or not args.verdict:
                parser.error("alerts disposition requires ID and --verdict")
            finding_id = int(args.arguments[1])
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                result = db.set_finding_disposition(finding_id, args.verdict, args.reason, actor=args.actor)
                console.print(f"[green]Finding {finding_id} marked {args.verdict}.[/green] ")
                console.print(f"[dim]Recomputed priority: {result['assessment']['priority_score']:.1f}/100[/dim]")
            finally:
                db.close()
            return
        from core.cli.modules.forensics import ForensicsModule
        ip = args.arguments[0] if args.arguments else None
        positional_limit = int(args.arguments[1]) if len(args.arguments) > 1 and args.arguments[1].isdigit() else None
        limit = args.limit_option or positional_limit
        if ip and ip.isdigit() and len(args.arguments) == 1 and args.limit_option is None:
            ip, limit = None, int(ip)
        ForensicsModule({
            "source": args.source, "interface": args.interface, "session": args.session,
        }).show("alerts", ip=ip, limit=limit)

    elif args.command == "dive":
        from core.cli.modules.forensics import ForensicsModule
        dive_args = args.ip
        if args.export is not None:
            dive_args += " --export"
            if args.export:
                dive_args += f" {args.export}"
        ForensicsModule({"source": args.source}).dive(dive_args)

    elif args.command == "lookup":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"source": args.source}).lookup(args.ip)

    elif args.command == "status":
        from core.mesh.hybrid import hybrid_enabled
        if hybrid_enabled():
            from core.mesh.hybrid import status as hybrid_status
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                console.print_json(data=hybrid_status(db))
            finally:
                db.close()
        else:
            # Unified status: Show daemon + engine health
            status = DaemonClient().get_status()
            from core.cli.modules.capture import CaptureModule
            CaptureModule.show_status(status)
            from core.cli.modules.forensics import ForensicsModule
            ForensicsModule({"interfaces": status.get("interfaces", [])}).show_stats()

    elif args.command == "doctor":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).doctor(json_output=args.json)

    elif args.command == "stats":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"interface": args.interface}).show_stats()

    elif args.command == "sources":
        from rich.table import Table
        from core.mesh.hybrid import devices as hybrid_devices, hybrid_enabled
        table = Table(title="Capture Sources")
        table.add_column("Type", style="cyan")
        table.add_column("Device", style="white")
        table.add_column("Address", style="green")
        table.add_column("Backends")
        table.add_column("Status")
        if hybrid_enabled():
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                device_rows = hybrid_devices(db)
            finally:
                db.close()
        else:
            from core.capture_sources import default_registry
            device_rows = default_registry().list_devices()
        for device in device_rows:
            if isinstance(device, dict):
                available = bool(device.get("available", True))
                unavailable_reason = str(device.get("unavailable_reason") or "")
                source_type = str(device.get("source_type") or "network")
                name = str(device.get("name") or device.get("device_id") or "unknown")
                addresses = [str(item) for item in device.get("addresses") or []]
                backends = [str(item) for item in device.get("backends") or []]
            else:
                available, unavailable_reason = device.available, device.unavailable_reason
                source_type, name, addresses, backends = device.source_type, device.name, device.addresses, device.backends
            status = "[green]Available[/green]" if available else f"[yellow]{unavailable_reason}[/yellow]"
            table.add_row(
                source_type, name, ", ".join(addresses) or "-",
                ", ".join(backends) or "-", status,
            )
        console.print(table)

    elif args.command == "endpoint":
        from core.storage.database import WatchtowerDB
        from core.endpoint.sysmon import SysmonCollector
        from rich.table import Table
        db = WatchtowerDB()
        try:
            if args.endpoint_command == "sysmon":
                status = SysmonCollector(db).status()
                state = "[green]AVAILABLE[/green]" if status.get("available") else "[yellow]UNAVAILABLE[/yellow]"
                table = Table(title="Sysmon Endpoint Telemetry")
                table.add_column("Metric", style="cyan")
                table.add_column("Value")
                table.add_row("Status", state)
                table.add_row("Channel", str(status.get("channel") or "-"))
                table.add_row("Observations", f"{int(status.get('observations') or 0):,}")
                table.add_row("Flow coverage", f"{float(status.get('coverage') or 0.0):.1%}")
                table.add_row("Reason", str(status.get("reason") or "Ready"))
                console.print(table)
            else:
                rows = db.get_endpoint_process_observations(ip=args.ip, limit=args.limit)
                table = Table(title="Endpoint Process Observations")
                table.add_column("Time")
                table.add_column("Process", style="cyan")
                table.add_column("PID")
                table.add_column("Service")
                table.add_column("Connection")
                for item in rows:
                    connection = f"{item.get('local_ip') or '-'}:{item.get('local_port') or 0} -> {item.get('remote_ip') or '-'}:{item.get('remote_port') or 0}"
                    table.add_row(
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(item.get("observed_at") or 0))),
                        str(item.get("image") or "-"), str(item.get("pid") or "-"),
                        ", ".join(item.get("service_names") or []) or "-", connection,
                    )
                console.print(table)
        finally:
            db.close()

    elif args.command == "mesh":
        from core.storage.database import WatchtowerDB
        from core.mesh.agent import MeshAgent
        from core.mesh.runtime import MeshRuntimeManager
        from core.mesh.service import MeshControllerService
        from rich.prompt import Confirm
        db = WatchtowerDB()
        try:
            runtime = MeshRuntimeManager(str(db.data_dir))
            if args.mesh_command == "controller":
                controller = MeshControllerService(db)
                if args.mesh_controller_command == "init":
                    status = controller.initialize(args.host)
                    console.print("[green]Mesh controller initialized.[/green]")
                    console.print(f"[dim]CA certificate: {controller.authority.ca_cert_path}[/dim]")
                    console.print_json(data=status)
                elif args.mesh_controller_command == "setup":
                    status = controller.setup(
                        args.mode, args.address, args.enrollment_port, args.ingest_port,
                        args.acknowledge_public_risk,
                    )
                    console.print(f"[green]Mesh controller configured for {args.mode} connectivity.[/green]")
                    if args.mode == "vpn":
                        console.print("[cyan]VPN-overlay mode keeps the controller off the public internet.[/cyan]")
                    elif args.mode == "public":
                        console.print("[bold yellow]Direct-public mode selected. Restrict both ports at the firewall.[/bold yellow]")
                    console.print_json(data=status)
                elif args.mesh_controller_command == "start":
                    console.print_json(data=runtime.start_controller())
                elif args.mesh_controller_command == "stop":
                    console.print_json(data=runtime.stop_controller())
                elif args.mesh_controller_command == "restart":
                    console.print_json(data=runtime.restart_controller())
                elif args.mesh_controller_command == "rotate-certificate":
                    if runtime.controller_status().get("running"):
                        raise RuntimeError("Stop the mesh controller before rotating its listener certificate")
                    console.print_json(data=controller.rotate_certificate())
                elif args.mesh_controller_command == "status":
                    status = controller.status()
                    status["runtime"] = runtime.controller_status()
                    console.print_json(data=status)
                else:
                    from core.mesh.transport import MeshGrpcServer
                    controller.initialize(args.host)
                    server = MeshGrpcServer(controller, args.host, args.enrollment_port, args.ingest_port)
                    addresses = server.start()
                    console.print(f"[green]Mesh listeners active:[/green] {addresses['host']}:{addresses['enrollment_port']} (enroll), {addresses['host']}:{addresses['ingest_port']} (mTLS ingest)")
                    try:
                        server.wait()
                    except KeyboardInterrupt:
                        console.print("[yellow]Stopping mesh controller...[/yellow]")
                    finally:
                        server.stop()
            elif args.mesh_command == "enroll":
                result = MeshControllerService(db).create_enrollment(args.name, args.ttl, args.max_uses)
                console.print("[bold yellow]Legacy enrollment token (shown once):[/bold yellow]")
                console.print(result["token"])
                console.print("[dim]Prefer 'tower mesh nodes add' for a verified one-step join package.[/dim]")
                console.print_json(data={key: value for key, value in result.items() if key not in {"token", "join_code"}})
            elif args.mesh_command == "nodes":
                node_command = getattr(args, "mesh_nodes_command", None) or "list"
                controller = MeshControllerService(db)
                if node_command == "add":
                    result = controller.create_enrollment(args.name, args.ttl, 1)
                    console.print(f"[bold yellow]Join package expires at {time.ctime(result['expires_at'])}.[/bold yellow]")
                    console.print(f"[cyan]Controller CA fingerprint:[/cyan] {result['ca_fingerprint']}")
                    if args.output:
                        from pathlib import Path
                        output = Path(args.output).expanduser().resolve()
                        output.write_text(result["join_code"], encoding="ascii")
                        console.print(f"[green]Enrollment package written to {output}[/green]")
                    else:
                        console.print("[bold]Enrollment package (shown once):[/bold]")
                        console.print(result["join_code"])
                elif node_command == "show":
                    node = db.get_sensor_node(args.node_id)
                    if not node:
                        console.print("[red]Mesh node not found.[/red]")
                        raise SystemExit(2)
                    console.print_json(data=controller._health_view(node))
                elif node_command == "remove":
                    if not controller.revoke(args.node_id, args.reason):
                        console.print("[red]Mesh node not found.[/red]")
                        raise SystemExit(2)
                    console.print(f"[green]Decommissioned mesh node {args.node_id}; historical evidence was retained.[/green]")
                else:
                    from rich.table import Table
                    table = Table(title="Sensor Mesh Nodes")
                    table.add_column("Name", style="cyan")
                    table.add_column("Node ID", overflow="ellipsis", max_width=24)
                    table.add_column("Status")
                    table.add_column("Platform")
                    table.add_column("Last Seen")
                    for node in db.list_sensor_nodes():
                        seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(node.get("last_seen_at") or 0))) if node.get("last_seen_at") else "-"
                        table.add_row(str(node.get("name")), str(node.get("id")), str(node.get("status")), str(node.get("platform") or "-"), seen)
                    console.print(table)
            elif args.mesh_command == "revoke":
                if not MeshControllerService(db).revoke(args.node_id, args.reason):
                    console.print("[red]Mesh node not found.[/red]")
                    raise SystemExit(2)
                console.print(f"[green]Decommissioned mesh node {args.node_id}.[/green]")
            else:
                agent = MeshAgent(db)
                if args.mesh_agent_command == "enroll":
                    console.print_json(data=agent.enroll(
                        args.controller, args.token, args.ca, args.name, args.enrollment_port, args.ingest_port,
                    ))
                elif args.mesh_agent_command == "join":
                    package_file = args.package_file
                    if package_file:
                        package_path = Path(package_file).expanduser()
                        if package_path.is_symlink() or not package_path.is_file():
                            raise ValueError("Enrollment package file must be a regular file")
                        if package_path.stat().st_size > 64 * 1024:
                            raise ValueError("Enrollment package file exceeds the 64 KiB limit")
                        package = package_path.read_text(encoding="ascii")
                    elif args.package and not args.package.startswith("WTJ1-"):
                        candidate = Path(args.package).expanduser()
                        if candidate.is_file():
                            if candidate.is_symlink() or candidate.stat().st_size > 64 * 1024:
                                raise ValueError("Enrollment package file must be a regular file under 64 KiB")
                            package = candidate.read_text(encoding="ascii")
                        else:
                            package = args.package
                    else:
                        package = args.package or console.input("[bold]Enrollment package:[/bold] ", password=True)
                    decoded = MeshControllerService.decode_join_package(package)
                    console.print(f"[cyan]Controller:[/cyan] {decoded['controller']}:{decoded['ingest_port']}")
                    console.print(f"[cyan]CA fingerprint:[/cyan] {decoded['ca_fingerprint']}")
                    if not args.yes and not Confirm.ask("Does this fingerprint match the controller display?", default=False):
                        console.print("[yellow]Enrollment cancelled.[/yellow]")
                        raise SystemExit(2)
                    console.print_json(data=agent.join(package, args.name))
                elif args.mesh_agent_command == "start":
                    console.print_json(data=runtime.start_agent(args.interval, args.limit))
                elif args.mesh_agent_command == "stop":
                    console.print_json(data=runtime.stop_agent())
                elif args.mesh_agent_command == "restart":
                    console.print_json(data=runtime.restart_agent(args.interval, args.limit))
                elif args.mesh_agent_command == "leave":
                    if runtime.agent_status().get("running"):
                        runtime.stop_agent()
                    console.print_json(data=agent.leave(args.reason, args.force))
                elif args.mesh_agent_command == "status":
                    status = agent.status()
                    status["runtime"] = runtime.agent_status()
                    console.print_json(data=status)
                elif args.mesh_agent_command == "sync":
                    console.print_json(data=agent.sync_once(args.limit))
                else:
                    interval = max(1, int(args.interval))
                    console.print(f"[green]Mesh agent running every {interval}s. Press Ctrl+C to stop.[/green]")
                    try:
                        while True:
                            console.print_json(data=agent.sync_once(args.limit))
                            time.sleep(interval)
                    except KeyboardInterrupt:
                        console.print("[yellow]Mesh agent stopped.[/yellow]")
        finally:
            db.close()

    elif args.command == "plugins":
        from core.forensics.plugin_loader import PluginLoader
        if args.plugin_command == "scaffold":
            from core.calibration.service import CalibrationError, CalibrationService
            try:
                result = CalibrationService().scaffold(args.detector_id, args.finding_type, args.input_kind)
                console.print("[bold green]Detector scaffold created.[/bold green]")
                for name, path in result.items():
                    console.print(f"[cyan]{name.title()}[/cyan]  {path}")
            except CalibrationError as exc:
                console.print(f"[bold red]Scaffold failed:[/bold red] {exc}")
                raise SystemExit(3)
        elif args.plugin_command == "calibration":
            from core.calibration.service import CalibrationError, CalibrationService
            from rich.table import Table
            service = CalibrationService()
            try:
                if args.calibration_command == "run":
                    result = service.run(args.detector, finding_type=args.finding_type, backend=args.backend)
                    table = Table(title="Detector Calibration")
                    table.add_column("Finding", style="cyan")
                    table.add_column("Level")
                    table.add_column("Precision", justify="right")
                    table.add_column("Recall", justify="right")
                    table.add_column("Result")
                    for report in result["reports"]:
                        metrics = report["metrics"]
                        table.add_row(
                            report["target"]["finding_type"], report["awarded_level"],
                            f"{metrics['precision']:.1%}", f"{metrics['recall']:.1%}",
                            "[green]PASS[/green]" if report["passed"] else "[red]FAIL[/red]",
                        )
                        console.print(f"[dim]Report: {report['report_path']}[/dim]")
                    console.print(table)
                    if not result["passed"]:
                        raise SystemExit(2)
                elif args.calibration_command == "status":
                    result = service.status(args.detector)
                    if args.output_format == "json":
                        console.print_json(data=result)
                    else:
                        table = Table(title="Detector Calibration Status")
                        table.add_column("Detector", style="cyan")
                        table.add_column("Finding")
                        table.add_column("Trust")
                        table.add_column("Cap", justify="right")
                        table.add_column("Attestation")
                        for item in result["targets"]:
                            table.add_row(
                                item["detector_id"], item["finding_type"], item["calibration_level"],
                                f"{item['effective_cap']:.1f}", item["attestation_digest"][:12] or "-",
                            )
                        console.print(table)
                elif args.calibration_command == "field-export":
                    console.print_json(data=service.field_export(args.since, args.output))
                elif args.calibration_command == "ingest":
                    console.print_json(data=service.ingest(args.field_bundle))
                elif args.calibration_command == "promote":
                    console.print_json(data=service.promote(args.report, args.reviewer, args.reason))
                elif args.calibration_command == "invalidate-stale":
                    console.print_json(data=service.invalidate_stale_profiles())
                else:
                    result = service.verify()
                    console.print_json(data=result)
                    if not result["valid"]:
                        raise SystemExit(2)
            except CalibrationError as exc:
                console.print(f"[bold red]Calibration failed:[/bold red] {exc}")
                raise SystemExit(3)
        elif args.plugin_command == "sigma":
            from core.forensics.sigma_sync import SigmaCorpusManager, SigmaRuleManager
            manager = SigmaCorpusManager()
            rules = SigmaRuleManager()
            try:
                if args.sigma_command == "status":
                    console.print_json(data=manager.status())
                elif args.sigma_command == "list":
                    console.print_json(data=rules.list_rules())
                elif args.sigma_command == "preview":
                    console.print_json(data=rules.preview_url(args.url))
                elif args.sigma_command == "load":
                    console.print_json(data=rules.install_url(args.url, args.sha256))
                elif args.sigma_command == "sync":
                    console.print_json(data=manager.sync().__dict__)
                else:
                    console.print_json(data=manager.rollback().__dict__)
            except Exception as exc:
                console.print(f"[yellow]Sigma {args.sigma_command} unavailable: {exc}[/yellow]")
        else:
            loader = PluginLoader()
            console.print("[bold cyan]Active Forensic Plugins:[/bold cyan]")
            for name, info in loader.list_plugins().items():
                status = "[green]PASS[/green]" if info["valid"] and not info["errors"] else "[red]FAIL[/red]"
                if args.plugin_command == "test":
                    contract = f"contract v{info.get('contract_version', 1)}"
                    calibration = "not applicable" if info.get("type") == "parser" else info.get("calibration_level", "UNCALIBRATED")
                    console.print(f" - {status} {name} [dim]({contract}, {calibration})[/dim]")
                else:
                    console.print(f" - [green]{name}[/green]: {info.get('description', 'No description')}")

    elif args.command == "hunt":
        if args.list:
            from core.cli.modules.forensics import ForensicsModule
            ForensicsModule({"source": args.source}).show_artifacts()
        else:
            from core.forensics.sigma_engine import SigmaEngine
            engine = SigmaEngine()
            alerts = engine.run_hunt(source=args.source, specific_rule=args.rule, interface=args.interface)
            console.print(f"[green]Hunt complete.[/green] {len(alerts)} Sigma match(es).")

    elif args.command == "survey":
        from core.storage.database import WatchtowerDB
        from core.survey.runner import SurveyConfig, SurveyRunner, parse_duration
        duration = parse_duration(args.duration)
        if duration > 0: DaemonManager.ensure_running()
        runner = SurveyRunner(WatchtowerDB())
        report = runner.run(SurveyConfig(duration_seconds=duration, active=args.active,
                                         capture_backend=args.backend), capture=duration > 0)
        console.print(f"[bold green]Survey complete.[/bold green] {len(report.devices)} device(s), "
                      f"{len(report.services)} service(s), {report.probe_count} bounded probe(s).")
        console.print(f"[dim]Hashed case bundle: {report.case_path}[/dim]")

    elif args.command == "enrich":
        from core.intelligence.reindex import EnrichmentReindexer
        from core.storage.database import WatchtowerDB
        db = WatchtowerDB()
        try:
            reindexer = EnrichmentReindexer(db)
            kwargs = {"source": args.source, "interface": args.interface, "session_id": args.session}
            if args.enrich_command == "status":
                result = reindexer.status(**kwargs)
                console.print(
                    f"[cyan]Enrichment coverage:[/cyan] {result['flows']:,} flows, {result['ips']:,} IPs, "
                    f"{result['public_with_capture_geo']:,}/{result['public_endpoints']:,} public peers with capture-time ownership data."
                )
            else:
                result = reindexer.rebuild(**kwargs, dry_run=args.dry_run)
                mode = "Previewed" if args.dry_run else "Rebuilt"
                console.print(
                    f"[green]{mode} enrichment:[/green] {result['flows']:,} flows, "
                    f"{result['changed_flows']:,} context updates, {result['removed_untrusted_macs']:,} unsafe MAC claims removed."
                )
                if result.get("backup"):
                    console.print(f"[dim]Verified backup: {result['backup']['database']}[/dim]")
        finally:
            db.close()

    elif args.command == "identity":
        from core.intelligence.reindex import EndpointIdentityReindexer
        from core.storage.database import WatchtowerDB
        db = WatchtowerDB()
        try:
            reindexer = EndpointIdentityReindexer(db)
            kwargs = {"source": args.source, "interface": args.interface, "session_id": args.session}
            if args.identity_command == "status":
                result = reindexer.status(**kwargs)
                console.print(
                    f"[cyan]Identity coverage:[/cyan] {result['identified']:,}/{result['endpoints']:,} endpoint associations; "
                    f"{result.get('confirmed_endpoints', 0):,} confirmed, {result.get('probable_endpoints', 0):,} probable, "
                    f"{result.get('unconfirmed_targets', 0):,} unconfirmed targets, {result.get('address_only', 0):,} address-only; "
                    f"{result['missing_identities']:,} identity card(s) pending rebuild."
                )
            elif args.identity_command == "rebuild":
                result = reindexer.rebuild(**kwargs, dry_run=args.dry_run)
                mode = "Previewed" if result["dry_run"] else "Rebuilt"
                console.print(
                    f"[green]{mode} endpoint identities:[/green] {result['identities']:,} records, "
                    f"{result['changed_identities']:,} updated, {result['strong_identities']:,} high-confidence."
                )
                if result.get("backup"):
                    console.print(f"[dim]Verified backup: {result['backup']['database']}[/dim]")
            elif args.identity_command == "confirm":
                from core.intelligence.confirmation import IdentityConfirmationService
                result = IdentityConfirmationService(db).confirm(
                    ips=args.ips, source=args.source, interface=args.interface, session=args.session,
                    dry_run=args.dry_run,
                )
                if result.get("confirmed") and not args.dry_run:
                    result["identity_rebuild"] = reindexer.rebuild(
                        source=args.source, interface=args.interface, session_id=args.session,
                    )
                console.print(f"[cyan]Identity confirmation {'preview' if args.dry_run else 'operation'} {result['operation_id']}:[/cyan] "
                              f"{result['eligible']:,} eligible, {result.get('confirmed', 0):,} confirmed, "
                              f"{len(result.get('excluded') or []):,} excluded.")
            elif args.identity_command == "enrich":
                from core.intelligence.ip_lookup import IpLookupService
                values = args.ips or [row["entity_ip"] for row in db.get_endpoint_identities(source=args.source, capture_session_id=args.session, limit=100)]
                results = []
                for ip in values:
                    try:
                        results.append(IpLookupService(db).lookup(ip, args.source, persist=False))
                    except Exception as exc:
                        results.append({"ip": ip, "error": str(exc)})
                console.print(f"[green]Enriched {len(results):,} endpoint(s) using cached public and passive evidence.[/green]")
        finally:
            db.close()

    elif args.command == "scoring":
        from core.cli.modules.scoring import ScoringModule
        from core.detection.operations import ScoringOperations
        from core.storage.database import WatchtowerDB
        module = ScoringModule()
        try:
            if args.scoring_command == "status":
                module.status()
            elif args.scoring_command == "validate":
                module.validate()
            elif args.scoring_command == "explain":
                module.explain(args.ip, source=args.source, interface=args.interface, session_id=args.session)
            elif args.scoring_command == "recompute":
                result = module.operations.recompute(
                    source=args.source, interface=args.interface, session_id=args.session,
                    as_of=args.as_of, dry_run=args.dry_run,
                )
                console.print(f"[green]Recomputed {result['subjects']} subject(s).[/green] Maximum priority {result['max_priority_score']:.1f}/100")
            else:
                daemon = DaemonClient().get_status()
                from core.cli.modules.capture import CaptureModule
                running_interfaces = set(daemon.get("interfaces") or ()) | set(CaptureModule({})._get_running_interfaces())
                if running_interfaces:
                    console.print("[red]Stop all capture interfaces before migration or restore.[/red]")
                    return
                if args.scoring_command == "migrate":
                    result = module.operations.backup_and_purge()
                    console.print(f"[green]Verified backup created and legacy risk purged.[/green] {result['database']}")
                    if args.rebuild_available:
                        rebuild = module.operations.rebuild_available_pcaps()
                        console.print(f"[green]Reanalyzed {len(rebuild['reanalyzed'])} retained PCAP(s).[/green] {len(rebuild['missing'])} original(s) unavailable.")
                else:
                    destination = str(module.db.db_path)
                    module.db.close()
                    result = ScoringOperations.restore_backup(args.file, destination)
                    console.print(f"[green]Verified backup restored.[/green] {result['restored']}")
        finally:
            module.db.close()

    elif args.command == "graph":
        if getattr(args, "graph_command", None) in {"status", "materialize"}:
            from core.storage.database import WatchtowerDB
            from core.graph.service import EvidenceGraphService
            db = WatchtowerDB()
            try:
                graph = EvidenceGraphService(db)
                if args.graph_command == "status":
                    console.print_json(data=graph.status())
                else:
                    console.print_json(data=graph.materialize(args.limit, owner="cli-manual"))
                graph.close()
            finally:
                db.close()
        else:
            from core.cli.modules.forensics import ForensicsModule
            ForensicsModule({}).do_graph("")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

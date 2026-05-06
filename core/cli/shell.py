import cmd
import os
import sys
from datetime import datetime
from rich.console import Console

console = Console()

class WatchtowerShell(cmd.Cmd):
    intro = "Welcome to the Watchtower Shell. Type help or ? to list commands.\n"
    prompt = "tower > "
    
    def __init__(self):
        super().__init__()
        self.ui_proc = None
        import threading
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    def _heartbeat_loop(self):
        from core.daemon.client import DaemonClient
        import time
        client = DaemonClient()
        while True:
            try:
                # CLI lease: 5 minutes, renewed every 30s
                client.heartbeat(300)
            except: pass
            time.sleep(30)

    def do_help(self, arg):
        """Show categorized help for all commands or detailed help for a specific command."""
        from rich.table import Table
        from rich.panel import Panel
        
        if arg:
            # Detailed help for specific command
            func = getattr(self, f"do_{arg}", None)
            if func and func.__doc__:
                console.print(Panel(
                    func.__doc__.strip(),
                    title=f"Help: {arg}",
                    border_style="cyan"
                ))
            else:
                console.print(f"[red]Unknown command: {arg}[/red]")
            return
        
        console.print()
        # Capture Management
        t1 = Table(title="🔴 Capture Management (Daemon)", show_header=True, header_style="bold cyan", expand=True, border_style="dim")
        t1.add_column("Command", style="bold white", min_width=18)
        t1.add_column("Description", style="dim white")
        t1.add_column("Example", style="green")
        t1.add_row("start [iface]", "Tell the background daemon to start capturing on an interface", "start Wi-Fi")
        t1.add_row("stop", "Send shutdown signal to all background daemon engines", "stop")
        t1.add_row("status", "Check if any daemon capture engines are running", "status")
        t1.add_row("stats", "Show live packet, flow, and byte statistics", "stats")
        t1.add_row("dump [file]", "Save current packet buffer to a PCAP file", "dump evidence.pcap")
        console.print(t1)

        
        console.print()
        # Forensic Investigation
        t2 = Table(title="🔍 Forensic Investigation", show_header=True, header_style="bold cyan", expand=True, border_style="dim")
        t2.add_column("Command", style="bold white", min_width=18)
        t2.add_column("Description", style="dim white")
        t2.add_column("Example", style="green")
        t2.add_row("analyze <pcap>", "Run deep forensic analysis on a PCAP file. Extracts identities,\nfingerprints TLS, detects anomalies, carves files.", "analyze traffic.pcap")
        t2.add_row("  --keylog <file>", "  Provide TLS key log for decryption", "analyze traffic.pcap --keylog keys.log")
        t2.add_row("dive <IP>", "Deep dive investigation into a specific IP address.\nShows identity, alerts, carved files, and destinations.", "dive 192.168.1.50")
        t2.add_row("  --stream", "  Follow and reassemble TCP streams for the IP", "dive 192.168.1.50 --stream")
        t2.add_row("  --stream --port", "  Filter streams to a specific port", "dive 10.0.0.5 --stream --port 445")
        t2.add_row("flows", "Show recent network flow records from the database", "flows")
        t2.add_row("alerts", "Show recent security alerts", "alerts")
        t2.add_row("lookup <IP>", "Perform GeoIP and intelligence lookup on an IP", "lookup 8.8.8.8")
        t2.add_row("graph", "Generate interactive network topology visualization\nand open it in your browser", "graph")
        console.print(t2)

        console.print()
        # System Commands
        t3 = Table(title="⚙️  System Management", show_header=True, header_style="bold cyan", expand=True, border_style="dim")
        t3.add_column("Command", style="bold white", min_width=18)
        t3.add_column("Description", style="dim white")
        t3.add_column("Example", style="green")
        t3.add_row("plugins", "List all active protocol parsers and threat detectors", "plugins")
        t3.add_row("hunt", "Run Sigma rules against historical capture data", "hunt [rule_name]")
        t3.add_row("clean", "Wipe the entire database and start fresh.\nStops all engines. Requires confirmation.", "clean")
        t3.add_row("logout", "Log out, clear the current session, and lock the Vault", "logout")
        t3.add_row("exit / quit", "Exit the Watchtower shell", "exit")
        t3.add_row("help [cmd]", "Show this help or detailed help for a command", "help dive")
        console.print(t3)

        console.print()
        console.print(Panel(
            "[bold cyan]Quick Start:[/bold cyan]\n"
            "  1. [white]start[/white]         → Signal Daemon to begin capturing on default interface\n"
            "  2. [white]status[/white]        → Check if the daemon is running\n"
            "  3. [white]flows[/white]         → View captured network flows\n"
            "  4. [white]analyze <pcap>[/white] → Run deep forensics on an offline file\n\n"
            "[bold cyan]Forensic Workflow:[/bold cyan]\n"
            "  1. [white]analyze suspect.pcap[/white]     → Full PCAP analysis (Strictly Isolated)\n"
            "  2. [white]dive 192.168.1.50[/white]        → Investigate a suspect IP\n"
            "  3. [white]graph[/white]                    → Visualize network topology\n"
            "  4. [white]logout[/white]                   → Lock the Secure Vault",
            title="Common Workflows",
            border_style="green"
        ))

    def do_start(self, arg):
        """Start the background capture engine.

Usage: start [interface_name]

Starts a background packet capture process on the specified network
interface. If no interface is specified, Watchtower auto-selects the
primary interface (the one with an active IP address).

The engine runs in the background and writes captured data to the
SQLite database (data/watchtower.db). You can start multiple engines
on different interfaces simultaneously.

Examples:
  start             Start on default interface
  start Wi-Fi       Start on the Wi-Fi adapter
  start Ethernet    Start on the Ethernet adapter

Note: Requires administrator/root privileges for packet capture."""
        opts = {"interface": arg} if arg else {}
        from core.cli.modules.capture import CaptureModule
        CaptureModule(opts).run()

    def do_background(self, arg):
        """Configure Watchtower for persistent background monitoring.

Usage: background

Opens an interactive selector to choose which network interfaces should
be monitored in the background. Once configured, Watchtower will
continue capturing and analyzing traffic even after this shell is closed.

This mode ensures forensic data collection persists across system reboots
(if the daemon is set to auto-start) and user logouts.

Use 'stop' to terminate background engines."""
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).background()

    def do_plugins(self, arg):
        """List all dynamically loaded protocol parsers and threat detectors.

Usage: plugins

Displays a table of all active plugins loaded into the forensic engine."""
        from rich.table import Table
        from core.forensics.plugin_loader import PluginLoader
        
        loader = PluginLoader()
        
        table = Table(title="🔌 Active Forensic Plugins", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Plugin Type", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Status", style="green")
        
        for parser in loader.get_parsers():
            status_str = "[green]Enabled[/green]" if parser.enabled else "[red]Disabled[/red]"
            table.add_row("Parser", parser.name, status_str)
            
        for detector in loader.get_detectors():
            status_str = "[green]Enabled[/green]" if detector.enabled else "[red]Disabled[/red]"
            table.add_row("Detector", detector.name, status_str)
            
        from core.forensics.sigma_engine import SigmaEngine
        sigma = SigmaEngine()
        for rule in sigma.rules:
            status_str = "[green]Loaded[/green]"
            table.add_row("Sigma Rule", rule.get("title", "Unknown"), status_str)
            
        console.print(table)

    def do_hunt(self, arg):
        """Run Sigma YAML rules against historical database records.

Usage: hunt [rule_name]

Runs the Watchtower SigmaEngine to search for threats in historical flow 
and entity data. Any matched rules will generate new ForensicAlerts.
If rule_name is provided, only that specific rule is evaluated.
"""
        from core.forensics.sigma_engine import SigmaEngine
        from rich.console import Console
        from rich.table import Table
        c = Console()
        
        c.print("[cyan]Initializing SigmaEngine...[/cyan]")
        engine = SigmaEngine()
        if not engine.rules:
            c.print("[red]No Sigma rules found in core/forensics/plugins/sigma/.[/red]")
            return
            
        c.print(f"[cyan]Loaded {len(engine.rules)} Sigma rules. Starting hunt...[/cyan]")
        rule_name = arg.strip() if arg else None
        
        alerts = engine.run_hunt(specific_rule=rule_name)
        
        if not alerts:
            c.print("[green]✅ Hunt complete. No Sigma matches found.[/green]")
            return
            
        c.print(f"[bold red]⚠️ Hunt complete. Found {len(alerts)} Sigma matches![/bold red]")
        table = Table(title="Sigma Hunt Results", show_header=True)
        table.add_column("Rule Match", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Target Evidence", style="white")
        
        for alert in alerts:
            ev = alert.evidence
            target = ev.get("flow") or ev.get("entity_ip") or "Unknown"
            table.add_row(ev.get("rule", "Unknown"), alert.severity, str(target))
            
        c.print(table)
        c.print("[dim]Alerts have been saved to the database and forwarded to SIEMs.[/dim]")

    def do_stop(self, arg):
        """Stop all running background capture engines.

Usage: stop

Terminates all background capture engine processes across all
monitored interfaces. Removes their PID files from the data directory.

This does NOT delete any captured data — flows, entities, and alerts
remain in the database. Use 'clean' to wipe the database."""
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).stop()

    def do_status(self, arg):
        """Check if any capture engines are currently running.

Usage: status

Shows the running state and lists all active network interfaces being
monitored. Also displays the process IDs (PIDs) for each engine."""
        from core.cli.modules.capture import CaptureModule
        cm = CaptureModule({})
        ifaces = cm._get_running_interfaces()
        if ifaces:
            console.print(f"Engine Status: [green]RUNNING[/green]")
            console.print(f"Active Interfaces: [cyan]{', '.join(ifaces)}[/cyan]")
        else:
            console.print(f"Engine Status: [red]STOPPED[/red]")

    def do_stats(self, arg):
        """Show live packet, flow, and traffic statistics for today.

Usage: stats

Displays a table with today's cumulative metrics including total
packets captured, flow count, and data volume in megabytes."""
        from core.packet_engine.persistence import DailyAccumulator
        import time
        from rich.table import Table
        acc = DailyAccumulator()
        stats = acc.get_today()
        table = Table(title="Live Stats")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Flows", str(stats.get("total_flows", 0)))
        table.add_row("Packets", str(stats.get("total_packets", 0)))
        table.add_row("Bytes", f"{stats.get('total_bytes', 0)/(1024*1024):.2f} MB")
        console.print(table)

    def do_flows(self, arg):
        """Show the most recent network flow records from the database.

Usage: flows

Displays a table of the 20 most recent flows with columns for flow ID,
protocol, identity (hostname/SNI), and risk score. Flows are sourced
from live capture data in watchtower.db."""
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).show("flows")

    def do_alerts(self, arg):
        """Show recent security alerts from the detection engine.

Usage: alerts

Displays the 15 most recent alerts including timestamp, entity IP,
severity level, and explanation. Alert types include beaconing, DNS
anomalies, lateral movement, and suspicious file transfers."""
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).show("alerts")

    def do_lookup(self, arg):
        """Perform GeoIP and threat intelligence lookup on an IP address.

Usage: lookup <ip_address>

Queries public GeoIP databases to retrieve location, ASN, and network
information for the specified IP address.

Examples:
  lookup 8.8.8.8          Google DNS
  lookup 1.1.1.1          Cloudflare DNS
  lookup 203.0.113.50     Check an external IP"""
        if not arg:
            console.print("[yellow]Usage: lookup <ip>[/yellow]")
            return
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).lookup(arg)



    def do_dump(self, arg):
        """Save the current packet buffer to a PCAP file.

Usage: dump [filename]

Exports captured packets from the running engine into a standard PCAP
file that can be opened in Wireshark or analyzed with 'analyze'.

If no filename is provided, a timestamped name is generated:
  dump_20260430_153000.pcap

Examples:
  dump                    Auto-named with timestamp
  dump evidence.pcap      Custom filename
  dump /path/to/file.pcap Full path"""
        if not arg:
            filename = f"dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        else:
            filename = arg
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).dump(filename)

    def do_analyze(self, arg):
        """Run deep forensic analysis on an offline PCAP file.

Usage: analyze <file.pcap> [--keylog <keylog_file>]

Processes every packet through the full forensic pipeline:
  1. Identity extraction (NTLM, Kerberos, NBNS, DHCP, LDAP)
  2. TLS fingerprinting (JA3/JA4) with malware library matching
  3. Behavioral anomaly detection (beaconing, DGA, scanning)
  4. TCP stream reassembly and file carving
  5. VirusTotal hash lookups on carved files (if API key set)
  6. Comprehensive forensic report generation

Results are written to the database and can be explored with 'dive',
'flows', 'alerts', and the web dashboard.

Options:
  --keylog <file>   Path to an SSLKEYLOGFILE for TLS decryption

Examples:
  analyze suspicious_traffic.pcap
  analyze capture.pcap --keylog /tmp/sslkeys.log"""
        if not arg:
            console.print("[yellow]Usage: analyze <file.pcap>[/yellow]")
            return
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).analyze(arg)

    def do_dive(self, arg):
        """Deep dive forensic investigation into a specific IP address.

Usage: dive <IP> [--stream] [--port <port>]

Displays a comprehensive profile for the target IP including:
  • Host identification (IP, MAC, hostname, username, full name, OS)
  • TLS fingerprints (JA3/JA4) and client library identification
  • Carved files with VirusTotal scan results
  • Security alerts and behavioral anomalies
  • Top traffic destinations

Options:
  --stream          Reassemble and export TCP streams for this host
  --port <port>     Filter streams to a specific destination port

Examples:
  dive 192.168.1.50
  dive 10.0.0.5 --stream
  dive 10.0.0.5 --stream --port 445"""
        if not arg:
            console.print("[yellow]Usage: dive <IP>[/yellow]")
            return
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).dive(arg)

    def do_graph(self, arg):
        """Generate an interactive network topology visualization.

Usage: graph

Builds a Cytoscape.js force-directed graph from all entities and flows
in the database and opens it in your browser. The visualization shows:

  • Node risk scoring with color coding (green → yellow → red)
  • Cloud provider grouping (Azure, AWS, Google, Cloudflare)
  • Attack view filtering for high-risk connections
  • Interactive node selection with forensic overlays

The graph is saved to data/topology.html and can be reopened anytime."""
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).do_graph(arg)

    def do_clean(self, arg):
        """Wipe the entire database and start fresh.

Usage: clean

Stops all running capture engines and deletes ALL data from the
database including flows, entities, alerts, carved files, timeline
data, and forensic reports.

This action is IRREVERSIBLE. You will be prompted for confirmation.
Use this when switching to a new network or starting a new
investigation from scratch."""
        confirm = input("⚠️  This will DELETE ALL captured data. Are you sure? (yes/N): ").strip()
        if confirm.lower() != "yes":
            console.print("[dim]Cancelled.[/dim]")
            return
        
        # Stop engines
        from core.cli.modules.capture import CaptureModule
        cm = CaptureModule({})
        ifaces = cm._get_running_interfaces()
        if ifaces:
            cm.stop()
        
        # Reset database
        from core.storage.database import WatchtowerDB
        db = WatchtowerDB()
        counts = db.reset_all()
        
        total = sum(counts.values())
        console.print(f"[bold green]✅ Database wiped clean. {total} records removed.[/bold green]")
        for table, count in counts.items():
            if count > 0:
                console.print(f"  [dim]{table}: {count} rows deleted[/dim]")
        console.print("[dim]Ready for a fresh start. Run 'start' to begin capturing.[/dim]")


    def do_exit(self, arg):
        """Exit the Watchtower shell.

Usage: exit (or quit)

Exits the interactive shell. Running engines will be stopped on exit, 
and the UI dashboard process will be terminated."""
        if self.ui_proc and self.ui_proc.poll() is None:
            console.print("[yellow]Stopping UI dashboard...[/yellow]")
            self.ui_proc.terminate()
            try:
                self.ui_proc.wait(timeout=2.0)
            except:
                self.ui_proc.kill()
        
        console.print("[yellow]Exiting Watchtower...[/yellow]")
        return True

    def default(self, line):
        if line == "quit":
            return self.do_exit(line)
        console.print(f"[red]Unknown command: {line}[/red]")

if __name__ == "__main__":
    WatchtowerShell().cmdloop()

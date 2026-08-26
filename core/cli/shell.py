import cmd
import shlex
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
        from rich.text import Text
        
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
        t1.add_row(Text("start [iface]"), "Tell the background daemon to start capturing on an interface", "start Wi-Fi")
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
        t2.add_row(Text("  --export [name]"), "  Export JSON/CSV evidence with a SHA-256 manifest", "dive 192.168.1.50 --export case-001")
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
        t3.add_row("ui", "Launch the local Web Dashboard and API", "ui")
        t3.add_row("chat", "Open the shared local AI analyst conversation", "chat --source live")
        t3.add_row("ai", "Show analyst providers, research sources, and conversations", "ai status")
        t3.add_row("plugins", "List all active protocol parsers and threat detectors", "plugins")
        t3.add_row("doctor", "Run backend configuration, database, disk, and daemon checks", "doctor")
        t3.add_row("hunt", "Run Sigma rules against historical capture data", Text("hunt [rule_name]"))
        t3.add_row("enrich", "Inspect or safely rebuild evidence-backed IP enrichment", "enrich rebuild --session ID")
        t3.add_row("identity", "Inspect or safely rebuild endpoint identity cards", "identity rebuild --session ID")
        t3.add_row("survey", "Capture and survey directly connected private networks", "survey --duration 60m --active deep")
        t3.add_row("clean", "Wipe the entire database and start fresh.\nStops all engines. Requires confirmation.", "clean")
        t3.add_row("exit / quit", "Exit the Watchtower shell", "exit")
        t3.add_row(Text("help [cmd]"), "Show this help or detailed help for a command", "help dive")
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
            "  4. [white]exit[/white]                     → Leave the shell",
            title="Common Workflows",
            border_style="green"
        ))

    def do_ui(self, arg):
        """Launch the local WatchTower Web Dashboard and API.

Usage: ui [--port PORT] [--api-port PORT] [--no-open]

Starts the local API and analyst dashboard using the same launcher as
the top-level `tower ui` command. The dashboard opens in your browser
unless --no-open is supplied. Press Ctrl+C to stop services started by
this command and return to the WatchTower shell.

Examples:
  ui
  ui --no-open
  ui --port 4174 --api-port 8001"""
        parts = shlex.split(arg)
        port = 4173
        api_port = 8000
        open_browser = True
        index = 0
        try:
            while index < len(parts):
                option = parts[index]
                if option == "--no-open":
                    open_browser = False
                    index += 1
                    continue
                if option in {"--port", "--api-port"}:
                    if index + 1 >= len(parts):
                        raise ValueError(f"{option} requires a port number")
                    value = int(parts[index + 1])
                    if not 1 <= value <= 65535:
                        raise ValueError(f"{option} must be between 1 and 65535")
                    if option == "--port":
                        port = value
                    else:
                        api_port = value
                    index += 2
                    continue
                raise ValueError(f"unknown option: {option}")
        except (TypeError, ValueError) as exc:
            console.print(f"[yellow]Invalid UI options: {exc}[/yellow]")
            console.print("[dim]Usage: ui [--port PORT] [--api-port PORT] [--no-open][/dim]")
            return

        from core.ui_launcher import launch_ui

        try:
            launch_ui(
                console,
                port=port,
                api_port=api_port,
                open_browser=open_browser,
            )
        except RuntimeError as exc:
            console.print(f"[bold red]UI launch failed:[/bold red] {exc}")

    def do_chat(self, arg):
        """Open the shared WatchTower AI analyst conversation.

Usage: chat [--conversation ID] [--source SOURCE] [--interface NAME]
            [--session ID] [--provider ollama|openai] [--research auto|off]

The conversation is shared with the Analyst page in the local dashboard.
The analyst reads scoped evidence automatically and presents sensitive,
write, capture, and external-provider operations for approval.
"""
        from core.cli.modules.ai import AIModule

        parts = shlex.split(arg)
        values = {
            "--conversation": None,
            "--source": None,
            "--interface": None,
            "--session": None,
            "--provider": "ollama",
            "--research": "auto",
        }
        try:
            for option in values:
                if option in parts:
                    values[option] = parts[parts.index(option) + 1]
            if values["--provider"] not in {"ollama", "openai"}:
                raise ValueError("--provider must be ollama or openai")
            if values["--research"] not in {"auto", "off"}:
                raise ValueError("--research must be auto or off")
            module = AIModule(console=console)
            try:
                module.chat(
                    conversation_id=values["--conversation"], source=values["--source"],
                    interface=values["--interface"], session=values["--session"],
                    provider=values["--provider"], research_mode=values["--research"],
                )
            finally:
                module.service.close()
        except (IndexError, ValueError) as exc:
            console.print(f"[red]Invalid chat options: {exc}[/red]")

    def do_ai(self, arg):
        """Manage local analyst providers, research sources, and conversations.

Usage: ai status|providers|research [sources|status]|conversations [list]
          |credentials set|delete|status [REFERENCE]
"""
        from core.cli.modules.ai import AIModule

        parts = shlex.split(arg)
        action = parts[0] if parts else "status"
        module = AIModule(console=console)
        try:
            if action in {"status", "providers"}:
                module.status()
            elif action == "research":
                module.research_sources()
            elif action == "conversations":
                module.conversations()
            elif action == "credentials":
                credential_action = parts[1] if len(parts) > 1 else "status"
                reference = parts[2] if len(parts) > 2 else None
                if credential_action == "status":
                    module.status()
                elif credential_action == "set" and reference:
                    module.credential_set(reference)
                elif credential_action == "delete" and reference:
                    module.credential_delete(reference)
                else:
                    raise ValueError("Usage: ai credentials set|delete REFERENCE")
            else:
                raise ValueError(f"Unknown AI command: {action}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
        finally:
            module.service.close()

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
        parts = shlex.split(arg)
        opts = {}
        if "--backend" in parts:
            index = parts.index("--backend")
            if index + 1 >= len(parts) or parts[index + 1] not in {"python", "rust"}:
                console.print("[yellow]Usage: start [interface] [--backend python|rust][/yellow]")
                return
            opts["backend"] = parts[index + 1]
            del parts[index:index + 2]
        if parts:
            opts["interface"] = " ".join(parts)
        from core.mesh.hybrid import hybrid_enabled
        if hybrid_enabled():
            from core.mesh.hybrid import start_capture
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                result = start_capture(db, opts.get("interface", ""), opts.get("backend"), "network")
                console.print("[green]Native sensor capture command queued.[/green]")
                console.print_json(data=result)
            finally:
                db.close()
        else:
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

Usage: plugins [list|test|scaffold detector ...|calibration ...|sigma ...]

Displays a table of all active plugins loaded into the forensic engine."""
        from rich.table import Table
        from core.forensics.plugin_loader import PluginLoader
        
        parts = shlex.split(arg) if arg else []
        if parts and parts[0] in {"calibration", "scaffold"}:
            from core.calibration.service import CalibrationError, CalibrationService
            service = CalibrationService()
            try:
                if parts[0] == "scaffold":
                    if len(parts) != 8 or parts[1] != "detector" or parts[2] != "--id" or parts[4] != "--finding-type" or parts[6] != "--input":
                        raise CalibrationError("Usage: plugins scaffold detector --id ID --finding-type TYPE --input KIND")
                    console.print_json(data=service.scaffold(parts[3], parts[5], parts[7]))
                    return
                action = parts[1] if len(parts) > 1 else "status"
                if action == "status":
                    detector = next((part for part in parts[2:] if not part.startswith("--")), None)
                    result = service.status(detector)
                    table = Table(title="Detector Calibration Status")
                    table.add_column("Detector", style="cyan")
                    table.add_column("Finding")
                    table.add_column("Trust")
                    table.add_column("Cap", justify="right")
                    for item in result["targets"]:
                        table.add_row(item["detector_id"], item["finding_type"], item["calibration_level"], f"{item['effective_cap']:.1f}")
                    console.print(table)
                elif action == "run":
                    if len(parts) < 3:
                        raise CalibrationError("Usage: plugins calibration run DETECTOR [--finding-type TYPE] [--backend all|python|rust]")
                    finding_type = parts[parts.index("--finding-type") + 1] if "--finding-type" in parts else None
                    backend = parts[parts.index("--backend") + 1] if "--backend" in parts else "all"
                    console.print_json(data=service.run(parts[2], finding_type=finding_type, backend=backend))
                elif action == "field-export":
                    if "--since" not in parts or "--output" not in parts:
                        raise CalibrationError("Usage: plugins calibration field-export --since DATE --output FILE")
                    console.print_json(data=service.field_export(
                        parts[parts.index("--since") + 1], parts[parts.index("--output") + 1],
                    ))
                elif action == "ingest" and len(parts) == 3:
                    console.print_json(data=service.ingest(parts[2]))
                elif action == "promote":
                    if len(parts) < 3 or "--reviewer" not in parts or "--reason" not in parts:
                        raise CalibrationError("Usage: plugins calibration promote REPORT --reviewer NAME --reason TEXT")
                    console.print_json(data=service.promote(
                        parts[2], parts[parts.index("--reviewer") + 1], parts[parts.index("--reason") + 1],
                    ))
                elif action == "verify":
                    console.print_json(data=service.verify())
                else:
                    raise CalibrationError(f"Unknown calibration action: {action}")
            except (CalibrationError, IndexError) as exc:
                console.print(f"[red]Calibration failed: {exc}[/red]")
            return
        if parts and parts[0] == "sigma":
            from core.forensics.sigma_sync import SigmaCorpusManager, SigmaRuleManager
            manager = SigmaCorpusManager()
            rules = SigmaRuleManager()
            action = parts[1] if len(parts) > 1 else "status"
            try:
                if action == "list":
                    console.print_json(data=rules.list_rules())
                    return
                if action == "preview":
                    if len(parts) != 3:
                        raise ValueError("Usage: plugins sigma preview <HTTPS_URL>")
                    console.print_json(data=rules.preview_url(parts[2]))
                    return
                if action == "load":
                    if len(parts) != 5 or parts[3] != "--sha256":
                        raise ValueError("Usage: plugins sigma load <HTTPS_URL> --sha256 <HASH>")
                    console.print_json(data=rules.install_url(parts[2], parts[4]))
                    return
                if action == "sync":
                    if len(parts) != 2:
                        raise ValueError("Usage: plugins sigma sync")
                    result = manager.sync()
                elif action == "rollback":
                    result = manager.rollback()
                elif action == "status":
                    console.print_json(data=manager.status())
                    return
                else:
                    raise ValueError(f"Unknown Sigma action: {action}")
                console.print_json(data=result.__dict__)
            except Exception as exc:
                console.print(f"[red]Sigma {action} failed: {exc}[/red]")
            return

        loader = PluginLoader()
        
        table = Table(title="🔌 Active Forensic Plugins", show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Plugin Type", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Status", style="green")
        table.add_column("Contract")
        table.add_column("Calibration")
        
        for parser in loader.get_parsers():
            status_str = "[green]Enabled[/green]" if parser.enabled else "[red]Disabled[/red]"
            if parts and parts[0] == "test": status_str = "[green]PASS[/green]"
            table.add_row("Parser", parser.name, status_str, f"v{getattr(parser, 'api_version', 1)}", "n/a")
            
        plugin_health = loader.list_plugins()
        for detector in loader.get_detectors():
            status_str = "[green]Enabled[/green]" if detector.enabled else "[red]Disabled[/red]"
            if parts and parts[0] == "test": status_str = "[green]PASS[/green]"
            manifest = getattr(detector, "manifest", None)
            effective = plugin_health.get(f"BaseDetector:{detector.name}", {})
            calibration = str(effective.get("calibration_level", "UNCALIBRATED")).replace("_", " ").title()
            table.add_row("Detector", detector.name, status_str,
                          f"v{getattr(manifest, 'contract_version', 1)}", calibration)
            
        from core.forensics.sigma_engine import SigmaEngine
        sigma = SigmaEngine()
        for rule in sigma.rules:
            status_str = "[green]Loaded[/green]"
            table.add_row("Sigma Rule", rule.get("title", "Unknown"), status_str, "v2", "Rule dependent")
            
        console.print(table)

    def do_hunt(self, arg):
        """Run Sigma YAML rules against historical database records.

Usage: hunt [rule_name] [--source SOURCE] [--interface NAME]

Runs the Watchtower SigmaEngine to search for threats in historical flow 
and entity data. Any matched rules will generate new ForensicAlerts.
If rule_name is provided, only that specific rule is evaluated.
"""
        import shlex
        initial_parts = shlex.split(arg) if arg else []
        if "--list" in initial_parts:
            from core.cli.modules.forensics import ForensicsModule
            ForensicsModule({}).show_artifacts()
            return

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
        parts = shlex.split(arg) if arg else []
        rule_parts, source, interface = [], None, None
        cursor = 0
        while cursor < len(parts):
            if parts[cursor] == "--source" and cursor + 1 < len(parts):
                source = parts[cursor + 1]; cursor += 2
            elif parts[cursor] == "--interface" and cursor + 1 < len(parts):
                interface = parts[cursor + 1]; cursor += 2
            else:
                rule_parts.append(parts[cursor]); cursor += 1
        rule_name = " ".join(rule_parts) or None

        alerts = engine.run_hunt(source=source, specific_rule=rule_name, interface=interface)
        
        if not alerts:
            c.print("[green]Hunt complete. No Sigma matches found.[/green]")
            return
            
        c.print(f"[bold red]Hunt complete. Found {len(alerts)} Sigma matches.[/bold red]")
        table = Table(title="Sigma Hunt Results", show_header=True)
        table.add_column("Rule Match", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Target Evidence", style="white")
        
        for alert in alerts:
            ev = alert.evidence
            target = ev.get("record_id") or "Historical record"
            table.add_row(ev.get("rule", "Unknown"), alert.severity, str(target))
            
        c.print(table)
        c.print("[dim]Alerts have been saved to the database and forwarded to SIEMs.[/dim]")

    def do_survey(self, arg):
        """Capture and survey directly connected private networks.

Usage: survey [--duration 60m] [--active none|safe|deep] [--backend python|rust]
"""
        import shlex
        from core.storage.database import WatchtowerDB
        from core.survey.runner import SurveyConfig, SurveyRunner, parse_duration
        parts = shlex.split(arg)
        values = {"--duration": "60m", "--active": "deep", "--backend": None}
        try:
            for option in values:
                if option in parts: values[option] = parts[parts.index(option) + 1]
            duration = parse_duration(values["--duration"])
            report = SurveyRunner(WatchtowerDB()).run(SurveyConfig(
                duration_seconds=duration, active=values["--active"],
                capture_backend=values["--backend"],
            ), capture=duration > 0)
            console.print(f"[bold green]Survey complete.[/bold green] {len(report.devices)} device(s), "
                          f"{len(report.services)} service(s), {report.probe_count} bounded probe(s).")
            console.print(f"[dim]Hashed case bundle: {report.case_path}[/dim]")
        except (IndexError, ValueError) as exc:
            console.print(f"[red]Invalid survey options: {exc}[/red]")

    def do_stop(self, arg):
        """Stop all running background capture engines.

Usage: stop

Terminates all background capture engine processes across all
monitored interfaces. Removes their PID files from the data directory.

This does NOT delete any captured data — flows, entities, and alerts
remain in the database. Use 'clean' to wipe the database."""
        from core.mesh.hybrid import hybrid_enabled
        if hybrid_enabled():
            from core.mesh.hybrid import stop_capture
            from core.storage.database import WatchtowerDB
            db = WatchtowerDB()
            try:
                queued = stop_capture(db, str(arg or "").strip() or None)
                console.print_json(data={"queued": queued, "count": len(queued)})
            finally:
                db.close()
        else:
            from core.cli.modules.capture import CaptureModule
            CaptureModule({}).stop()

    def do_status(self, arg):
        """Check if any capture engines are currently running.

Usage: status

Shows the running state and lists all active network interfaces being
monitored. Also displays the process IDs (PIDs) for each engine."""
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
            from core.cli.modules.capture import CaptureModule
            from core.daemon.client import DaemonClient
            CaptureModule.show_status(DaemonClient().get_status())

    def do_daemon(self, arg):
        """Manage daemon lifecycle.

Usage: daemon status|stop|restart|repair
"""
        from core.daemon.client import DaemonClient
        from core.daemon.manager import DaemonManager

        action = str(arg or "status").strip().lower()
        if action == "status":
            console.print_json(data=DaemonClient().get_status())
        elif action == "stop":
            console.print_json(data=DaemonClient().shutdown())
        elif action == "restart":
            console.print_json(data=DaemonManager.restart_daemon())
        elif action == "repair":
            console.print_json(data=DaemonManager.repair_state())
        else:
            console.print("[red]Usage: daemon status|stop|restart|repair[/red]")

    def do_stats(self, arg):
        """Show live packet, flow, and traffic statistics for today.

Usage: stats

Displays a table with today's cumulative metrics including total
packets captured, flow count, and data volume in megabytes."""
        parts = shlex.split(arg)
        interface = None
        if "--interface" in parts:
            index = parts.index("--interface")
            if index + 1 < len(parts):
                interface = parts[index + 1]
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"interface": interface}).show_stats()

    def do_flows(self, arg):
        """Show the most recent network flow records from the database.

Usage: flows

Displays a table of the 20 most recent flows with columns for flow ID,
protocol, identity (hostname/SNI), and risk score. Flows are sourced
from live capture data in watchtower.db."""
        options, positional = self._parse_view_args(arg)
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule(options).show(
            "flows", ip=positional[0] if positional else None,
            limit=int(positional[1]) if len(positional) > 1 and positional[1].isdigit() else None,
        )

    def do_alerts(self, arg):
        """Show recent security alerts from the detection engine.

Usage: alerts

Displays the 15 most recent alerts including timestamp, entity IP,
severity level, and explanation. Alert types include beaconing, DNS
anomalies, lateral movement, and suspicious file transfers."""
        initial = shlex.split(arg)
        if initial and initial[0] == "disposition":
            if len(initial) < 4 or "--verdict" not in initial:
                console.print("[yellow]Usage: alerts disposition ID --verdict VERDICT --reason TEXT[/yellow]")
                return
            try:
                finding_id = int(initial[1])
                verdict = initial[initial.index("--verdict") + 1]
                reason = initial[initial.index("--reason") + 1] if "--reason" in initial else ""
                from core.storage.database import WatchtowerDB
                db = WatchtowerDB()
                try:
                    result = db.set_finding_disposition(finding_id, verdict, reason)
                finally:
                    db.close()
                console.print(f"[green]Finding {finding_id} marked {verdict}.[/green] ")
                console.print(f"[dim]Recomputed priority: {result['assessment']['priority_score']:.1f}/100[/dim]")
            except (ValueError, IndexError) as exc:
                console.print(f"[red]Disposition failed: {exc}[/red]")
            return
        options, positional = self._parse_view_args(arg)
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule(options).show(
            "alerts", ip=positional[0] if positional else None,
            limit=int(positional[1]) if len(positional) > 1 and positional[1].isdigit() else None,
        )

    def do_scoring(self, arg):
        """Operate the Behavioral Scoring V2 investigation-priority model.

Usage: scoring status|validate|explain IP|recompute [--dry-run]
"""
        parts = shlex.split(arg)
        action = parts[0] if parts else "status"
        from core.cli.modules.scoring import ScoringModule
        module = ScoringModule()
        try:
            if action == "status":
                module.status()
            elif action == "validate":
                module.validate()
            elif action == "explain":
                if len(parts) < 2:
                    raise ValueError("Usage: scoring explain IP [--source SOURCE] [--interface NAME] [--session ID]")
                options = {}
                for flag, key in (("--source", "source"), ("--interface", "interface"), ("--session", "session_id")):
                    if flag in parts and parts.index(flag) + 1 < len(parts):
                        options[key] = parts[parts.index(flag) + 1]
                module.explain(parts[1], **options)
            elif action == "recompute":
                options = {"dry_run": "--dry-run" in parts}
                for flag, key in (("--source", "source"), ("--interface", "interface"), ("--session", "session_id")):
                    if flag in parts and parts.index(flag) + 1 < len(parts):
                        options[key] = parts[parts.index(flag) + 1]
                result = module.operations.recompute(**options)
                console.print(f"[green]Recomputed {result['subjects']} subject(s).[/green] Maximum priority {result['max_priority_score']:.1f}/100")
            else:
                raise ValueError(f"Unknown scoring action: {action}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
        finally:
            module.db.close()

    @staticmethod
    def _parse_view_args(arg):
        parts = shlex.split(arg)
        options = {}
        for flag, key in (("--interface", "interface"), ("--session", "session"), ("--source", "source")):
            if flag in parts:
                index = parts.index(flag)
                if index + 1 < len(parts):
                    options[key] = parts[index + 1]
                    del parts[index:index + 2]
        return options, parts

    def do_sources(self, arg):
        """List available capture-source devices and backends."""
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
                rows = hybrid_devices(db)
            finally:
                db.close()
        else:
            from core.capture_sources import default_registry
            rows = default_registry().list_devices()
        for device in rows:
            if isinstance(device, dict):
                source_type = str(device.get("source_type") or "network")
                name = str(device.get("name") or device.get("device_id") or "unknown")
                addresses = [str(item) for item in device.get("addresses") or []]
                backends = [str(item) for item in device.get("backends") or []]
                available = bool(device.get("available", True))
                reason = str(device.get("unavailable_reason") or "")
            else:
                source_type, name = device.source_type, device.name
                addresses, backends = device.addresses, device.backends
                available, reason = device.available, device.unavailable_reason
            status = "[green]Available[/green]" if available else f"[yellow]{reason}[/yellow]"
            table.add_row(
                source_type, name, ", ".join(addresses) or "-",
                ", ".join(backends) or "-", status,
            )
        console.print(table)

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

Usage: analyze <file.pcap> [--mode auto|memory|streaming] [--backend python|rust] [--keylog <keylog_file>]

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
  --mode <mode>     auto, memory, or streaming (auto streams files at least 2 GiB)
  --backend <core>  python or rust

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
  --export [name]   Export a JSON/CSV case bundle with SHA-256 manifest

Examples:
  dive 192.168.1.50
  dive 10.0.0.5 --stream
  dive 10.0.0.5 --stream --port 445"""
        if not arg:
            console.print("[yellow]Usage: dive <IP>[/yellow]")
            return
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).dive(arg)

    def do_doctor(self, arg):
        """Run backend operational health diagnostics.

Usage: doctor

Checks configuration validity, SQLite integrity and schema, data storage,
free disk space, and daemon subprocess health."""
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).doctor()

    def do_enrich(self, arg):
        """Inspect or rebuild IP intelligence from stored packet evidence.

Usage: enrich status [--interface NAME] [--session ID]
       enrich rebuild [--interface NAME] [--session ID] [--dry-run]

Rebuild creates and verifies a SQLite backup before changing historical
derived identity fields. Captured flows, alerts, and evidence are retained."""
        import shlex
        from core.intelligence.reindex import EnrichmentReindexer
        from core.storage.database import WatchtowerDB

        parts = shlex.split(arg)
        if not parts or parts[0] not in {"status", "rebuild"}:
            console.print("[yellow]Usage: enrich status|rebuild [--interface NAME] [--session ID] [--dry-run][/yellow]")
            return
        options = {"source": None, "interface": None, "session_id": None}
        index = 1
        try:
            while index < len(parts):
                option = parts[index]
                if option == "--dry-run":
                    index += 1
                    continue
                if option not in {"--source", "--interface", "--session"}:
                    raise ValueError(option)
                options[{"--source": "source", "--interface": "interface", "--session": "session_id"}[option]] = parts[index + 1]
                index += 2
        except (IndexError, ValueError):
            console.print("[yellow]Invalid enrichment options.[/yellow]")
            return
        db = WatchtowerDB()
        try:
            service = EnrichmentReindexer(db)
            if parts[0] == "status":
                result = service.status(**options)
                console.print(f"[cyan]{result['flows']:,} flows[/cyan] across {result['ips']:,} IPs; "
                              f"{result['public_with_capture_geo']:,}/{result['public_endpoints']:,} public peers have capture-time ownership data.")
            else:
                result = service.rebuild(**options, dry_run="--dry-run" in parts)
                console.print(f"[green]{'Previewed' if result['dry_run'] else 'Rebuilt'} enrichment.[/green] "
                              f"{result['changed_flows']:,} flow contexts, {result['removed_untrusted_macs']:,} unsafe MAC claims removed.")
                if result.get("backup"):
                    console.print(f"[dim]Verified backup: {result['backup']['database']}[/dim]")
        finally:
            db.close()

    def do_identity(self, arg):
        """Inspect or rebuild evidence-backed endpoint identities.

Usage: identity status|rebuild|confirm|enrich [--interface NAME] [--session ID]
       identity confirm --pending [--dry-run]
       identity confirm --ip ADDRESS [--ip ADDRESS]

Identity cards are derived separately from flows and entities. Rebuild creates
and verifies a SQLite backup before changing those projections."""
        import shlex
        from core.intelligence.reindex import EndpointIdentityReindexer
        from core.storage.database import WatchtowerDB

        parts = shlex.split(arg)
        if not parts or parts[0] not in {"status", "rebuild", "confirm", "enrich"}:
            console.print("[yellow]Usage: identity status|rebuild|confirm|enrich [--interface NAME] [--session ID][/yellow]")
            return
        options = {"source": None, "interface": None, "session_id": None}
        index = 1
        try:
            while index < len(parts):
                option = parts[index]
                if option in {"--dry-run", "--pending"}:
                    index += 1
                    continue
                if option not in {"--source", "--interface", "--session"}:
                    raise ValueError(option)
                options[{"--source": "source", "--interface": "interface", "--session": "session_id"}[option]] = parts[index + 1]
                index += 2
        except (IndexError, ValueError):
            console.print("[yellow]Invalid identity options.[/yellow]")
            return
        db = WatchtowerDB()
        try:
            service = EndpointIdentityReindexer(db)
            if parts[0] == "status":
                result = service.status(**options)
                console.print(f"[cyan]{result['identified']:,}/{result['endpoints']:,} endpoints[/cyan] have identity associations; "
                              f"{result.get('confirmed_endpoints', 0):,} confirmed, {result.get('probable_endpoints', 0):,} probable, "
                              f"{result.get('unconfirmed_targets', 0):,} unconfirmed targets, {result.get('address_only', 0):,} address-only; "
                              f"{result['missing_identities']:,} card(s) are pending.")
            elif parts[0] == "rebuild":
                result = service.rebuild(**options, dry_run="--dry-run" in parts)
                console.print(f"[green]{'Previewed' if result['dry_run'] else 'Rebuilt'} endpoint identities.[/green] "
                              f"{result['identities']:,} records, {result['changed_identities']:,} updates.")
                if result.get("backup"):
                    console.print(f"[dim]Verified backup: {result['backup']['database']}[/dim]")
            elif parts[0] == "confirm":
                from core.intelligence.confirmation import IdentityConfirmationService
                ips = [parts[index + 1] for index, value in enumerate(parts) if value == "--ip" and index + 1 < len(parts)]
                result = IdentityConfirmationService(db).confirm(
                    ips=ips, source=options["source"], interface=options["interface"],
                    session=options["session_id"], dry_run="--dry-run" in parts,
                )
                console.print(f"[cyan]Confirmation {result['operation_id']}:[/cyan] {result['eligible']:,} eligible, "
                              f"{result.get('confirmed', 0):,} confirmed.")
            else:
                from core.intelligence.ip_lookup import IpLookupService
                ips = [parts[index + 1] for index, value in enumerate(parts) if value == "--ip" and index + 1 < len(parts)]
                if not ips:
                    ips = [row["entity_ip"] for row in db.get_endpoint_identities(
                        source=options["source"], capture_session_id=options["session_id"], limit=100,
                    )]
                complete = 0
                for ip in ips:
                    try:
                        IpLookupService(db).lookup(ip, options["source"], persist=False)
                        complete += 1
                    except Exception:
                        pass
                console.print(f"[green]Enriched {complete:,}/{len(ips):,} endpoint(s).[/green]")
        finally:
            db.close()

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
        """Reset operational data while preserving trust and configuration.

Usage: clean

Stops all running capture engines and deletes ALL data from the
database including flows, entities, alerts, carved files, timeline
data, and forensic reports.

This action is IRREVERSIBLE. You will be prompted for confirmation.
Use this when switching to a new network or starting a new
investigation from scratch."""
        option = str(arg or "").strip()
        if option not in {"", "--factory"}:
            console.print("[red]Usage: clean [--factory][/red]")
            return
        factory = option == "--factory"
        phrase = "FACTORY RESET WATCHTOWER" if factory else "RESET WATCHTOWER"
        description = (
            "all WatchTower state, authentication, mesh trust, and provider metadata"
            if factory else
            "captured, forensic, AI conversation, case, and runtime data"
        )
        confirm = input(f"This will DELETE {description}. Enter {phrase}: ").strip()
        if confirm != phrase:
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
        try:
            counts = db.reset_all(mode="factory" if factory else "operational")
        finally:
            db.close()
        
        total = sum(counts.values())
        reset_name = "Factory reset" if factory else "Operational reset"
        console.print(f"[bold green]{reset_name} complete. {total} records removed.[/bold green]")
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

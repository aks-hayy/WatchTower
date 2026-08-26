import os
import re
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.columns import Columns
from rich.rule import Rule
from rich.markup import escape
from rich.text import Text


from core.packet_engine.persistence import DailyAccumulator
from core.forensics.engine import ForensicsEngine
from core.backend_policy import backend_policy
from core.forensics.models import ForensicReport
from core.storage.database import WatchtowerDB
from core.intelligence.local_assets import LocalAssetProfiler
from core.investigation.service import InvestigationService
from core.detection.operations import ScoringOperations
from core.utils.network import format_endpoint

console = Console()

class ForensicsModule:
    def __init__(self, options):
        self.options = options
        self.db = WatchtowerDB()
        self.acc = DailyAccumulator()
        self.engine = ForensicsEngine(db=self.db)
        self.asset_profiler = LocalAssetProfiler(self.db)
        self.investigator = InvestigationService(self.db)
        self.scoring = ScoringOperations(self.db)
        # Keep last report in memory for stream following (needs raw data)
        self._last_report = None

    def run(self):
        console.print("[bold yellow]Watchtower Forensics Module Loaded.[/bold yellow]")
        console.print("Commands: show flows, show alerts, analyze <file.pcap>, dive <ip>, graph")

    def analyze(self, arg):
        import shlex
        parts = shlex.split(arg)
        if not parts:
            console.print("Usage: analyze <file.pcap> [--mode auto|memory|streaming] [--backend python|rust] [--keylog FILE]")
            return
            
        filename = parts[0]
        if not os.path.exists(filename):
            console.print(f"[red]Error: File {filename} not found.[/red]")
            return

        keylog_file = None
        if "--keylog" in parts:
            try:
                idx = parts.index("--keylog")
                keylog_file = parts[idx + 1]
                if not os.path.exists(keylog_file):
                    console.print(f"[red]Error: Keylog file {keylog_file} not found.[/red]")
                    return
            except (IndexError, ValueError):
                console.print("[red]Error: Missing keylog file path after --keylog.[/red]")
                return

        mode = "auto"
        backend = backend_policy.replay_backend()
        for option, allowed in (("--mode", {"auto", "memory", "streaming"}), ("--backend", {"python", "rust"})):
            if option in parts:
                try:
                    value = parts[parts.index(option) + 1]
                    if value not in allowed: raise ValueError
                    if option == "--mode": mode = value
                    else: backend = value
                except (IndexError, ValueError):
                    console.print(f"[red]Invalid value for {option}.[/red]")
                    return

        console.print(Panel(f"[bold cyan]Deep Forensic Analysis: {os.path.basename(filename)}[/bold cyan]\n[dim]Initializing engine and processing packets...[/dim]"))
        
        start_time = time.time()
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing PCAP...", total=100)
                
                def update_progress(current, total):
                    progress.update(task, completed=(current/total)*100)

                # ForensicsEngine now writes to SQLite automatically
                report = self.engine.analyze_pcap(
                    filename, progress_callback=update_progress, keylog_file=keylog_file,
                    mode=mode, backend=backend,
                )
                self._last_report = report

            duration = time.time() - start_time
            self._render_report(report, duration)
            
        except Exception as e:
            console.print(f"[bold red]Forensic analysis failed: {e}[/bold red]")
            import traceback
            console.print(traceback.format_exc())

    def _render_report(self, report: ForensicReport, duration: float):
        # 1. Summary Header
        summary = report.summary
        stats_panel = Panel(
            f"[bold white]Flows:[/bold white] {summary['total_flows']}  |  "
            f"[bold white]Entities:[/bold white] {summary['total_entities']}  |  "
            f"[bold red]Alerts:[/bold red] {summary['total_alerts']}  |  "
            f"[bold yellow]High Risk:[/bold yellow] {summary['high_risk_entities']}\n"
            f"[dim]Analysis completed in {duration:.2f}s[/dim]",
            title="Analysis Summary",
            border_style="blue"
        )
        console.print(stats_panel)

        # 2. Alerted Suspect Profiles
        sorted_entities = sorted(report.entities.values(), key=lambda e: e.risk_score, reverse=True)
        alerted_entities = [e for e in sorted_entities if e.risk_score > 0]

        if alerted_entities:
            console.print("\n[bold red]DETECTED SUSPECT PROFILES[/bold red]")
            profile_panels = []
            for suspect in alerted_entities:
                score_color = "red" if suspect.risk_score > 50 else ("yellow" if suspect.risk_score > 20 else "green")
                
                profile_content = (
                    f"[bold red]IP Address:[/bold red] {suspect.ip}\n"
                    f"[bold white]MAC Address:[/bold white] {suspect.mac or 'unknown'}\n"
                    f"[bold white]Host Name:[/bold white] {suspect.hostname or 'unknown'}\n"
                    f"[bold white]User Account:[/bold white] {suspect.user or 'unknown'}\n"
                    f"[bold white]Full Name:[/bold white] {suspect.full_name or suspect.user or 'unknown'}\n"
                    f"[bold white]TLS Profiling:[/bold white] {suspect.ja3_hash or 'None'} [dim]({suspect.tls_library or 'Standard Client'})[/dim]\n"
                    f"[bold white]JA4 Fingerprint:[/bold white] {suspect.ja4_string or 'None'}\n"
                    f"[bold white]Risk Score:[/bold white] [{score_color}]{suspect.risk_score:.1f}[/{score_color}]\n"
                    f"[bold white]Alerts:[/bold white] {len(suspect.alerts)}"
                )

                
                profile_panels.append(Panel(
                    profile_content,
                    title=f"Suspect: {suspect.ip}",
                    border_style=score_color,
                    expand=True
                ))
            
            console.print(Columns(profile_panels, equal=True, expand=True))
        
        # 3. Entity Table (Full list)
        table = Table(title="All Observed Entities", expand=True, box=None)
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("Traffic", style="white")
        table.add_column("Score", justify="right")
        table.add_column("Status")

        for entity in sorted_entities[:20]:
            score_color = "red" if entity.risk_score > 50 else ("yellow" if entity.risk_score > 20 else "green")
            status = "[bold red]ALERT[/bold red]" if entity.risk_score > 0 else "[dim]Normal[/dim]"
            
            table.add_row(
                entity.ip,
                entity.hostname or "[dim]-[/dim]",
                f"{entity.total_packets} pkts",
                f"[{score_color}]{entity.risk_score:.1f}[/{score_color}]",
                status
            )
        
        console.print(table)

        # 4. Detailed Evidence for high risk
        for entity in alerted_entities:
            if entity.risk_score > 20:
                unique_alerts = {}
                for a in entity.alerts:
                    key = f"{a.type}:{a.explanation}"
                    if key not in unique_alerts:
                        unique_alerts[key] = a
                
                alert_lines = [f"• [{a.severity}] {a.type}: {a.explanation}" for a in unique_alerts.values()]
                alert_list = "\n".join(alert_lines)
                console.print(Panel(
                    alert_list,
                    title=f"Forensic Evidence for {entity.ip}",
                    border_style="red",
                    subtitle=f"Identity: {entity.hostname or 'unknown'} / {entity.user or 'unknown'}"
                ))

    def _get_vendor(self, mac):
        if not mac: return "unknown"
        prefix = mac.replace(":", "").upper()[:6]
        # Common OUIs for discovery forensics
        vendors = {
            "44370B": "LG Electronics",
            "00E04C": "Realtek",
            "B827EB": "Raspberry Pi",
            "001788": "Philips Hue",
            "D80D17": "Apple",
            "28CFDA": "Apple",
            "C4AD34": "Apple",
            "000C29": "VMware",
            "080027": "VirtualBox"
        }
        return vendors.get(prefix, "unknown")

    def _render_deep_dive(self, ip: str):
        """Deep dive using SQLite data (works even without prior analyze)."""
        entity = self.db.get_entity(ip)
        if not entity:
            console.print(f"[bold red]Error:[/bold red] IP {ip} not found in database.")
            return

        console.print(Rule(f"Deep Dive: {ip} ({entity.get('hostname') or 'unknown'})", style="bold red"))
        
        # 1. Identity & Context
        identity_table = Table(box=None, padding=(0, 2))
        identity_table.add_column("Property", style="dim")
        identity_table.add_column("Value", style="bold white")
        
        mac = entity.get("mac")
        vendor = self._get_vendor(mac)
        
        identity_table.add_row("IP Address", entity.get("ip", "unknown"))
        identity_table.add_row("MAC Address", f"{mac or 'unknown'} [dim]({vendor})[/dim]")
        identity_table.add_row("Device Type", entity.get("device_type") or "unknown")
        identity_table.add_row("Asset Role", entity.get("asset_role") or "unknown")
        identity_table.add_row("Host Name", entity.get("hostname") or "unknown")
        identity_table.add_row("User Account", entity.get("username") or "unknown")
        identity_table.add_row("Full Name", entity.get("full_name") or "unknown")
        identity_table.add_row("Operating System", entity.get("os") or "unknown")
        identity_table.add_row("JA3 Hash", entity.get("ja3_hash") or "None")
        identity_table.add_row("JA4 Fingerprint", entity.get("ja4_string") or "None")
        identity_table.add_row("TLS Client", entity.get("tls_library") or "Standard Client")
        assessment = self._priority_assessment(ip)
        identity_table.add_row(
            "Investigation Priority",
            f"{assessment['priority_score']:.1f}/100 {assessment['risk_level']}",
        )
        identity_table.add_row("Source", entity.get("source", "unknown"))

        console.print(Panel(identity_table, title="[bold blue]Host Identification", border_style="blue"))

        investigation = None
        try:
            investigation = self.investigator.investigate(ip, source=self.options.get("source"))
            self._render_asset_profile(investigation.asset_profile)
            self._render_investigation(self._with_v2_assessment(investigation.to_dict(), assessment))
        except ValueError:
            console.print(f"[yellow]Unable to classify invalid IP address: {escape(ip)}[/yellow]")

        # 2. Flows
        flows = self.db.get_entity_flows(ip)
        if flows:
            all_ports = set()
            for f in flows:
                all_ports.add(f.get("dst_port", 0))
            
            port_list = ", ".join([str(p) for p in sorted(list(all_ports))[:15]])
            console.print(f"[dim]All Observed Ports:[/dim] {port_list}")

        # 3. Carved Files
        carved_files = self.db.get_carved_files(entity_ip=ip)
        if carved_files:
            file_table = Table(title="[bold yellow]Carved Files (Extracted from Streams)", expand=True)
            file_table.add_column("Filename", style="cyan")
            file_table.add_column("Type", style="white")
            file_table.add_column("Size", justify="right")
            file_table.add_column("VT Status")
            
            for cf in carved_files:
                vt_status = "[dim]N/A[/dim]"
                vt = cf.get("vt_results")
                if vt:
                    if isinstance(vt, dict):
                        if vt.get("malicious", 0) > 0:
                            vt_status = f"[bold red]MALICIOUS ({vt['malicious']})[/bold red]"
                        elif vt.get("status") == "not_found":
                            vt_status = "[yellow]Unknown[/yellow]"
                        else:
                            vt_status = "[green]Clean[/green]"
                
                file_table.add_row(
                    cf.get("filename", "unknown"),
                    cf.get("extension", "?"),
                    f"{cf.get('size', 0)/1024:.1f} KB",
                    vt_status
                )
            
            console.print(file_table)

        # 5. Top Destinations
        if flows:
            metrics_table = Table(title="Top Traffic Destinations", expand=True)
            metrics_table.add_column("Destination", style="cyan")
            metrics_table.add_column("Protocol", style="white")
            metrics_table.add_column("Packets", justify="right")
            metrics_table.add_column("Bytes", justify="right")
            
            dest_stats = {}
            for f in flows:
                dst = f.get("dst_ip", "?")
                if dst not in dest_stats:
                    dest_stats[dst] = {"packets": 0, "bytes": 0, "proto": f.get("protocol", "?")}
                dest_stats[dst]["packets"] += f.get("packet_count", 0)
                dest_stats[dst]["bytes"] += f.get("byte_count", 0)
            
            sorted_dests = sorted(dest_stats.items(), key=lambda x: x[1]["packets"], reverse=True)
            for dst, stats in sorted_dests[:10]:
                metrics_table.add_row(
                    dst, 
                    stats["proto"], 
                    str(stats["packets"]),
                    f"{stats['bytes']/1024:.1f} KB" if stats["bytes"] > 0 else "N/A"
                )
                
            console.print(metrics_table)

        return investigation

    def _render_asset_profile(self, profile: dict):
        """Render the shared passive profile used by lookup and dive."""
        overview = Table(box=None, padding=(0, 2), expand=True)
        overview.add_column("Asset Context", style="dim", width=22)
        overview.add_column("Observed Value", style="bold white")
        overview.add_row("Network Scope", profile.get("scope", "unknown"))
        overview.add_row("Local Subnet", profile.get("subnet") or "N/A")
        overview.add_row(
            "Inferred Role",
            f"{profile.get('role', 'Unclassified')} ({profile.get('role_confidence', 0) * 100:.0f}% confidence)",
        )
        overview.add_row("Role Evidence", "; ".join(profile.get("role_reasons") or ["None"]))
        overview.add_row("Device Attribute Coverage", f"{profile.get('identity_completeness', 0) * 100:.0f}%")
        overview.add_row(
            "Asset Byte Direction",
            f"out {profile.get('outbound_bytes', 0) / 1024:.1f} KB / in {profile.get('inbound_bytes', 0) / 1024:.1f} KB",
        )
        overview.add_row(
            "Peer Exposure",
            f"{len(profile.get('internal_peers') or [])} internal / {len(profile.get('external_peers') or [])} external",
        )
        console.print(Panel(overview, title="[bold cyan]Passive Asset Intelligence", border_style="cyan"))

        services = profile.get("served_services") or []
        consumed = profile.get("consumed_services") or []
        if services or consumed:
            service_table = Table(title="Observed Service Inventory", expand=True)
            service_table.add_column("Direction", style="dim")
            service_table.add_column("Service", style="cyan")
            service_table.add_column("Endpoint")
            service_table.add_column("Packets", justify="right")
            for service in services[:10]:
                service_table.add_row(
                    "Serves", service["name"], f"{service['protocol']}/{service['port']}", str(service["packets"])
                )
            for service in consumed[:10]:
                service_table.add_row(
                    "Uses", service["name"], f"{service['protocol']}/{service['port']}", str(service["packets"])
                )
            console.print(service_table)

        insights = profile.get("insights") or []
        if insights:
            console.print(Panel("\n".join(f"- {escape(item)}" for item in insights), title="Asset Findings", border_style="blue"))

    def _render_investigation(self, investigation: dict, compact: bool = False):
        verdict = investigation.get("verdict", "UNKNOWN")
        color = "red" if verdict in {"CRITICAL", "HIGH RISK"} else ("yellow" if verdict == "ELEVATED" else "green")
        headline = (
            f"[{color}]{verdict}[/{color}] | investigation priority {investigation.get('risk_score', 0):.1f}/100 | "
            f"assessment confidence {investigation.get('confidence', 0) * 100:.0f}%\n"
            f"{escape(investigation.get('summary', ''))}"
        )
        console.print(Panel(headline, title="[bold]Evidence-backed Assessment", border_style=color))
        if compact:
            return

        groups = investigation.get("alert_groups") or []
        if groups:
            alert_table = Table(title="Correlated Alert Groups", expand=True)
            alert_table.add_column("Type", style="cyan")
            alert_table.add_column("Severity")
            alert_table.add_column("Count", justify="right")
            alert_table.add_column("Evidence References")
            for group in groups[:10]:
                alert_table.add_row(
                    group["type"], group["max_severity"], str(group["count"]), ", ".join(group["refs"][:5])
                )
            console.print(alert_table)

        timeline = investigation.get("timeline") or []
        if timeline:
            timeline_table = Table(title="Evidence Timeline", expand=True)
            timeline_table.add_column("Time", width=19)
            timeline_table.add_column("Ref", style="cyan", width=14)
            timeline_table.add_column("Observation")
            for item in timeline[:15]:
                timestamp = item.get("timestamp") or 0
                when = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "unknown"
                timeline_table.add_row(when, item.get("ref", "?"), escape(item.get("summary", "")))
            console.print(timeline_table)

        actions = investigation.get("next_actions") or []
        if actions:
            console.print(Panel(
                "\n".join(f"{index}. {escape(action)}" for index, action in enumerate(actions, 1)),
                title="Recommended Investigation Actions",
                border_style="yellow",
            ))


    def do_report(self, arg):
        """
        Generate a court-ready PDF report of the last analyzed PCAP.
        Usage: report [optional_filename.pdf]
        """
        if not hasattr(self, '_last_report') or not self._last_report:
            console.print("[yellow]No recent analysis found. Please run 'analyze <pcap_file>' first.[/yellow]")
            return
            
        filename = arg.strip() if arg.strip() else None
        
        try:
            from core.utils.report_gen import ReportGenerator
            generator = ReportGenerator(output_dir=os.path.join(self.engine.data_dir, "reports"))
            pdf_path = generator.generate_forensic_report(self._last_report, filename=filename)
            console.print(f"[bold green]Forensic PDF Report generated successfully![/bold green]")
            console.print(f"Saved to: [bold cyan]{os.path.abspath(pdf_path)}[/bold cyan]")
        except Exception as e:
            console.print(f"[bold red]Failed to generate PDF report: {e}[/bold red]")


    def do_graph(self, arg):
        """
        Generate a standalone HTML network topology visualization.
        Usage: graph
        """
        import webbrowser
        import os
        
        console.print("[yellow]Generating standalone forensic topology artifact...[/yellow]")
        
        # Build graph from SQLite data
        entities = self.db.get_all_entities()
        if not entities:
            console.print("[bold red]Error:[/bold red] No data in database to visualize.")
            return

        from core.forensics.graph import ForensicGraphGenerator
        from core.forensics.models import ForensicReport, EntityProfile
        
        # Build a ForensicReport from DB data for the graph generator
        report = ForensicReport()
        # 1. Populate Entities
        for e in entities:
            profile = EntityProfile(
                ip=e["ip"], mac=e.get("mac"), hostname=e.get("hostname"),
                user=e.get("username"), full_name=e.get("full_name"),
                os=e.get("os"), ja3_hash=e.get("ja3_hash"),
                risk_score=e.get("risk_score", 0)
            )
            report.entities[e["ip"]] = profile
        
        # 2. Populate Flows (Edges)
        flows = self.db.get_flows(limit=1000) # Fetch up to 1k flows for the graph
        for f in flows:
            flow_id = (f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"])
            report.streams[flow_id] = {"packets": f["packet_count"], "bytes": f["byte_count"]}
        
        html_content = ForensicGraphGenerator.generate_cytoscape_html(report)
        
        if not os.path.exists("data"): os.makedirs("data")
        file_path = os.path.abspath("data/topology.html")
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        console.print(Panel(
            f"[green]Standalone visualization generated![/green]\n\n"
            f"[bold white]File Location:[/bold white] {file_path}\n"
            f"[dim]Opening in your browser...[/dim]",
            title="Forensic Mapping"
        ))
        
        try:
            webbrowser.open(f"file://{file_path}")
        except Exception:
            console.print("[yellow]Note: Could not open browser automatically.[/yellow]")


    def dive(self, arg):
        if not arg:
            console.print("Usage: dive <IP> [--stream --port <port>]")
            return
            
        parts = arg.split()
        ip = parts[0]

        # 0. Active Identity Resolve (If missing)
        entity = self.db.get_entity(ip)
        if entity and (not entity.get("device_type") or entity.get("device_type") == "unknown"):
            console.print(f"[dim]Performing active identity probe for {ip}...[/dim]")
            from core.forensics.plugins.parsers.infrastructure_parser import InfrastructureParser
            probe = InfrastructureParser().active_probe(ip)
            if probe.get("device_type") != "unknown":
                self.db.upsert_entity(
                    ip=ip, 
                    device_type=probe.get("device_type"),
                    asset_role=probe.get("asset_role"),
                    netbios_name=probe["identities"].get("netbios_name")
                )
                entity = self.db.get_entity(ip) # Reload
        
        if "--stream" in parts:
            # Stream following still requires in-memory report (raw packet data)
            if not self._last_report:
                console.print("[bold red]Error:[/bold red] Stream following requires a recent 'analyze' run in this session.")
                return
            
            port = None
            if "--port" in parts:
                try:
                    port_idx = parts.index("--port")
                    port = int(parts[port_idx + 1])
                except (ValueError, IndexError):
                    pass
            
            if port is None:
                for p in parts[1:]:
                    if p.isdigit():
                        port = int(p)
                        break
                    elif p.startswith("--") and p[2:].isdigit():
                        port = int(p[2:])
                        break

            self._render_stream(self._last_report, ip, port)
        else:
            # Deep dive from SQLite — works always
            investigation = self._render_deep_dive(ip)
            if investigation and "--export" in parts:
                export_index = parts.index("--export")
                case_name = None
                if export_index + 1 < len(parts) and not parts[export_index + 1].startswith("--"):
                    case_name = parts[export_index + 1]
                try:
                    from core.investigation.export import CaseExporter
                    case_dir = CaseExporter(os.path.join(self.engine.data_dir, "cases")).export(
                        investigation, case_name=case_name
                    )
                    console.print(f"[bold green]Case exported:[/bold green] {case_dir.resolve()}")
                except FileExistsError:
                    console.print("[bold red]Case export failed:[/bold red] that case name already exists.")

    def doctor(self, json_output: bool = False):
        """Run configuration, database, schema, storage and daemon diagnostics."""
        import json
        from core.operations.health import HealthService
        from core.daemon.client import DaemonClient

        report = HealthService(self.db).run()
        daemon = DaemonClient().get_status()
        daemon_status = "pass" if daemon.get("running") and daemon.get("healthy", True) else (
            "warn" if daemon.get("running") else "fail"
        )
        report["daemon"] = {
            "status": daemon_status,
            "running": bool(daemon.get("running")),
            "healthy": bool(daemon.get("healthy", False)),
            "interfaces": daemon.get("interfaces") or [],
        }
        if json_output:
            print(json.dumps(report, sort_keys=True, default=str))
            return report
        table = Table(title="Watchtower Operational Health", expand=True)
        table.add_column("Check", style="cyan")
        table.add_column("Status")
        table.add_column("Detail")
        colors = {"pass": "green", "warn": "yellow", "fail": "red"}
        for check in report["checks"]:
            color = colors.get(check["status"], "white")
            table.add_row(check["name"], f"[{color}]{check['status'].upper()}[/{color}]", check["detail"])

        color = colors[daemon_status]
        detail = f"interfaces: {', '.join(daemon.get('interfaces') or []) or 'none'}"
        table.add_row("daemon", f"[{color}]{daemon_status.upper()}[/{color}]", detail)
        console.print(table)

    def _identify_stream_type(self, data: bytes) -> str:
        if not data: return "Empty"
        if data.startswith(b"GET ") or data.startswith(b"POST ") or data.startswith(b"HTTP/1."):
            return "HTTP Plaintext"
        if data.startswith(b"\x16\x03\x01") or data.startswith(b"\x16\x03\x03"):
            return "TLS Encrypted (SSL) - Payload will be unreadable without keys"
        if b"SSH-" in data[:20]:
            return "SSH Encrypted - Payload will be unreadable"
        if data.startswith(b"\x00\x00\x00"):
            return "Binary Protocol (SMB/RPC/Custom)"
        
        printable = sum(1 for b in data if 32 <= b <= 126 or b in b"\n\r\t")
        if printable / len(data) > 0.8:
            return "Plaintext ASCII"
            
        return "Unknown Binary Data"

    def _decode_binary_protocol(self, data: bytes) -> str:
        """Deep analysis of binary blobs to extract human-readable metadata."""
        import re
        results = []
        
        # 0. Check for SASL/GSSAPI Wrapping
        if data.startswith(b"\x05\x04") or (len(data) > 4 and data[4:6] == b"\x05\x04"):
            results.append("--- SASL/GSSAPI Encrypted Session Detected ---\nThe payload is encrypted or signed via Kerberos/NTLM SASL layer. "
                           "Plaintext decoding is not possible without session keys.")

        # 1. LDAP Attribute Extraction
        ldap_attrs = [
            b"sAMAccountName", b"distinguishedName", b"displayName", b"mail",
            b"memberOf", b"operatingSystem", b"lastLogon", b"whenCreated",
            b"servicePrincipalName", b"dNSHostName", b"objectSid", b"cn=", b"CN="
        ]
        found_ldap = []
        for attr in ldap_attrs:
            if attr in data:
                idx = data.find(attr)
                sub_data = data[idx : idx + 150]
                matches = re.findall(rb"([a-zA-Z0-9\s,.=_\-\(\)]{4,128})", sub_data)
                for m in matches:
                    val = m.decode('utf-8', errors='ignore').strip()
                    if val.lower() == attr.decode().lower().rstrip('='):
                        continue
                    if val and val not in found_ldap:
                        if any(c in val for c in ["=", ",", "CN", "DC", "OU"]) or len(val) > 5:
                            found_ldap.append(f"{attr.decode().rstrip('=')}: {val}")
                            break
        
        if found_ldap:
            results.append("--- Extracted LDAP Metadata ---\n" + "\n".join(found_ldap))

        # 2. General String Extraction
        if not results:
            all_strings = re.findall(rb"([a-zA-Z0-9\s,.=_\-\(\)]{8,128})", data)
            meaningful = [s.decode('utf-8', errors='ignore').strip() for s in all_strings if len(s) > 10]
            if meaningful:
                results.append("--- Discovered Printable Strings ---\n" + "\n".join(list(set(meaningful))[:10]))

        # 3. NTLM Detection
        if b"NTLMSSP" in data:
            results.append("--- NTLM Auth Detected ---\nContains NTLM Security Support Provider challenge/response.")
            
        # 4. Path/Filename Extraction
        paths = re.findall(rb"([a-zA-Z]:\\[a-zA-Z0-9\s._\\-]{5,256}|\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9\s._\\-]+)", data)
        if paths:
            unique_paths = list(set([p.decode('utf-8', errors='ignore') for p in paths]))
            results.append("--- Discovered Paths ---\n" + "\n".join(unique_paths))

        return "\n\n".join(results) if results else ""

    def _render_stream(self, report: ForensicReport, ip: str, port: int = None):
        console.print(Rule(f"TCP Stream Follow: {ip} " + (f"on port {port}" if port else ""), style="bold cyan"))
        
        filename = f"data/dive_{ip.replace('.', '_')}_{port or 'all'}.txt"
        found_any = False
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"=== Watchtower Consolidated Stream Export ===\n")
                f.write(f"Target IP: {ip}\n")
                f.write(f"Target Port: {port if port is not None else 'ALL'}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write("="*60 + "\n\n")

                for flow_id, streams in report.streams.items():
                    if flow_id[0] == ip or flow_id[1] == ip:
                        if port is None or flow_id[2] == port or flow_id[3] == port:
                            found_any = True
                            
                            f.write(f"\n[FLOW: {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}]\n")
                            f.write("-" * 40 + "\n")
                            
                            console.print(f"\n[bold green]Flow: {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]}[/bold green]")
                            
                            for dir_name, color in [("to_server", "cyan"), ("to_client", "yellow")]:
                                data = None
                                if hasattr(streams, f"reassembled_{dir_name}"):
                                    data = getattr(streams, f"reassembled_{dir_name}", None)
                                
                                if data:
                                    stream_type = self._identify_stream_type(data)
                                    binary_insights = self._decode_binary_protocol(data)
                                    
                                    f.write(f"\n({dir_name.upper()} - {stream_type})\n")
                                    if binary_insights:
                                        f.write(f"{binary_insights}\n")
                                        f.write("-" * 20 + "\n")
                                    
                                    f.write(data.decode('utf-8', errors='replace'))
                                    f.write("\n")
                                    
                                    size_kb = len(data) / 1024
                                    console.print(f"[{color}]{dir_name.upper()}:[/{color}] {stream_type} ({size_kb:.1f} KB)")
                            
                            f.write("\n" + "="*60 + "\n")
            
            if found_any:
                console.print(f"\n[bold green]All matching streams and insights consolidated to: {filename}[/bold green]")
            else:
                if os.path.exists(filename): os.remove(filename)
                console.print(f"[yellow]No TCP streams found for {ip}" + (f" on port {port}" if port else "") + "[/yellow]")

        except Exception as e:
            console.print(f"[red]Error dumping streams to file: {e}[/red]")
            import traceback
            console.print(traceback.format_exc())


    def show(self, arg, ip=None, limit=None):
        source = self.options.get("source") or "live"
        interface = self.options.get("interface")
        capture_session_id = self.options.get("session")
        limit = limit or 20
        if arg == "flows":
            query_limit = limit if capture_session_id else limit * 3
            if ip:
                flows = self.db.get_entity_flows(
                    ip, limit=query_limit, source=source, interface=interface,
                    capture_session_id=capture_session_id,
                )
                title = f"Recent Flows for {ip} ({source})"
            else:
                flows = self.db.get_flows(
                    source=source, limit=query_limit, interface=interface,
                    capture_session_id=capture_session_id,
                )
                title = f"Recent Flow Forensics ({source})"

            if not capture_session_id:
                unique_flows = {}
                for flow in flows:
                    key = (
                        flow.get("capture_interface"), flow.get("src_ip"), flow.get("src_port"),
                        flow.get("dst_ip"), flow.get("dst_port"), flow.get("protocol"),
                    )
                    current = unique_flows.get(key)
                    if current is None or float(flow.get("last_seen") or 0) > float(current.get("last_seen") or 0):
                        unique_flows[key] = flow
                flows = list(unique_flows.values())[:limit]
            
            narrow = console.width < 110
            # The narrow IPv6 form is intentionally compact enough to remain
            # visible inside an 80-column Rich table after borders and cell
            # padding are accounted for.
            endpoint_width = 22 if narrow else 34
            # Preserve the compact IPv6 endpoint at its natural width on
            # narrow terminals; expanding the table makes Rich squeeze it
            # when the other columns compete for the same 80 columns.
            table = Table(title=title, expand=not narrow, pad_edge=not narrow)
            table.add_column("Iface" if narrow else "Interface", style="cyan", no_wrap=True, max_width=8 if narrow else 16)
            table.add_column("Source", overflow="ellipsis", no_wrap=True, max_width=endpoint_width)
            table.add_column("Destination", overflow="ellipsis", no_wrap=True, max_width=endpoint_width)
            table.add_column("Proto", justify="center", no_wrap=True, min_width=5)
            if not narrow:
                table.add_column("Identity", overflow="ellipsis", max_width=24)
            table.add_column("Priority", justify="right", no_wrap=True, max_width=4 if narrow else None)
            priority_cache = {}
            
            for f in flows:
                meta = f.get("l7_metadata", {})
                if isinstance(meta, str):
                    import json
                    try: meta = json.loads(meta)
                    except Exception: meta = {}
                flow_context = meta.get("watchtower_intel_v1") or {}
                identity = (
                    meta.get("hostname") or meta.get("sni") or meta.get("dns_query")
                    or flow_context.get("purpose", "")
                )
                if isinstance(identity, list): identity = identity[0] if identity else ""
                
                subject = f.get("src_ip", "")
                score_key = (subject, source, interface, capture_session_id)
                if score_key not in priority_cache:
                    priority_cache[score_key] = self._priority_assessment(
                        subject, source=source, interface=interface, session_id=capture_session_id,
                    )["priority_score"]
                score = priority_cache[score_key]
                score_color = "red" if score >= 80 else ("yellow" if score >= 50 else ("cyan" if score >= 20 else "green"))
                
                row = [
                    f.get("capture_interface") or self._interface_from_source(f.get("source")),
                    Text(format_endpoint(
                        f.get("src_ip"), f.get("src_port"), compact="narrow" if narrow else True
                    )),
                    Text(format_endpoint(
                        f.get("dst_ip"), f.get("dst_port"), compact="narrow" if narrow else True
                    )),
                    str(f.get("protocol") or "?").upper(),
                ]
                if not narrow:
                    row.append(str(identity))
                score_text = f"{score:.0f}" if narrow else f"{score:.1f}"
                row.append(f"[{score_color}]{score_text}[/{score_color}]")
                table.add_row(*row)
            console.print(table)
        elif arg == "alerts":
            if ip:
                alerts = self.db.get_alerts(
                    entity_ip=ip, source=source, limit=limit, interface=interface,
                    capture_session_id=capture_session_id,
                )
                title = f"Security Alerts for {ip} ({source})"
            else:
                alerts = self.db.get_alerts(
                    source=source, limit=limit, interface=interface,
                    capture_session_id=capture_session_id,
                )
                title = f"Security Alerts ({source})"
                
            narrow = console.width < 110
            table = Table(title=title, expand=narrow, pad_edge=not narrow)
            if narrow:
                table.add_column("Subject", no_wrap=True, overflow="ellipsis", width=28)
                table.add_column("Finding", no_wrap=True, overflow="ellipsis")
            else:
                table.add_column("Time", no_wrap=True, width=8)
                table.add_column("Entity", no_wrap=True, overflow="ellipsis", max_width=22)
                table.add_column("Interface", no_wrap=True, overflow="ellipsis", max_width=9)
                table.add_column("Severity", no_wrap=True, max_width=8)
                table.add_column("Explanation", overflow="fold")
            
            for a in alerts:
                time_format = "%H:%M" if narrow else "%H:%M:%S"
                ts = datetime.fromtimestamp(a.get("timestamp", 0)).strftime(time_format) if a.get("timestamp") else "?"
                entity = Text(format_endpoint(a.get("entity_ip"), compact="narrow" if narrow else False))
                severity = str(a.get("severity", "?"))
                if narrow:
                    severity = {"CRITICAL": "CRIT", "MEDIUM": "MED"}.get(severity.upper(), severity[:4].upper())
                    captured_on = a.get("capture_interface") or self._interface_from_source(a.get("source"))
                    context = f" {captured_on}" if captured_on != "-" else ""
                    row = [entity, f"{ts} {severity}{context}: {a.get('explanation', '')}"]
                else:
                    row = [
                        ts, entity,
                        a.get("capture_interface") or self._interface_from_source(a.get("source")),
                        severity, a.get("explanation", ""),
                    ]
                table.add_row(*row)
            console.print(table)
        else:
            console.print("[yellow]Usage: show flows [ip] [limit] | show alerts [ip] [limit][/yellow]")

    @staticmethod
    def _interface_from_source(source):
        source = str(source or "")
        if not source.startswith("live_"):
            return "-"
        return source[5:].split("#", 1)[0]

    def show_artifacts(self):
        """List files carved from historical traffic without running Sigma."""
        source = self.options.get("source")
        artifacts = self.db.get_carved_files(source=source)
        title = "Carved Evidence Artifacts" + (f" ({source})" if source else "")
        table = Table(title=title)
        table.add_column("Entity", style="cyan")
        table.add_column("Type")
        table.add_column("Size", justify="right")
        table.add_column("SHA-256", overflow="ellipsis", max_width=18)
        table.add_column("Path", overflow="fold")
        for artifact in artifacts:
            size = int(artifact.get("size") or 0)
            table.add_row(
                str(artifact.get("entity_ip") or "-"), str(artifact.get("extension") or "unknown"),
                f"{size:,} B", str(artifact.get("sha256") or "-"),
                str(artifact.get("filename") or "-"),
            )
        console.print(table)
        if not artifacts:
            console.print("[dim]No carved evidence artifacts found.[/dim]")

    def show_stats(self):
        interface = self.options.get("interface")
        active_scope = "interfaces" in self.options
        interfaces = self.options.get("interfaces") if active_scope else None
        if interface:
            stats = self.db.get_window_stats(source="live", interface=interface, window_seconds=86400)
        elif active_scope:
            interfaces = sorted({str(name) for name in (interfaces or []) if name})
            if interfaces:
                interface_stats = [self.acc.get_today(source=f"live_{name}") for name in interfaces]
                stats = {
                    "total_flows": sum(item.get("total_flows", 0) for item in interface_stats),
                    "total_packets": sum(item.get("total_packets", 0) for item in interface_stats),
                    "total_bytes": sum(item.get("total_bytes", 0) for item in interface_stats),
                }
            else:
                # A stopped daemon has no active interface list.  Keep recent
                # live session totals visible instead of showing a false zero.
                active_scope = False
                interfaces = self.db.get_today_live_interfaces()
                interface_stats = [self.acc.get_today(source=f"live_{name}") for name in interfaces]
                stats = {
                    "total_flows": sum(item.get("total_flows", 0) for item in interface_stats),
                    "total_packets": sum(item.get("total_packets", 0) for item in interface_stats),
                    "total_bytes": sum(item.get("total_bytes", 0) for item in interface_stats),
                }
        else:
            # Mesh-prefixed live sources do not create legacy DailyStats rows;
            # use the same authoritative flow aggregation as the API/UI.
            stats = self.acc.get_today(source="live")
            interfaces = self.db.get_today_live_interfaces()
        table = Table(title=f"Live Stats{f' ({interface})' if interface else ''}")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Flows", str(stats.get("total_flows", 0)))
        table.add_row("Packets", str(stats.get("total_packets", 0)))
        table.add_row("Bytes", f"{stats.get('total_bytes', 0)/(1024*1024):.2f} MB")
        console.print(table)

        if not interface:
            if not active_scope:
                interfaces = self.db.get_today_live_interfaces()
            if interfaces:
                breakdown = Table(title="Interface Breakdown")
                breakdown.add_column("Interface", style="cyan")
                breakdown.add_column("Flows", justify="right")
                breakdown.add_column("Packets", justify="right")
                breakdown.add_column("Bytes", justify="right")
                for name in interfaces:
                    item = self.acc.get_today(source=f"live_{name}")
                    breakdown.add_row(
                        name, str(item.get("total_flows", 0)), str(item.get("total_packets", 0)),
                        f"{item.get('total_bytes', 0)/(1024*1024):.2f} MB",
                    )
                console.print(breakdown)

    def lookup(self, ip):
        """Render the same evidence-backed lookup used by the local API."""
        from core.intelligence.ip_lookup import IpLookupService

        source = self.options.get("source")
        with console.status(f"[cyan]Performing deep lookup for {ip}..."):
            try:
                investigation = self.investigator.investigate(ip, source=source)
                lookup = IpLookupService(self.db).lookup(ip, source=source, persist=True)
            except ValueError:
                console.print(f"[bold red]Invalid IP address:[/bold red] {escape(ip)}")
                return
        asset_profile = lookup["asset_profile"]
        identity = lookup["identity"]
        enrichment = lookup["enrichment"]
        activity = lookup["activity"]
        alerts = int(activity.get("alert_count") or 0)

        # 1. External Intelligence Panel
        intel_table = Table(box=None, padding=(0, 2))
        intel_table.add_column("Source", style="dim")
        intel_table.add_column("Intelligence", style="bold white")
        
        intel_table.add_row("Location", lookup["location"].get("label") or "Unknown")
        intel_table.add_row("ISP / Org", f"{enrichment.get('isp') or 'Unknown'} [dim]({enrichment.get('org') or 'Unknown'})[/dim]")
        intel_table.add_row("ASN", enrichment.get("asn") or "Unknown ASN")
        intel_table.add_row("Reverse DNS", identity.get("reverse_dns") or "[dim]None found[/dim]")
        intel_table.add_row("Evidence", str(enrichment.get("evidence_source") or "capture/passive"))
        
        # Threat flags
        is_internal = lookup.get("scope") in {"private", "link-local", "loopback"} or enrichment.get("is_local_endpoint")
        flag_style = "green" if not is_internal else "blue"
        flag_text = "Internal Asset" if is_internal else "External Host"
        
        console.print(Panel(
            intel_table, 
            title=f"[bold white]Intelligence Lookup: {ip}[/bold white] [[{flag_style}]{flag_text}[/{flag_style}]]",
            border_style="cyan"
        ))

        endpoint_identity = lookup.get("endpoint_identity") or {}
        if endpoint_identity:
            identity_table = Table(box=None, padding=(0, 2), expand=True)
            identity_table.add_column("Endpoint Identity", style="bold magenta")
            identity_table.add_column("Evidence-backed Value", style="white")
            identity_table.add_row("Association", str(endpoint_identity.get("identity_label") or ip))
            identity_table.add_row("Identity Type", str(endpoint_identity.get("identity_type") or "address_endpoint"))
            identity_table.add_row(
                "Confidence",
                f"{float(endpoint_identity.get('confidence') or 0.0) * 100:.0f}% ({endpoint_identity.get('verification') or 'observed'})",
            )
            evidence = endpoint_identity.get("evidence") or []
            if evidence:
                identity_table.add_row("Basis", "; ".join(str(item.get("summary")) for item in evidence[:3]))
            console.print(Panel(identity_table, title="Endpoint Identity", border_style="magenta"))

        self._render_asset_profile(asset_profile)
        flow_intelligence = lookup.get("flow_intelligence") or {}
        if flow_intelligence.get("total_flows"):
            flow_table = Table(box=None, padding=(0, 2), expand=True)
            flow_table.add_column("Capture Evidence", style="bold cyan")
            flow_table.add_column("Observed Context", style="white")
            purposes = list(flow_intelligence.get("purposes") or [])
            services = list(flow_intelligence.get("services") or [])
            directions = flow_intelligence.get("directions") or {}
            actions = list(flow_intelligence.get("recommended_actions") or [])
            if purposes:
                flow_table.add_row("Classifications", ", ".join(str(value) for value in purposes[:4]))
            if services:
                labels = [
                    f"{item.get('name')} ({item.get('port')}/{item.get('protocol')}, {item.get('basis')})"
                    for item in services[:4]
                ]
                flow_table.add_row("Service Context", ", ".join(labels))
            if directions:
                flow_table.add_row(
                    "Direction",
                    ", ".join(f"{name}: {count}" for name, count in sorted(directions.items())),
                )
            if actions:
                flow_table.add_row("Next Step", str(actions[0]))
            console.print(Panel(flow_table, title="Capture Evidence Summary", border_style="blue"))

        assessment = self._priority_assessment(ip)
        self._render_investigation(
            self._with_v2_assessment(investigation.to_dict(), assessment), compact=True,
        )

        # 2. Watchtower Internal Context
        if activity.get("flow_count") or alerts or identity.get("hostname"):
            context_table = Table(box=None, padding=(0, 2), expand=True)
            context_table.add_column("Watchtower Context", style="bold yellow")
            context_table.add_column("Details", style="white")

            if identity:
                id_text = f"{identity.get('hostname') or 'Unknown Host'} ({identity.get('username') or 'No User'})"
                context_table.add_row("Host Attributes", id_text)
                score = assessment["priority_score"]
                score_color = "red" if score >= 80 else ("yellow" if score >= 50 else ("cyan" if score >= 20 else "green"))
                context_table.add_row(
                    "Investigation Priority",
                    f"[{score_color}]{score:.1f}/100 {assessment['risk_level']}[/{score_color}]",
                )
                context_table.add_row("Asset Role", asset_profile.get("role", "Unclassified"))
            
            if activity.get("flow_count"):
                total_bytes = int(activity.get("total_bytes") or 0)
                total_pkts = int(activity.get("total_packets") or 0)
                context_table.add_row("Session Traffic", f"{total_pkts} packets / {total_bytes/1024:.1f} KB")
            
            if alerts:
                context_table.add_row("Security Alerts", f"[bold red]{alerts} alerts triggered[/bold red]")

            console.print(Panel(context_table, title="Watchtower Forensic History", border_style="yellow"))
        else:
            console.print("[dim]No prior session history found for this IP in Watchtower database.[/dim]")

        # 3. Quick Action Recommendations
        if alerts or (activity.get("flow_count") and assessment["priority_score"] >= 50):
             console.print("\n[bold red]RECOMMENDED ACTION:[/bold red] Run [cyan]dive {ip}[/cyan] to inspect reassembled streams and behavior.")
        elif is_internal:
             console.print("\n[dim]Tip: Use [cyan]graph[/cyan] to see how this internal host is connected to the rest of the network.[/dim]")

    def _priority_assessment(self, ip, source=None, interface=None, session_id=None):
        source = source if source is not None else (self.options.get("source") or "live")
        interface = interface if interface is not None else self.options.get("interface")
        session_id = session_id if session_id is not None else self.options.get("session")
        try:
            return self.scoring.explain(
                ip, source=source, interface=interface, session_id=session_id, persist=False,
            )
        except Exception:
            return {
                "priority_score": 0.0, "risk_level": "LOW", "assessment_confidence": 0.0,
                "contributors": [],
            }

    @staticmethod
    def _with_v2_assessment(investigation, assessment):
        result = dict(investigation)
        level = assessment.get("risk_level", "LOW")
        result["risk_score"] = float(assessment.get("priority_score") or 0.0)
        result["confidence"] = float(assessment.get("assessment_confidence") or 0.0)
        result["verdict"] = "HIGH RISK" if level == "HIGH" else level
        result["summary"] = (
            f"V2 scoring identified {len(assessment.get('contributors') or [])} active contributor(s). "
            "Priority is an investigation index, not a threat probability."
        )
        return result

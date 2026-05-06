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


from core.packet_engine.persistence import DailyAccumulator
from core.packet_engine.utils import get_geoip_info, get_reverse_dns
from core.forensics.engine import ForensicsEngine
from core.forensics.models import ForensicReport
from core.storage.database import WatchtowerDB

console = Console()

class ForensicsModule:
    def __init__(self, options):
        self.options = options
        self.db = WatchtowerDB()
        self.acc = DailyAccumulator()
        self.engine = ForensicsEngine(db=self.db)
        # Keep last report in memory for stream following (needs raw data)
        self._last_report = None

    def run(self):
        console.print("[bold yellow]Watchtower Forensics Module Loaded.[/bold yellow]")
        console.print("Commands: show flows, show alerts, analyze <file.pcap>, dive <ip>, graph")

    def analyze(self, arg):
        parts = arg.split()
        if not parts:
            console.print("Usage: analyze <file.pcap> [--keylog <keylog_file>]")
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

        console.print(Panel(f"[bold cyan]Deep Forensic Analysis: {os.path.basename(filename)}[/bold cyan]\n[dim]Initializing engine and processing packets...[/dim]"))
        
        start_time = time.time()
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Processing PCAP...", total=100)
                
                def update_progress(current, total):
                    progress.update(task, completed=(current/total)*100)

                # ForensicsEngine now writes to SQLite automatically
                report = self.engine.analyze_pcap(filename, progress_callback=update_progress, keylog_file=keylog_file)
                self._last_report = report

                from core.forensics.sigma_engine import SigmaEngine
                sigma = SigmaEngine()
                if sigma.rules:
                    progress.update(task, description="[cyan]Running Sigma Rules...[/cyan]")
                    alerts = sigma.run_hunt(source=self.engine._source)
                    # The alerts are automatically added to DB and will be shown in _render_report 
                    # when it pulls from the DB, but since the in-memory report is already built,
                    # we should append them to the report.entities for immediate CLI rendering.
                    for alert in alerts:
                        ev = alert.evidence
                        ip = ev.get("entity_ip") or ev.get("flow", "").split(" ")[0]
                        if ip and ip in report.entities:
                            report.entities[ip].alerts.append(alert)
                            report.entities[ip].risk_score += alert.score

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
        identity_table.add_row("Risk Score", f"{entity.get('risk_score', 0):.1f}")
        identity_table.add_row("Source", entity.get("source", "unknown"))

        console.print(Panel(identity_table, title="[bold blue]Host Identification", border_style="blue"))

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

        # 4. Alerts
        alerts = self.db.get_alerts(entity_ip=ip)
        if alerts:
            unique_alerts = {}
            for a in alerts:
                key = f"{a.get('type')}:{a.get('explanation')}"
                if key not in unique_alerts:
                    unique_alerts[key] = a
            
            behaviors = []
            for alert in unique_alerts.values():
                severity = alert.get("severity", "MEDIUM")
                color = "red" if severity == "CRITICAL" else "yellow"
                behaviors.append(f"[{color}]• {alert.get('type', 'UNKNOWN')}:[/{color}] {alert.get('explanation', '')}")
            
            console.print(Panel("\n".join(behaviors), title="[bold red]Malware Behavior & Alerts", border_style="red"))

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
            self._render_deep_dive(ip)

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
        limit = limit or 20
        if arg == "flows":
            if ip:
                flows = self.db.get_entity_flows(ip, limit=limit)
                title = f"Recent Flows for {ip} ({source})"
            else:
                flows = self.db.get_flows(source=source, limit=limit)
                title = f"Recent Flow Forensics ({source})"
            
            table = Table(title=title)
            table.add_column("Flow ID")
            table.add_column("Proto")
            table.add_column("Identity")
            table.add_column("Score")
            
            for f in flows:
                meta = f.get("l7_metadata", {})
                if isinstance(meta, str):
                    import json
                    try: meta = json.loads(meta)
                    except Exception: meta = {}
                identity = meta.get("hostname") or meta.get("sni") or meta.get("dns_query", "")
                if isinstance(identity, list): identity = identity[0] if identity else ""
                
                # Get entity for risk score
                entity = self.db.get_entity(f.get("src_ip", ""))
                score = entity.get("risk_score", 0.0) if entity else 0.0
                score_color = "red" if score > 70 else ("yellow" if score > 40 else "green")
                
                table.add_row(
                    f.get("flow_id", ""),
                    f.get("protocol", "?"),
                    str(identity),
                    f"[{score_color}]{score:.1f}[/{score_color}]"
                )
            console.print(table)
        elif arg == "alerts":
            if ip:
                alerts = self.db.get_alerts(entity_ip=ip, source=source, limit=limit)
                title = f"Security Alerts for {ip} ({source})"
            else:
                alerts = self.db.get_alerts(source=source, limit=limit)
                title = f"Security Alerts ({source})"
                
            table = Table(title=title)
            table.add_column("Time")
            table.add_column("Entity")
            table.add_column("Severity")
            table.add_column("Explanation")
            
            for a in alerts:
                ts = datetime.fromtimestamp(a.get("timestamp", 0)).strftime("%H:%M:%S") if a.get("timestamp") else "?"
                table.add_row(ts, a.get("entity_ip", "?"), a.get("severity", "?"), a.get("explanation", ""))
            console.print(table)
        else:
            console.print("[yellow]Usage: show flows [ip] [limit] | show alerts [ip] [limit][/yellow]")

    def lookup(self, ip):
        """Enhanced IP intelligence lookup combining external and internal data."""
        with console.status(f"[cyan]Performing deep lookup for {ip}..."):
            geo = get_geoip_info(ip)
            rdns = get_reverse_dns(ip)
            
            # Check internal DB for this IP
            entity = self.db.get_entity(ip)
            flows = self.db.get_entity_flows(ip)
            alerts = self.db.get_alerts(entity_ip=ip)

        # 1. External Intelligence Panel
        intel_table = Table(box=None, padding=(0, 2))
        intel_table.add_column("Source", style="dim")
        intel_table.add_column("Intelligence", style="bold white")
        
        intel_table.add_row("Location", f"{geo.get('city')}, {geo.get('country')}")
        intel_table.add_row("ISP / Org", f"{geo.get('isp')} [dim]({geo.get('org')})[/dim]")
        intel_table.add_row("ASN", geo.get('asn'))
        intel_table.add_row("Reverse DNS", rdns or "[dim]None found[/dim]")
        
        # Threat flags
        is_internal = "Local Network" in geo.get('country', '')
        flag_style = "green" if not is_internal else "blue"
        flag_text = "Internal Asset" if is_internal else "External Host"
        
        console.print(Panel(
            intel_table, 
            title=f"[bold white]Intelligence Lookup: {ip}[/bold white] [[{flag_style}]{flag_text}[/{flag_style}]]",
            border_style="cyan"
        ))

        # 2. Watchtower Internal Context
        if entity or flows or alerts:
            context_table = Table(box=None, padding=(0, 2), expand=True)
            context_table.add_column("Watchtower Context", style="bold yellow")
            context_table.add_column("Details", style="white")

            if entity:
                id_text = f"{entity.get('hostname') or 'Unknown Host'} ({entity.get('username') or 'No User'})"
                context_table.add_row("Identity", id_text)
                score = entity.get('risk_score', 0)
                score_color = "red" if score > 50 else ("yellow" if score > 20 else "green")
                context_table.add_row("Risk Score", f"[{score_color}]{score:.1f}[/{score_color}]")
            
            if flows:
                total_bytes = sum(f.get('byte_count', 0) for f in flows)
                total_pkts = sum(f.get('packet_count', 0) for f in flows)
                context_table.add_row("Session Traffic", f"{total_pkts} packets / {total_bytes/1024:.1f} KB")
            
            if alerts:
                context_table.add_row("Security Alerts", f"[bold red]{len(alerts)} alerts triggered[/bold red]")

            console.print(Panel(context_table, title="Watchtower Forensic History", border_style="yellow"))
        else:
            console.print("[dim]No prior session history found for this IP in Watchtower database.[/dim]")

        # 3. Quick Action Recommendations
        if alerts or (entity and entity.get('risk_score', 0) > 40):
             console.print("\n[bold red]RECOMMENDED ACTION:[/bold red] Run [cyan]dive {ip}[/cyan] to inspect reassembled streams and behavior.")
        elif is_internal:
             console.print("\n[dim]Tip: Use [cyan]graph[/cyan] to see how this internal host is connected to the rest of the network.[/dim]")

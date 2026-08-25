import sys
import os
import datetime
import signal
import psutil
import multiprocessing
import threading
from rich.console import Console
from rich.table import Table
from core.packet_engine.capture import start_capture
from core.packet_engine.flow_worker import flow_worker
from core.packet_engine.config import PacketEngineConfig
from core.packet_engine.persistence import DailyAccumulator
from core.packet_engine.ipc import get_ipc_key, IPC_PORT
from multiprocessing.connection import Listener, Client
import scapy.all as scapy


console = Console()

class CaptureModule:
    PID_FILE = "data/engine.pid"
    
    def __init__(self, options):
        self.options = options
        self.config = PacketEngineConfig(
            source_type=options.get("source_type") or "network",
            capture_backend=options.get("backend"),
        )
        self.control_queue = multiprocessing.Queue()
        self.ipc_key = get_ipc_key(self.config.data_dir)
        self.ipc_port = IPC_PORT

        if "interface" in options:
            self.config.interface = options["interface"]

    def run(self, background=False):
        from core.daemon.manager import DaemonManager
        DaemonManager.ensure_running(silent=True)

        from core.daemon.client import DaemonClient
        client = DaemonClient()

        interfaces = []
        if "interface" in self.options and self.options["interface"]:
            interfaces = [self.options["interface"]]
        else:
            # Interactive Selection
            interfaces = self._select_interfaces(multi=True)

        if not interfaces:
            return

        if background:
            client.set_background(True)

        for iface in interfaces:
            if self._is_running(iface):
                console.print(f"[yellow]Engine for {iface} is already running.[/yellow]")
                continue

            console.print(f"[cyan]Starting capture on {iface}...[/cyan]")
            res = client.start_engine(
                iface, backend=self.config.capture_backend,
                source_type=self.config.source_type,
            )
            
            if res.get("status") == "error":
                console.print(f"[red]Error starting {iface}: {res.get('message')}[/red]")
            elif res.get("status") == "started":
                console.print(f"[green]Engine started on {res.get('interface', iface)}[/green]")

        if background:
            console.print("[bold green]\nWATCHTOWER is now running in BACKGROUND MODE.[/bold green]")
            console.print("[dim]Monitoring will continue even if you close this terminal.[/dim]")
            console.print("[dim]Use 'tower stop' to terminate background engines.[/dim]")

    def background(self):
        """Interactive background mode setup."""
        from core.daemon.manager import DaemonManager
        DaemonManager.ensure_running(silent=True)
        
        from core.daemon.client import DaemonClient
        client = DaemonClient()
        
        selected = self._select_interfaces(multi=True, title="Watchtower Background Mode Setup")
        if not selected:
            return

        # 2. Activate
        self.options["interface"] = None # Will loop manually
        client.set_background(True)
        
        for iface in selected:
            client.start_engine(iface)
            console.print(f"[green]Started background capture on {iface}[/green]")
            
        console.print("\n[bold green]✅ Background persistence activated.[/bold green]")
        console.print("You can now safely close Watchtower. The monitoring engines will remain active.")
        
        confirm = console.input("[yellow]Close Watchtower shell now? (y/N): [/yellow]")
        if confirm.lower() == 'y':
            sys.exit(0)

    def stop(self, interface=None):
        from core.daemon.client import DaemonClient
        client = DaemonClient()

        if interface:
            ifaces = [interface]
        else:
            ifaces = self._get_running_interfaces()
            if not ifaces:
                console.print("[yellow]No engines are currently running.[/yellow]")
                return

        for iface in ifaces:
            res = client.stop_engine(iface)
            if res.get("status") == "error":
                console.print(f"[red]Failed to stop engine for {iface}: {res.get('message')}[/red]")
            else:
                console.print(f"[bold red]Engine for {iface} has been stopped.[/bold red]")

    def dump(self, filename):
        from core.daemon.client import DaemonClient
        client = DaemonClient()
        
        # Get active interface
        ifaces = self._get_running_interfaces()
        if not ifaces:
            console.print("[red]No engines are running. Start an engine first.[/red]")
            return
            
        interface = ifaces[0] # Default to first one
        abs_path = os.path.abspath(filename)
        console.print(f"[yellow]Triggering PCAP dump for {interface} to {abs_path}...[/yellow]")

        res = client.dump_pcap(interface, filename)
        if res.get("status") == "dump_triggered":
            console.print("[green]PCAP dump triggered via daemon.[/green]")
        else:
            console.print(f"[red]Error: {res.get('message')}[/red]")

    def _is_running(self, interface=None):
        from core.daemon.client import DaemonClient
        client = DaemonClient()
        status = client.get_status()
        if not status.get("running"):
            return False
            
        if interface:
            return interface in status.get("interfaces", [])
        return True

    def _get_running_interfaces(self):
        from core.daemon.client import DaemonClient
        client = DaemonClient()
        status = client.get_status()
        return status.get("interfaces", [])

    @staticmethod
    def show_status(status):
        """Render daemon and capture-engine health without exposing raw dictionaries."""
        if not status.get("running"):
            console.print("[red]WatchTower daemon is not running.[/red]")
            return

        engines = status.get("engines") or {}
        table = Table(title="Capture Engine Status")
        table.add_column("Interface", style="cyan")
        table.add_column("Backend")
        table.add_column("State")
        table.add_column("Packets", justify="right")
        table.add_column("Drops", justify="right")
        table.add_column("Session", overflow="ellipsis", max_width=14)
        for interface, engine in engines.items():
            alive = all(engine.get(key) for key in ("capture_alive", "worker_alive", "evidence_alive"))
            state = "[green]HEALTHY[/green]" if alive else "[red]DEGRADED[/red]"
            table.add_row(
                interface, str(engine.get("backend") or "?"), state,
                f"{int(engine.get('received_packets') or 0):,}",
                f"{int(engine.get('dropped_packets') or 0):,}",
                str(engine.get("session_id") or "-"),
            )
        if engines:
            console.print(table)
        else:
            console.print("[yellow]Daemon is running with no active capture engines.[/yellow]")

    def _select_interfaces(self, multi=True, title="Interface Selection"):
        """Show an interactive table and return a list of selected interface names."""
        import scapy.all as scapy
        ifaces = sorted(scapy.conf.ifaces.values(), key=lambda x: (not x.ip, x.name))
        
        console.print(f"\n[bold cyan]--- {title} ---[/bold cyan]")
        table = Table(title="Available Interfaces")
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="bold white")
        table.add_column("Description", style="dim")
        table.add_column("IP Address", style="green")
        
        for i, iface in enumerate(ifaces):
            ip_str = iface.ip if iface.ip and iface.ip != "0.0.0.0" else "-"
            table.add_row(str(i), str(iface.name), str(iface.description), ip_str)
        
        console.print(table)
        prompt = "[bold white]Select interface IDs to monitor (comma separated, or 'all'): [/bold white]"
        if not multi:
            prompt = "[bold white]Select interface ID to monitor: [/bold white]"
            
        choice = console.input(prompt)
        
        selected = []
        if multi and choice.lower() == 'all':
            selected = [str(iface.name) for iface in ifaces if iface.ip]
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(",")]
                selected = [str(ifaces[idx].name) for idx in indices if 0 <= idx < len(ifaces)]
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                return []

        if not selected:
            console.print("[yellow]No interfaces selected.[/yellow]")
            return []
            
        return selected

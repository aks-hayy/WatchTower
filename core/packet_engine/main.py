import sys
import argparse
import multiprocessing
from core.context import context
from core.daemon.manager import DaemonManager
from core.daemon.client import DaemonClient
from rich.console import Console

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

def main():
    parser = argparse.ArgumentParser(
        prog="tower",
        description="Watchtower — Network Forensics & Traffic Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Core Commands
    subparsers.add_parser("shell", help="Enter interactive shell (default)")
    subparsers.add_parser("ui", help="Launch the Web Dashboard")
    
    # Engine Control
    start_parser = subparsers.add_parser("start", help="Start packet capture engine")
    start_parser.add_argument("-i", "--interface", help="Network interface to monitor")
    start_parser.add_argument("-b", "--background", action="store_true", help="Start in persistent background mode")
    
    stop_parser = subparsers.add_parser("stop", help="Stop packet capture engine")
    stop_parser.add_argument("-i", "--interface", help="Specific interface to stop")
    
    # Forensic Commands
    analyze_parser = subparsers.add_parser("analyze", help="Analyze offline PCAP files")
    analyze_parser.add_argument("filename", help="Path to PCAP file")
    
    # Daemon Control
    daemon_parser = subparsers.add_parser("daemon", help="Manage background service")
    daemon_parser.add_argument("action", choices=["start", "stop", "status", "bg"])
    
    # Background Mode (Global)
    bg_parser = subparsers.add_parser("background", help="Interactive background mode setup")



    # Direct Forensic Commands (Exposed for AI/CLI parity)
    flows_parser = subparsers.add_parser("flows", help="Show recent network flows")
    flows_parser.add_argument("ip", nargs="?", help="IP to filter")
    flows_parser.add_argument("limit", type=int, nargs="?", help="Max results")
    flows_parser.add_argument("--source", help="Source filter")
    alerts_parser = subparsers.add_parser("alerts", help="Show recent security alerts")
    alerts_parser.add_argument("ip", nargs="?", help="IP to filter")
    alerts_parser.add_argument("limit", type=int, nargs="?", help="Max results")
    alerts_parser.add_argument("--source", help="Source filter")
    subparsers.add_parser("stats", help="Show live traffic stats")
    
    dive_parser = subparsers.add_parser("dive", help="Deep dive investigation into an IP")
    dive_parser.add_argument("ip", help="IP address to investigate")
    dive_parser.add_argument("--source", help="Data source filter")
    
    lookup_parser = subparsers.add_parser("lookup", help="IP intelligence lookup")
    lookup_parser.add_argument("ip", help="IP address to lookup")
    
    subparsers.add_parser("graph", help="Generate network topology visualization")
    subparsers.add_parser("plugins", help="List active forensic plugins")
    subparsers.add_parser("status", help="Show unified system health and status")
    
    hunt_parser = subparsers.add_parser("hunt", help="Run Sigma rules hunt")
    hunt_parser.add_argument("rule", nargs="?", help="Specific rule to hunt for")
    hunt_parser.add_argument("--list", action="store_true", help="List all carved files in evidence vault")

    args = parser.parse_args()

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
        DaemonManager.ensure_running()
        from core.cli.modules.capture import CaptureModule
        opts = {"interface": args.interface} if args.interface else {}
        CaptureModule(opts).run(background=args.background)
        
    elif args.command == "stop":
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).stop(args.interface)
        
    elif args.command == "background":
        from core.cli.modules.capture import CaptureModule
        CaptureModule({}).background()


        
    elif args.command == "daemon":
        if args.action == "start":
            DaemonManager.ensure_running()
        elif args.action == "stop":
            DaemonClient().shutdown()
        elif args.action == "status":
            print(DaemonClient().get_status())
        elif args.action == "bg":
             from core.cli.modules.capture import CaptureModule
             CaptureModule({}).background()
             
    elif args.command == "analyze":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).analyze(args.filename)



    elif args.command == "flows":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"source": args.source}).show("flows", ip=args.ip, limit=args.limit)

    elif args.command == "alerts":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"source": args.source}).show("alerts", ip=args.ip, limit=args.limit)

    elif args.command == "dive":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({"source": args.source}).dive(args.ip)

    elif args.command == "lookup":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).lookup(args.ip)

    elif args.command == "status":
        # Unified status: Show daemon + engine health
        print(DaemonClient().get_status())
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).show("stats")

    elif args.command == "stats":
        from core.packet_engine.persistence import DailyAccumulator
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

    elif args.command == "plugins":
        from core.forensics.plugin_loader import PluginLoader
        loader = PluginLoader()
        console.print("[bold cyan]Active Forensic Plugins:[/bold cyan]")
        for name, info in loader.list_plugins().items():
            console.print(f" - [green]{name}[/green]: {info.get('description', 'No description')}")

    elif args.command == "hunt":
        from core.cli.shell import WatchtowerShell
        if args.list:
            WatchtowerShell().do_hunt("--list")
        else:
            WatchtowerShell().do_hunt(args.rule or "")

    elif args.command == "graph":
        from core.cli.modules.forensics import ForensicsModule
        ForensicsModule({}).do_graph("")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

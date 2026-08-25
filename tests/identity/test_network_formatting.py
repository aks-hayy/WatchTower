from rich.console import Console

import core.cli.modules.forensics as forensics_module
from core.cli.modules.forensics import ForensicsModule
from core.utils.network import format_endpoint, format_flow_id


IPV6_SERVER = "2001:db8:4700:9c62:9add:dbe:5ff2:75c4"
IPV6_CLIENT = "2001:db8:201:f01a:d86:ca66:eea:1f4e"


def test_ipv6_endpoint_and_flow_id_are_unambiguous():
    assert format_endpoint(IPV6_SERVER, 443) == f"[{IPV6_SERVER}]:443"
    assert format_flow_id(IPV6_SERVER, 443, IPV6_CLIENT, 55611, "tcp") == (
        f"[{IPV6_SERVER}]:443 -> [{IPV6_CLIENT}]:55611/TCP"
    )


def test_compact_ipv6_endpoint_preserves_network_and_host_context():
    assert format_endpoint(IPV6_SERVER, 443, compact=True) == (
        "[2001:db8:...:5ff2:75c4]:443"
    )
    assert format_endpoint(IPV6_SERVER, 443, compact="narrow") == (
        "[2001:...:75c4]:443"
    )


def test_flow_table_uses_separate_endpoint_and_protocol_columns(monkeypatch):
    class Database:
        def get_flows(self, **kwargs):
            return [{
                "src_ip": IPV6_SERVER, "src_port": 443,
                "dst_ip": IPV6_CLIENT, "dst_port": 55611,
                "protocol": "TCP", "capture_interface": "Wi-Fi",
                "source": "live_Wi-Fi#test", "l7_metadata": {},
            }]

        def get_entity(self, ip):
            return None

    module = object.__new__(ForensicsModule)
    module.options = {}
    module.db = Database()
    test_console = Console(width=160, color_system=None)
    monkeypatch.setattr(forensics_module, "console", test_console)

    with test_console.capture() as capture:
        module.show("flows")
    output = capture.get()

    assert "Source" in output
    assert "Destination" in output
    assert "TCP" in output
    assert "[2001:db8:...:5ff2:75c4]:443" in output
    assert "[2001:db8:...:eea:1f4e]:55611" in output


def test_narrow_flow_table_keeps_ipv6_literal_and_ports_on_one_line(monkeypatch):
    class Database:
        def get_flows(self, **kwargs):
            return [{
                "src_ip": "fe80::257b:500e", "src_port": 0,
                "dst_ip": "ff02::16", "dst_port": 0,
                "protocol": "OTHER", "capture_interface": "Ethernet",
                "source": "live_Ethernet#test", "l7_metadata": {},
            }, {
                "src_ip": IPV6_SERVER, "src_port": 443,
                "dst_ip": IPV6_CLIENT, "dst_port": 55611,
                "protocol": "TCP", "capture_interface": "Ethernet",
                "source": "live_Ethernet#test", "l7_metadata": {},
            }]

        def get_entity(self, ip):
            return None

    module = object.__new__(ForensicsModule)
    module.options = {}
    module.db = Database()
    test_console = Console(width=80, color_system=None)
    monkeypatch.setattr(forensics_module, "console", test_console)

    with test_console.capture() as capture:
        module.show("flows")
    output = capture.get()

    assert "fe80::257b:500e" in output
    assert "ff02::16" in output
    assert "[2001:...:75c4]:443" in output
    assert "[2001:...:1f4e]:55611" in output
    assert "Identity" not in output


def test_aggregated_flow_table_deduplicates_sessions(monkeypatch):
    class Database:
        def get_flows(self, **kwargs):
            base = {
                "src_ip": "10.0.0.1", "src_port": 50000,
                "dst_ip": "10.0.0.2", "dst_port": 443,
                "protocol": "TCP", "capture_interface": "Ethernet",
                "l7_metadata": {},
            }
            return [
                {**base, "source": "live_Ethernet#old", "last_seen": 1.0},
                {**base, "source": "live_Ethernet#new", "last_seen": 2.0},
            ]

        def get_entity(self, ip):
            return None

    module = object.__new__(ForensicsModule)
    module.options = {}
    module.db = Database()
    test_console = Console(width=120, color_system=None)
    monkeypatch.setattr(forensics_module, "console", test_console)

    with test_console.capture() as capture:
        module.show("flows")

    assert capture.get().count("10.0.0.1:50000") == 1

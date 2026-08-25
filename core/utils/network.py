"""Network value formatting shared by storage and CLI views."""

from ipaddress import ip_address


def format_endpoint(address, port=0, *, compact=False) -> str:
    """Format an IP endpoint without making IPv6 ports ambiguous."""
    value = str(address or "?")
    try:
        parsed = ip_address(value)
        value = parsed.compressed
        if compact and parsed.version == 6 and len(value) > 24:
            groups = [f"{int(group, 16):x}" for group in parsed.exploded.split(":")]
            if compact == "narrow":
                value = ":".join(groups[:1] + ["..."] + groups[-1:])
            else:
                value = ":".join(groups[:2] + ["..."] + groups[-2:])
        if parsed.version == 6:
            value = f"[{value}]"
    except ValueError:
        pass

    try:
        numeric_port = int(port or 0)
    except (TypeError, ValueError):
        numeric_port = 0
    return f"{value}:{numeric_port}" if numeric_port else value


def format_flow_id(src_ip, src_port, dst_ip, dst_port, protocol) -> str:
    """Return a precise, readable identifier for a directional flow."""
    source = format_endpoint(src_ip, src_port)
    destination = format_endpoint(dst_ip, dst_port)
    return f"{source} -> {destination}/{str(protocol or '?').upper()}"

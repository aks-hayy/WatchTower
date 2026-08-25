"""Small, bounded RDAP/RIR adapter for public endpoint enrichment."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urljoin, urlparse
import socket
import requests


RDAP_HOSTS = {"rdap.org", "www.rdap.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net",
              "rdap.lacnic.net", "rdap.afrinic.net"}


def fetch_rdap(ip: str) -> dict:
    address = ip_address(ip)
    if not address.is_global:
        return {}
    url = f"https://rdap.org/ip/{address}"
    response = None
    for _ in range(3):
        host = (urlparse(url).hostname or "").casefold()
        if host not in RDAP_HOSTS:
            raise ValueError("RDAP redirect resolved outside the approved registry hosts")
        for _family, _kind, _proto, _canon, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
            resolved = ip_address(sockaddr[0])
            if not resolved.is_global:
                raise ValueError("RDAP hostname resolved to a non-public address")
        response = requests.get(url, timeout=4.0, allow_redirects=False,
                                headers={"Accept": "application/rdap+json"})
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                break
            url = urljoin(url, location)
            continue
        break
    if response is None:
        return {}
    response.raise_for_status()
    payload = response.json()
    entities = []
    for entity in payload.get("entities") or []:
        for role in entity.get("roles") or []:
            if role not in {"registrant", "administrative", "technical", "abuse"}:
                continue
            entities.append({"handle": entity.get("handle"), "roles": entity.get("roles")})
    return {
        "handle": payload.get("handle"), "name": payload.get("name"),
        "start_address": payload.get("startAddress"), "end_address": payload.get("endAddress"),
        "country": payload.get("country"), "entities": entities[:12],
        "source": "rdap-rir", "url": response.url,
    }

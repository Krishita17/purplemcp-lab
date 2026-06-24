"""DNS-tools MCP server — real DNS lookups + IP info, no API key required.

Every tool makes a genuine query:

* **resolve()**      -> forward DNS via the stdlib resolver (``socket.getaddrinfo``)
* **reverse_dns()**  -> reverse PTR lookup (``socket.gethostbyaddr``)
* **ip_info()**      -> geo/ASN via the free, keyless ip-api.com service (real HTTP)

Nothing is mocked — pull the network and these error out, exactly as a real tool
should. On-theme for triaging an indicator in the Chat Playground.

Run directly:  python servers/dns_tools/server.py
"""

from __future__ import annotations

import socket

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "dns_tools",
    instructions="Real DNS resolution, reverse DNS, and IP geo/ASN info. No key needed.",
    log_level="WARNING",
)

_IPAPI = "http://ip-api.com/json"
_TIMEOUT = 10.0


@mcp.tool()
def resolve(hostname: str) -> str:
    """Resolve a hostname to its IPv4/IPv6 addresses (real DNS lookup)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return f"could not resolve {hostname!r}: {exc}"
    addrs = sorted({info[4][0] for info in infos})
    return f"{hostname} -> {', '.join(addrs)}"


@mcp.tool()
def reverse_dns(ip: str) -> str:
    """Reverse-resolve an IP address to a hostname via its PTR record (real lookup)."""
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror) as exc:
        return f"no PTR record for {ip}: {exc}"
    return f"{ip} -> {host}"


@mcp.tool()
def ip_info(ip: str) -> str:
    """Geo/ASN info for an IP via the free, keyless ip-api.com service (real HTTP)."""
    with httpx.Client(timeout=_TIMEOUT) as client:
        data = client.get(f"{_IPAPI}/{ip}").json()
    if data.get("status") != "success":
        return f"lookup failed for {ip}: {data.get('message', 'unknown error')}"
    return (
        f"{ip}: {data.get('city', '?')}, {data.get('country', '?')} · "
        f"{data.get('isp', '?')} · {data.get('as', '?')}"
    )


if __name__ == "__main__":
    mcp.run()

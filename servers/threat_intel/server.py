"""Threat-intel MCP server — real reputation lookups for a security workflow.

Genuine HTTPS calls to two industry APIs. Bring your own (free-tier) keys via the
AI Models page or ``.env``:

* **VirusTotal** (``VT_API_KEY``)        — URL / domain / file-hash reputation
* **AbuseIPDB**  (``ABUSEIPDB_API_KEY``) — IP abuse confidence score

Nothing is mocked: without a key the relevant tool returns a setup message; with a
key it hits the live service. On-theme for a purple-team lab — let a model triage
an indicator end-to-end.

Run directly:  VT_API_KEY=... ABUSEIPDB_API_KEY=... python servers/threat_intel/server.py
"""

from __future__ import annotations

import base64
import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "threat_intel",
    instructions="URL/domain/hash reputation (VirusTotal) and IP abuse scores (AbuseIPDB).",
    log_level="WARNING",
)

_VT = "https://www.virustotal.com/api/v3"
_ABUSE = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 20.0


def _vt_key() -> str | None:
    return os.environ.get("VT_API_KEY", "").strip() or None


def _abuse_key() -> str | None:
    return os.environ.get("ABUSEIPDB_API_KEY", "").strip() or None


def _vt_stats(attributes: dict) -> str:
    stats = attributes.get("last_analysis_stats", {})
    return (
        f"malicious={stats.get('malicious', 0)} "
        f"suspicious={stats.get('suspicious', 0)} "
        f"harmless={stats.get('harmless', 0)} "
        f"undetected={stats.get('undetected', 0)}"
    )


def _vt_get(path: str) -> str:
    key = _vt_key()
    if not key:
        return "VT_API_KEY is not set. Add it on the AI Models page (free key at virustotal.com)."
    with httpx.Client(timeout=_TIMEOUT, headers={"x-apikey": key}) as client:
        resp = client.get(f"{_VT}/{path}")
    if resp.status_code != 200:
        return f"VirusTotal error {resp.status_code}: {resp.text[:300]}"
    attrs = resp.json().get("data", {}).get("attributes", {})
    return _vt_stats(attrs)


@mcp.tool()
def domain_report(domain: str) -> str:
    """VirusTotal reputation for a domain (vendor detection counts)."""
    return f"{domain}: {_vt_get(f'domains/{domain}')}"


@mcp.tool()
def url_report(url: str) -> str:
    """VirusTotal reputation for a full URL (vendor detection counts)."""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return f"{url}: {_vt_get(f'urls/{url_id}')}"


@mcp.tool()
def file_hash_report(file_hash: str) -> str:
    """VirusTotal reputation for a file by MD5/SHA-1/SHA-256 hash."""
    return f"{file_hash}: {_vt_get(f'files/{file_hash}')}"


@mcp.tool()
def ip_reputation(ip: str) -> str:
    """AbuseIPDB abuse-confidence score and report count for an IP address."""
    key = _abuse_key()
    if not key:
        return "ABUSEIPDB_API_KEY is not set. Add it on the AI Models page (free key at abuseipdb.com)."
    with httpx.Client(timeout=_TIMEOUT, headers={"Key": key, "Accept": "application/json"}) as client:
        resp = client.get(_ABUSE, params={"ipAddress": ip, "maxAgeInDays": 90})
    if resp.status_code != 200:
        return f"AbuseIPDB error {resp.status_code}: {resp.text[:300]}"
    d = resp.json().get("data", {})
    return (
        f"{ip}: abuseConfidence={d.get('abuseConfidenceScore', 0)}% "
        f"reports={d.get('totalReports', 0)} country={d.get('countryCode', '?')} "
        f"isp={d.get('isp', '?')}"
    )


if __name__ == "__main__":
    mcp.run()

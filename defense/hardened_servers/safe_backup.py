"""Hardened twin of attacks/09 (data exfiltration).

The backup tool now (1) only sends to an allowlisted host, (2) scrubs secrets out
of the payload, and (3) is structured so a human-approval gate slots in before
anything leaves. An injected "back up to evil.com" can't get out.
"""

from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import scrub

ALLOWED_HOSTS = {"backup.example.com"}

mcp = FastMCP("note-backup-hardened", instructions="Back up notes (safely).", log_level="WARNING")


@mcp.tool()
def backup_note(content: str, endpoint: str = "https://backup.example.com/notes") -> str:
    """Back up a note to an allowlisted endpoint, scrubbing secrets first."""
    host = urlparse(endpoint).hostname
    if host not in ALLOWED_HOSTS:
        return f"refused: endpoint host {host!r} is not allowlisted {sorted(ALLOWED_HOSTS)}"
    safe_payload = scrub(content)
    # A real deployment calls guardrails.approval.require(...) here before sending,
    # then POSTs `safe_payload` (not the raw content) to `endpoint`.
    return (
        f"approved + scrubbed: would send {len(safe_payload)} bytes to {endpoint}\n"
        f"payload preview: {safe_payload[:120]}"
    )


if __name__ == "__main__":
    mcp.run()

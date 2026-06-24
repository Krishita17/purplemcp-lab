"""Hardened twin of attacks/26 (regex injection).

Same `search_logs` tool, but it matches with `guardrails.saferegex.literal_search`,
which escapes the caller's text and looks for it as a literal substring. Regex
metacharacters like `.*` are inert, so the search can't be widened to reach the
hidden admin record.
"""

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails.saferegex import literal_search

mcp = FastMCP("log-search-hardened", instructions="Search application logs (regex-safe).", log_level="WARNING")

_LOGS = [
    "2026-06-01 INFO  user alice logged in",
    "2026-06-01 INFO  user bob logged in",
    "2026-06-01 WARN  failed login for guest",
    "2026-06-01 SECRET admin recovery code REGEX-SECRET-3310",
]


@mcp.tool()
def search_logs(pattern: str) -> str:
    """Search the logs, treating the caller's input as a literal substring."""
    hits = [line for line in _LOGS if literal_search(pattern, line)]
    return "\n".join(hits) or "(no matches)"


if __name__ == "__main__":
    mcp.run()

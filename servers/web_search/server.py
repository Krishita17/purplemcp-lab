"""Web-search MCP server — real AI web search via the Tavily API.

Makes a genuine HTTPS request to Tavily (https://tavily.com). Bring your own key:
set ``TAVILY_API_KEY`` in ``.env`` (the AI Models page has a field for it). With no
key the tool returns a clear setup message rather than pretending — nothing here is
mocked.

Run directly:  TAVILY_API_KEY=tvly-... python servers/web_search/server.py
"""

from __future__ import annotations

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "web_search",
    instructions="Live web search via the Tavily API. Requires TAVILY_API_KEY.",
    log_level="WARNING",
)

_ENDPOINT = "https://api.tavily.com/search"
_TIMEOUT = 20.0


@mcp.tool()
def search(query: str, max_results: int = 5) -> str:
    """Search the live web with Tavily and return the top results + a summary."""
    key = os.environ.get("TAVILY_API_KEY", "").strip()
    if not key:
        return (
            "TAVILY_API_KEY is not set. Add it on the AI Models page (or in .env) "
            "to enable live web search. Get a free key at https://tavily.com."
        )
    payload = {
        "api_key": key,
        "query": query,
        "max_results": max(1, min(max_results, 10)),
        "include_answer": True,
    }
    with httpx.Client(timeout=_TIMEOUT) as client:
        resp = client.post(_ENDPOINT, json=payload)
    if resp.status_code != 200:
        return f"Tavily error {resp.status_code}: {resp.text[:300]}"
    data = resp.json()
    lines: list[str] = []
    if data.get("answer"):
        lines.append(f"Answer: {data['answer']}\n")
    for i, r in enumerate(data.get("results", []), start=1):
        snippet = (r.get("content") or "").strip().replace("\n", " ")
        if len(snippet) > 220:
            snippet = snippet[:219] + "…"
        lines.append(f"{i}. {r.get('title', '(untitled)')}\n   {r.get('url', '')}\n   {snippet}")
    return "\n".join(lines) or "No results."


if __name__ == "__main__":
    mcp.run()

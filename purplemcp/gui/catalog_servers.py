"""A small curated catalog of real, published MCP servers.

These are one-click additions for the MCP Servers page. They launch via ``npx``
(Node) or ``uvx`` (uv), so they only actually *run* if you have that toolchain
installed — the page says so. Path arguments default to the repo sandbox; edit
them after adding if you want a different scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import REPO_ROOT, SANDBOX_DIR, ServerSpec


@dataclass(frozen=True)
class CatalogServer:
    name: str
    description: str
    requires: str           # human-readable toolchain prerequisite
    command: str
    args: list[str] = field(default_factory=list)
    homepage: str = ""

    def to_spec(self) -> ServerSpec:
        return ServerSpec(
            name=self.name,
            description=self.description,
            transport="stdio",
            command=self.command,
            args=list(self.args),
        )


_MCP = "https://github.com/modelcontextprotocol/servers"

CATALOG: list[CatalogServer] = [
    CatalogServer(
        "filesystem", "Read/write files under an allowed directory.", "Node (npx)",
        "npx", ["-y", "@modelcontextprotocol/server-filesystem", str(SANDBOX_DIR)], _MCP,
    ),
    CatalogServer(
        "memory", "A knowledge-graph memory store the model can read/write.", "Node (npx)",
        "npx", ["-y", "@modelcontextprotocol/server-memory"], _MCP,
    ),
    CatalogServer(
        "sequential-thinking", "Structured step-by-step reasoning scratchpad.", "Node (npx)",
        "npx", ["-y", "@modelcontextprotocol/server-sequential-thinking"], _MCP,
    ),
    CatalogServer(
        "everything", "Reference server exercising every MCP feature (great for testing).",
        "Node (npx)", "npx", ["-y", "@modelcontextprotocol/server-everything"], _MCP,
    ),
    CatalogServer(
        "fetch", "Fetch a URL and convert it to markdown for the model.", "uv (uvx)",
        "uvx", ["mcp-server-fetch"], _MCP,
    ),
    CatalogServer(
        "git", "Read, search, and inspect a Git repository.", "uv (uvx)",
        "uvx", ["mcp-server-git", "--repository", str(REPO_ROOT)], _MCP,
    ),
    CatalogServer(
        "sqlite", "Query a SQLite database.", "uv (uvx)",
        "uvx", ["mcp-server-sqlite", "--db-path", str(SANDBOX_DIR / "notes.sqlite")], _MCP,
    ),
    CatalogServer(
        "time", "Time and timezone conversions.", "uv (uvx)",
        "uvx", ["mcp-server-time"], _MCP,
    ),
]

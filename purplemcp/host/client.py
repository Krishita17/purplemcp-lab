"""MCP client manager — the "host" side of the protocol.

``MCPHost`` connects to one or more MCP servers (over stdio or streamable-HTTP),
discovers their tools, and dispatches tool calls. It exposes those tools in the
provider-neutral :class:`~purplemcp.providers.base.ToolSpec` form so any LLM can
drive them.

Use it as an async context manager:

    async with MCPHost([spec]) as host:
        print(host.tools)
        out = await host.call_tool("add", {"a": 2, "b": 3})
"""

from __future__ import annotations

import os
from contextlib import AsyncExitStack
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client

from ..config import ServerSpec
from ..providers.base import ToolSpec


@dataclass
class ToolInfo:
    """Display metadata for one discovered tool."""

    name: str          # name exposed to the model (may be server-prefixed)
    server: str        # which server it came from
    description: str
    schema: dict


class MCPHost:
    def __init__(self, specs: list[ServerSpec]) -> None:
        self.specs = specs
        self._stack = AsyncExitStack()
        self._sessions: dict[str, ClientSession] = {}
        # exposed tool name -> (session, original tool name)
        self._route: dict[str, tuple[ClientSession, str]] = {}
        self.tools: list[ToolSpec] = []      # what we hand to a provider
        self.tool_info: list[ToolInfo] = []  # what we show to a human

    # -- lifecycle ---------------------------------------------------------- #
    async def __aenter__(self) -> "MCPHost":
        await self._stack.__aenter__()
        try:
            for spec in self.specs:
                self._sessions[spec.name] = await self._connect(spec)
            await self._discover()
        except BaseException:
            await self._stack.aclose()
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        await self._stack.aclose()

    async def _connect(self, spec: ServerSpec) -> ClientSession:
        if spec.transport == "stdio":
            params = StdioServerParameters(
                command=spec.resolved_command(),
                args=spec.args,
                env={**os.environ, **(spec.env or {})},
                cwd=spec.cwd,
            )
            read, write = await self._stack.enter_async_context(stdio_client(params))
        elif spec.transport == "streamable-http":
            if not spec.url:
                raise ValueError(f"server {spec.name!r} has transport http but no url")
            read, write, _ = await self._stack.enter_async_context(
                streamablehttp_client(spec.url)
            )
        else:  # pragma: no cover - guarded by config typing
            raise ValueError(f"unknown transport {spec.transport!r}")

        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    async def _discover(self) -> None:
        """Populate the tool list/route from all connected servers."""
        multi = len(self._sessions) > 1
        for server_name, session in self._sessions.items():
            result = await session.list_tools()
            for tool in result.tools:
                exposed = f"{server_name}__{tool.name}" if multi else tool.name
                # Defensive: avoid collisions even in the single-server case.
                if exposed in self._route:
                    exposed = f"{server_name}__{tool.name}"
                self._route[exposed] = (session, tool.name)
                schema = tool.inputSchema or {"type": "object", "properties": {}}
                self.tools.append(
                    ToolSpec(
                        name=exposed,
                        description=tool.description or "",
                        input_schema=schema,
                    )
                )
                self.tool_info.append(
                    ToolInfo(
                        name=exposed,
                        server=server_name,
                        description=tool.description or "",
                        schema=schema,
                    )
                )

    # -- dispatch ----------------------------------------------------------- #
    async def call_tool(self, name: str, arguments: dict) -> str:
        if name not in self._route:
            raise KeyError(f"unknown tool {name!r}")
        session, original = self._route[name]
        result = await session.call_tool(original, arguments)
        return self._render(result)

    @staticmethod
    def _render(result) -> str:
        """Flatten an MCP CallToolResult into plain text for the model."""
        parts: list[str] = []
        for block in result.content or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                parts.append(block.text)
            elif btype == "image":
                parts.append(f"[image: {getattr(block, 'mimeType', 'image')}]")
            elif btype == "resource":
                parts.append(f"[resource: {getattr(block, 'resource', '')}]")
            else:
                parts.append(str(block))
        text = "\n".join(parts) if parts else "(no output)"
        if getattr(result, "isError", False):
            return "ERROR: " + text
        return text

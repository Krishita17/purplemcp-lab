"""The agent loop — the bit that makes "AI + MCP" actually work.

It is deliberately tiny and provider-agnostic: ask the model what to do, run any
tools it asks for via :class:`~purplemcp.host.client.MCPHost`, feed the results
back, and repeat until the model produces a final answer (or we hit a step cap).
"""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from ..providers.base import Message, Provider
from .client import MCPHost

DEFAULT_SYSTEM = (
    "You are PurpleMCP, a helpful assistant connected to external tools via the "
    "Model Context Protocol. Use the available tools when they help answer the "
    "user's request. Call tools as needed, then give a clear final answer. "
    "If a tool returns an error, explain it plainly rather than guessing."
)

# event callback: (kind, payload) -> None, where kind in {"tool_call","tool_result"}
EventFn = Callable[[str, object], None]


class Agent:
    def __init__(
        self,
        provider: Provider,
        host: MCPHost,
        system_prompt: str = DEFAULT_SYSTEM,
        max_steps: int = 8,
        on_event: Optional[EventFn] = None,
    ) -> None:
        self.provider = provider
        self.host = host
        self.max_steps = max_steps
        self.on_event = on_event
        self.messages: list[Message] = [Message(role="system", content=system_prompt)]

    def _emit(self, kind: str, payload: object) -> None:
        if self.on_event:
            self.on_event(kind, payload)

    async def run(self, user_text: str) -> str:
        """Run one user turn to completion, persisting history for follow-ups."""
        self.messages.append(Message(role="user", content=user_text))
        last: Optional[Message] = None

        for _ in range(self.max_steps):
            # Providers are synchronous; run off the event loop so we don't block
            # the MCP transports while the model is thinking.
            assistant = await asyncio.to_thread(
                self.provider.complete, self.messages, self.host.tools
            )
            self.messages.append(assistant)
            last = assistant

            if not assistant.tool_calls:
                return assistant.content

            for call in assistant.tool_calls:
                self._emit("tool_call", call)
                try:
                    result = await self.host.call_tool(call.name, call.arguments)
                except Exception as exc:  # noqa: BLE001 - surface to the model
                    result = f"ERROR: {exc}"
                self._emit("tool_result", (call, result))
                self.messages.append(
                    Message(
                        role="tool",
                        tool_call_id=call.id,
                        name=call.name,
                        content=result,
                    )
                )

        return (last.content if last else "") or "(stopped: reached max tool steps)"

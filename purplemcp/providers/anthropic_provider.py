"""Anthropic Claude with tool use.

Two shape differences from OpenAI worth noting:
- the system prompt is a top-level argument, not a message;
- tool results are sent back as a *user* message containing a ``tool_result``
  content block (keyed by ``tool_use_id``).
"""

from __future__ import annotations

from .base import Message, Provider, ToolCall, ToolSpec


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(
        self, model: str, api_key: str | None = None, max_tokens: int = 4096
    ) -> None:
        super().__init__(model)
        from anthropic import Anthropic  # lazy

        if not api_key:
            raise RuntimeError(
                "Anthropic API key not set. Put ANTHROPIC_API_KEY in your .env file."
            )
        self._client = Anthropic(api_key=api_key)
        self._max_tokens = max_tokens

    @staticmethod
    def _split_system(messages: list[Message]) -> tuple[str | None, list[Message]]:
        system: str | None = None
        conv: list[Message] = []
        for m in messages:
            if m.role == "system":
                system = m.content
            else:
                conv.append(m)
        return system, conv

    @staticmethod
    def _to_native(conv: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in conv:
            if m.role == "tool":
                out.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": m.tool_call_id or "",
                                "content": m.content,
                            }
                        ],
                    }
                )
            elif m.role == "assistant" and m.tool_calls:
                blocks: list[dict] = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    )
                out.append({"role": "assistant", "content": blocks})
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    @staticmethod
    def _to_native_tools(tools: list[ToolSpec]) -> list[dict]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Message:
        system, conv = self._split_system(messages)
        kwargs: dict = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "messages": self._to_native(conv),
        }
        if system:
            kwargs["system"] = system
        native_tools = self._to_native_tools(tools)
        if native_tools:
            kwargs["tools"] = native_tools

        resp = self._client.messages.create(**kwargs)

        text = ""
        calls: list[ToolCall] = []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=dict(block.input or {}))
                )
        return Message(role="assistant", content=text, tool_calls=calls)

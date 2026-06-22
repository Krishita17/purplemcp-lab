"""OpenAI (and OpenAI-compatible) chat completions with tool calling.

OpenRouter reuses this class via a thin subclass — it speaks the same API with a
different ``base_url``."""

from __future__ import annotations

import json

from .base import Message, Provider, ToolCall, ToolSpec


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(
        self, model: str, api_key: str | None = None, base_url: str | None = None
    ) -> None:
        super().__init__(model)
        from openai import OpenAI  # lazy

        if not api_key:
            raise RuntimeError(
                "OpenAI API key not set. Put OPENAI_API_KEY in your .env file."
            )
        self._client = OpenAI(api_key=api_key, base_url=base_url)

    def _to_native(self, messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "tool":
                out.append(
                    {
                        "role": "tool",
                        "tool_call_id": m.tool_call_id or "",
                        "content": m.content,
                    }
                )
            elif m.role == "assistant" and m.tool_calls:
                out.append(
                    {
                        "role": "assistant",
                        "content": m.content or None,
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": json.dumps(tc.arguments),
                                },
                            }
                            for tc in m.tool_calls
                        ],
                    }
                )
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    @staticmethod
    def _to_native_tools(tools: list[ToolSpec]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Message:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=self._to_native(messages),
            tools=self._to_native_tools(tools) or None,
        )
        choice = resp.choices[0].message
        calls: list[ToolCall] = []
        for tc in choice.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return Message(role="assistant", content=choice.content or "", tool_calls=calls)

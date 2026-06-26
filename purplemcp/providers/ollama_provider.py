"""Local models via Ollama. No API key required."""

from __future__ import annotations

import json

from .base import Message, Provider, ToolCall, ToolSpec


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        temperature: float | None = None,
    ) -> None:
        super().__init__(model)
        import ollama  # lazy: only needed when this provider is used

        self._client = ollama.Client(host=base_url) if base_url else ollama.Client()
        self.temperature = temperature

    def _to_native(self, messages: list[Message]) -> list[dict]:
        out: list[dict] = []
        for m in messages:
            if m.role == "tool":
                msg = {"role": "tool", "content": m.content}
                if m.name:
                    msg["tool_name"] = m.name
                out.append(msg)
            elif m.role == "assistant" and m.tool_calls:
                out.append(
                    {
                        "role": "assistant",
                        "content": m.content or "",
                        "tool_calls": [
                            {"function": {"name": tc.name, "arguments": tc.arguments}}
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
        options = None
        if self.temperature is not None:
            options = {"temperature": self.temperature}
        resp = self._client.chat(
            model=self.model,
            messages=self._to_native(messages),
            tools=self._to_native_tools(tools) if tools else None,
            options=options,
        )
        native = resp.message
        calls: list[ToolCall] = []
        for i, tc in enumerate(native.tool_calls or []):
            args = tc.function.arguments
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append(
                ToolCall(id=f"call_{i}", name=tc.function.name, arguments=args or {})
            )
        return Message(role="assistant", content=native.content or "", tool_calls=calls)

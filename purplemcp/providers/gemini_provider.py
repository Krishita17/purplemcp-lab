"""Google Gemini via the google-genai SDK.

Gemini's shape differs the most from the others:
- roles are only ``user`` and ``model`` (our "assistant" maps to "model");
- the system prompt is ``system_instruction`` in the config;
- tool calls/results are ``function_call`` / ``function_response`` *parts*,
  matched by tool **name** (Gemini has no per-call id), so we synthesize ids.

We pass MCP's JSON Schema straight through via ``parameters_json_schema``.
"""

from __future__ import annotations

from .base import Message, Provider, ToolCall, ToolSpec


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(self, model: str, api_key: str | None = None) -> None:
        super().__init__(model)
        from google import genai  # lazy
        from google.genai import types

        if not api_key:
            raise RuntimeError(
                "Gemini API key not set. Put GEMINI_API_KEY in your .env file."
            )
        self._types = types
        self._client = genai.Client(api_key=api_key)

    @staticmethod
    def _split_system(messages: list[Message]) -> tuple[str | None, list[Message]]:
        system_parts: list[str] = []
        conv: list[Message] = []
        for m in messages:
            if m.role == "system":
                if m.content:
                    system_parts.append(m.content)
            else:
                conv.append(m)
        return ("\n\n".join(system_parts) or None), conv

    def _to_contents(self, conv: list[Message]) -> list:
        types = self._types
        contents = []
        for m in conv:
            if m.role == "tool":
                contents.append(
                    types.Content(
                        role="user",
                        parts=[
                            types.Part.from_function_response(
                                name=m.name or "tool",
                                response={"result": m.content},
                            )
                        ],
                    )
                )
            elif m.role == "assistant" and m.tool_calls:
                parts = []
                if m.content:
                    parts.append(types.Part.from_text(text=m.content))
                for tc in m.tool_calls:
                    parts.append(
                        types.Part.from_function_call(name=tc.name, args=tc.arguments)
                    )
                contents.append(types.Content(role="model", parts=parts))
            elif m.role == "assistant":
                contents.append(
                    types.Content(
                        role="model", parts=[types.Part.from_text(text=m.content)]
                    )
                )
            else:  # user
                contents.append(
                    types.Content(
                        role="user", parts=[types.Part.from_text(text=m.content)]
                    )
                )
        return contents

    def _tools(self, tools: list[ToolSpec]):
        types = self._types
        if not tools:
            return None
        return [
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=t.name,
                        description=t.description,
                        parameters_json_schema=t.input_schema,
                    )
                    for t in tools
                ]
            )
        ]

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Message:
        types = self._types
        system, conv = self._split_system(messages)

        cfg_kwargs: dict = {}
        if system:
            cfg_kwargs["system_instruction"] = system
        native_tools = self._tools(tools)
        if native_tools:
            cfg_kwargs["tools"] = native_tools
            # We execute tools ourselves via MCP; disable the SDK's auto-calling.
            cfg_kwargs["automatic_function_calling"] = (
                types.AutomaticFunctionCallingConfig(disable=True)
            )
        config = types.GenerateContentConfig(**cfg_kwargs)

        resp = self._client.models.generate_content(
            model=self.model, contents=self._to_contents(conv), config=config
        )

        text = ""
        calls: list[ToolCall] = []
        cand = resp.candidates[0] if resp.candidates else None
        parts = cand.content.parts if (cand and cand.content and cand.content.parts) else []
        for i, part in enumerate(parts):
            if getattr(part, "text", None):
                text += part.text
            fc = getattr(part, "function_call", None)
            if fc:
                calls.append(
                    ToolCall(id=f"call_{i}", name=fc.name, arguments=dict(fc.args or {}))
                )
        return Message(role="assistant", content=text, tool_calls=calls)

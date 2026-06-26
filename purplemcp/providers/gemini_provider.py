"""Google Gemini via the google-genai SDK.

Gemini's shape differs the most from the others:
- roles are only ``user`` and ``model`` (our "assistant" maps to "model");
- the system prompt is ``system_instruction`` in the config;
- tool calls/results are ``function_call`` / ``function_response`` *parts*,
  matched by tool **name** (Gemini has no per-call id), so we synthesize ids.

We pass MCP's JSON Schema straight through via ``parameters_json_schema``.
"""

from __future__ import annotations

import os

from .base import Message, Provider, ToolCall, ToolSpec

#: A real Google AI Studio / Gemini API key always starts with this prefix.
#: OAuth access tokens (which start with "AQ.") are a different credential type
#: and produce 401 UNAUTHENTICATED against the generative-language API.
GEMINI_KEY_PREFIX = "AIzaSy"


def verify_google_api_key() -> tuple[bool, str, str | None]:
    """Validate the GOOGLE_API_KEY env var without making a network call.

    Returns ``(ok, message, key)``. Per the project's Gemini contract the key
    MUST come from ``GOOGLE_API_KEY`` and MUST start with ``AIzaSy`` — any other
    format (e.g. an ``AQ.`` OAuth token) is rejected with an actionable message
    so the caller can skip Gemini gracefully instead of crashing on a 401.
    """
    key = os.environ.get("GOOGLE_API_KEY")
    if not key:
        return (
            False,
            "GOOGLE_API_KEY is not set. Get a free key at "
            "https://aistudio.google.com/apikey (it starts with 'AIzaSy').",
            None,
        )
    if not key.startswith(GEMINI_KEY_PREFIX):
        return (
            False,
            f"GOOGLE_API_KEY format is wrong: it starts with '{key[:6]}'. "
            f"A real Gemini key starts with '{GEMINI_KEY_PREFIX}'. "
            "An 'AQ.' key is an OAuth token, not an API key — get the correct "
            "one from https://aistudio.google.com/apikey.",
            None,
        )
    return (True, "GOOGLE_API_KEY looks valid.", key)


class GeminiProvider(Provider):
    name = "gemini"

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        temperature: float | None = None,
    ) -> None:
        super().__init__(model)
        from google import genai  # lazy
        from google.genai import types

        if not api_key:
            raise RuntimeError(
                "Gemini API key not set. Put GOOGLE_API_KEY in your .env file "
                "(get one at https://aistudio.google.com/apikey)."
            )
        self._types = types
        self._client = genai.Client(api_key=api_key)
        self.temperature = temperature

    def verify_ready(self) -> str:
        """Make one tiny real call to prove the key works before probing.

        Raises on any auth/transport failure; returns the model's reply on
        success so the caller can print proof of a live connection.
        """
        resp = self._client.models.generate_content(
            model=self.model, contents="respond with only the word READY"
        )
        text = (getattr(resp, "text", None) or "").strip()
        return text or "(empty response)"

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
        if self.temperature is not None:
            cfg_kwargs["temperature"] = self.temperature
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

"""OpenRouter — one API key in front of many models (Claude, GPT, Llama, ...).

It is wire-compatible with OpenAI's chat completions API, so we just point the
OpenAI client at OpenRouter's base URL."""

from __future__ import annotations

from .openai_provider import OpenAIProvider


class OpenRouterProvider(OpenAIProvider):
    name = "openrouter"

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        base_url: str = "https://openrouter.ai/api/v1",
    ) -> None:
        if not api_key:
            raise RuntimeError(
                "OpenRouter API key not set. Put OPENROUTER_API_KEY in your .env file."
            )
        super().__init__(model, api_key=api_key, base_url=base_url)

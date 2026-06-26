"""Provider registry.

``build_provider`` turns a :class:`~purplemcp.config.ProviderConfig` into a
concrete provider. Concrete classes are imported lazily so a missing optional
SDK (or a provider you never use) never breaks the others.
"""

from __future__ import annotations

from ..config import ProviderConfig
from .base import Message, Provider, ToolCall, ToolSpec

__all__ = ["Provider", "Message", "ToolCall", "ToolSpec", "build_provider"]


def build_provider(cfg: ProviderConfig) -> Provider:
    if cfg.name == "ollama":
        from .ollama_provider import OllamaProvider

        return OllamaProvider(cfg.model, base_url=cfg.base_url, temperature=cfg.temperature)
    if cfg.name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(cfg.model, api_key=cfg.api_key)
    if cfg.name == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(cfg.model, api_key=cfg.api_key, base_url=cfg.base_url)
    if cfg.name == "gemini":
        from .gemini_provider import GeminiProvider

        return GeminiProvider(cfg.model, api_key=cfg.api_key, temperature=cfg.temperature)
    if cfg.name == "openrouter":
        from .openrouter_provider import OpenRouterProvider

        return OpenRouterProvider(cfg.model, api_key=cfg.api_key, base_url=cfg.base_url)
    raise ValueError(f"Unknown provider: {cfg.name!r}")

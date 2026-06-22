"""Provider message/tool translation, exercised offline with dummy keys.

These don't make network calls — constructing a client and translating the
neutral message list is enough to catch SDK-shape mistakes.
"""

from purplemcp.config import ProviderConfig
from purplemcp.providers import build_provider
from purplemcp.providers.base import Message, ToolCall, ToolSpec

TOOLS = [
    ToolSpec(
        "add",
        "add two ints",
        {"type": "object", "properties": {"a": {"type": "integer"}}},
    )
]
CONVO = [
    Message(role="system", content="sys"),
    Message(role="user", content="u"),
    Message(role="assistant", tool_calls=[ToolCall("c", "add", {"a": 1})]),
    Message(role="tool", tool_call_id="c", name="add", content="1"),
]


def test_ollama_translation():
    p = build_provider(ProviderConfig(name="ollama", model="m"))
    assert p._to_native(CONVO)
    assert p._to_native_tools(TOOLS)


def test_openai_translation():
    p = build_provider(ProviderConfig(name="openai", model="m", api_key="x"))
    native = p._to_native(CONVO)
    assert any(msg.get("role") == "tool" for msg in native)
    assert p._to_native_tools(TOOLS)


def test_openrouter_uses_openai_shape():
    p = build_provider(
        ProviderConfig(name="openrouter", model="m", api_key="x", base_url="https://x/")
    )
    assert p._to_native(CONVO)


def test_anthropic_translation():
    p = build_provider(ProviderConfig(name="anthropic", model="m", api_key="x"))
    system, conv = p._split_system(CONVO)
    assert system == "sys"
    assert p._to_native(conv)
    assert p._to_native_tools(TOOLS)


def test_gemini_translation():
    p = build_provider(ProviderConfig(name="gemini", model="m", api_key="x"))
    system, conv = p._split_system(CONVO)
    assert system == "sys"
    assert len(p._to_contents(conv)) == 3  # user, assistant(call), tool(response)
    assert p._tools(TOOLS)

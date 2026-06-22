# 02 — PurpleMCP architecture

The design goal: **one host, any model, any server**, so the same agent loop can
drive a local Llama or cloud Claude against a clean, vulnerable, or hardened
server.

```
purplemcp/
├── providers/      one uniform interface over every LLM
│   ├── base.py         neutral types: Message, ToolCall, ToolSpec; Provider ABC
│   ├── ollama_provider.py        (local)
│   ├── anthropic_provider.py
│   ├── openai_provider.py        (+ openrouter_provider.py reuses it)
│   └── gemini_provider.py
├── host/
│   ├── client.py       MCPHost: connect servers, discover + dispatch tools
│   └── agent.py        Agent: the model<->tools loop
├── guardrails/     reusable hardening primitives (the defense library)
├── installer/      write server configs into Claude Desktop etc.
├── scanner.py      static + dynamic MCP security scanner
├── config.py       provider settings + the MCP server registry
└── cli.py          the `purplemcp` command
```

## The key abstraction: a stateless provider

Every LLM backend implements one method:

```python
class Provider(ABC):
    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Message: ...
```

Messages are **provider-neutral** (`role`, `content`, optional `tool_calls`).
Each provider translates that to/from its native SDK shape internally. Because
the provider is stateless (it gets the whole message list every call), the loop
lives in exactly one place and providers are trivial to unit-test.

## The loop (host/agent.py)

```
messages = [system, user]
repeat up to max_steps:
    assistant = provider.complete(messages, host.tools)
    append assistant
    if no tool_calls: return assistant.content        # final answer
    for each tool_call:
        result = host.call_tool(name, args)            # via MCP
        append tool result
```

## The host (host/client.py)

`MCPHost` is an async context manager that connects one or more servers (stdio or
HTTP), runs `list_tools`, and exposes them as neutral `ToolSpec`s. It namespaces
tools as `server__tool` when multiple servers are connected, and renders
`CallToolResult` down to text for the model.

## Adding things

- **A new provider**: add `providers/x_provider.py` implementing `complete`, wire
  it in `providers/__init__.py:build_provider`. ~50 lines.
- **A new server**: write it with FastMCP, add a `ServerSpec` to
  `config.py:default_registry`.

Next: [03 — installing models](03-installing-models.md).

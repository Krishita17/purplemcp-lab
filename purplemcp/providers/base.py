"""Provider abstraction — one uniform interface over every LLM backend.

The whole point of PurpleMCP's core is that the agent loop in
``purplemcp/host/agent.py`` should not care whether it is driving a local Llama
via Ollama or cloud Claude. It does that by speaking a small **neutral message
protocol** defined here. Each concrete provider translates this neutral form to
and from its native SDK shape.

A provider is *stateless*: it receives the full neutral message list every call
and returns one assistant :class:`Message`. That makes providers trivial to
unit-test (no hidden conversation state) and keeps the loop in one place.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class ToolSpec:
    """A tool the model may call, in provider-neutral form.

    ``input_schema`` is a JSON Schema object (exactly what an MCP server returns
    in ``Tool.inputSchema``)."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """A model's request to invoke one tool."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    """One turn of conversation in neutral form.

    - ``role="assistant"`` may carry ``tool_calls`` (a request to run tools).
    - ``role="tool"`` carries one tool's result; ``tool_call_id``/``name`` link
      it back to the call that produced it.
    """

    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: Optional[str] = None  # set when role == "tool"
    name: Optional[str] = None          # tool name, set when role == "tool"


class Provider(ABC):
    """Base class every LLM backend implements."""

    #: short identifier, e.g. "ollama" / "anthropic"
    name: str = "base"

    def __init__(self, model: str) -> None:
        self.model = model

    @abstractmethod
    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Message:
        """Run one model turn.

        Given the full conversation so far and the available tools, return a
        single assistant :class:`Message`. If the returned message has a
        non-empty ``tool_calls`` list, the caller is expected to execute those
        tools and call ``complete`` again with the results appended.
        """
        raise NotImplementedError

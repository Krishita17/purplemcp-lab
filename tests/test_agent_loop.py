"""The provider-agnostic agent loop, proven without any LLM or network.

A scripted provider returns a tool call, then a final answer. A fake host
records the call. We assert the loop ran the tool and produced the answer.
"""

import asyncio

from purplemcp.host import Agent
from purplemcp.providers.base import Message, Provider, ToolCall, ToolSpec


class ScriptedProvider(Provider):
    name = "scripted"

    def __init__(self, turns):
        self.model = "mock"
        self._turns = list(turns)

    def complete(self, messages, tools):
        return self._turns.pop(0)


class FakeHost:
    def __init__(self):
        self.tools = [ToolSpec("echo", "echo back", {"type": "object"})]
        self.tool_info = []
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return f"ECHO:{arguments}"


def test_agent_runs_tool_then_answers():
    provider = ScriptedProvider(
        [
            Message(role="assistant", tool_calls=[ToolCall("c1", "echo", {"x": 1})]),
            Message(role="assistant", content="all done"),
        ]
    )
    host = FakeHost()
    agent = Agent(provider, host, max_steps=4)

    answer = asyncio.run(agent.run("hello"))

    assert answer == "all done"
    assert host.calls == [("echo", {"x": 1})]
    # the tool result was fed back into the conversation
    assert any(m.role == "tool" and "ECHO" in m.content for m in agent.messages)


def test_agent_answers_without_tools():
    provider = ScriptedProvider([Message(role="assistant", content="42")])
    host = FakeHost()
    agent = Agent(provider, host)
    assert asyncio.run(agent.run("meaning of life?")) == "42"
    assert host.calls == []


def test_agent_respects_max_steps():
    # Always asks for a tool -> should stop at the step cap, not loop forever.
    looping = [
        Message(role="assistant", tool_calls=[ToolCall(f"c{i}", "echo", {})])
        for i in range(50)
    ]
    provider = ScriptedProvider(looping)
    host = FakeHost()
    agent = Agent(provider, host, max_steps=3)
    asyncio.run(agent.run("loop"))
    assert len(host.calls) == 3

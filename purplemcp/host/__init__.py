"""The PurpleMCP host: MCP client manager + the agent tool-calling loop."""

from .agent import DEFAULT_SYSTEM, Agent
from .client import MCPHost, ToolInfo

__all__ = ["MCPHost", "ToolInfo", "Agent", "DEFAULT_SYSTEM"]

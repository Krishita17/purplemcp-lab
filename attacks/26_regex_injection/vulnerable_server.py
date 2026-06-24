"""26 - Regex injection. VULNERABLE. Lab only.

A log-search tool compiles the *caller's* string as a regular expression. That hands
the caller full regex power over the data: a single ``.*`` broadens the match to every
line — including a hidden admin record. (The same metacharacters also enable ReDoS.)
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("26 regex-injection vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("log-search", instructions="Search application logs.", log_level="WARNING")

_LOGS = [
    "2026-06-01 INFO  user alice logged in",
    "2026-06-01 INFO  user bob logged in",
    "2026-06-01 WARN  failed login for guest",
    "2026-06-01 SECRET admin recovery code REGEX-SECRET-3310",  # must never surface in a normal search
]


@mcp.tool()
def search_logs(pattern: str) -> str:
    """Search the application logs for lines matching a pattern."""
    # VULNERABLE: the caller's pattern is compiled as a regex, so '.*' (or any
    # metacharacter) broadens the match to every line — including the secret one.
    hits = [line for line in _LOGS if re.search(pattern, line)]
    return "\n".join(hits) or "(no matches)"


if __name__ == "__main__":
    mcp.run()

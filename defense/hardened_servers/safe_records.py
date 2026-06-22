"""Hardened twin of attacks/14 (broken access control / IDOR).

Same `get_record` tool and same data, but every read is checked against the
session principal with `guardrails.assert_owner`: you get your own records (or
anything if you hold the `admin` scope), and someone else's record is refused —
even though you can name its id.
"""

import os

from mcp.server.fastmcp import FastMCP

from purplemcp.guardrails import AuthorizationError, assert_owner

PRINCIPAL = os.environ.get("PURPLEMCP_PRINCIPAL", "alice")
SCOPES = {s for s in os.environ.get("PURPLEMCP_SCOPES", "").split(",") if s}

RECORDS = {
    1: {"owner": "alice", "name": "Alice Smith", "ssn": "SSN-111-11-1111", "salary": "$95,000"},
    2: {"owner": "bob", "name": "Bob Jones", "ssn": "SSN-417-55-0199", "salary": "$240,000"},
    3: {"owner": "carol", "name": "Carol Diaz", "ssn": "SSN-902-33-7654", "salary": "$310,000"},
}

mcp = FastMCP("hr-records-hardened", instructions=f"HR records (acting as {PRINCIPAL}).", log_level="WARNING")


@mcp.tool()
def get_record(record_id: int) -> str:
    """Fetch an HR record by id (only your own, unless you hold the admin scope)."""
    rec = RECORDS.get(record_id)
    if not rec:
        return f"no record #{record_id}"
    try:
        assert_owner(PRINCIPAL, rec["owner"], scopes=SCOPES)
    except AuthorizationError as exc:
        return f"refused: {exc}"
    return f"#{record_id} {rec['name']} ssn={rec['ssn']} salary={rec['salary']}"


if __name__ == "__main__":
    mcp.run()

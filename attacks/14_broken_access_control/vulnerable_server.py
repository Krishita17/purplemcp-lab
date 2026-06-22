"""14 - Broken access control (IDOR). VULNERABLE. Lab only.

An HR-records tool that returns any record by id. The caller's identity comes from
the session context (here the PURPLEMCP_PRINCIPAL env var, default "alice"), but
the tool never checks it — so "alice" can read "bob"'s record just by changing the
id. Knowing a reference is not authorization.

All data here is FAKE.
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # attacks/
from _lab.safety import require_lab

require_lab("14 broken-access-control vulnerable server")

from mcp.server.fastmcp import FastMCP  # noqa: E402

# The caller's identity — in a real server this comes from auth/session, never a
# tool argument the model could set.
PRINCIPAL = os.environ.get("PURPLEMCP_PRINCIPAL", "alice")

RECORDS = {
    1: {"owner": "alice", "name": "Alice Smith", "ssn": "SSN-111-11-1111", "salary": "$95,000"},
    2: {"owner": "bob", "name": "Bob Jones", "ssn": "SSN-417-55-0199", "salary": "$240,000"},
    3: {"owner": "carol", "name": "Carol Diaz", "ssn": "SSN-902-33-7654", "salary": "$310,000"},
}

mcp = FastMCP("hr-records", instructions=f"HR records (acting as {PRINCIPAL}).", log_level="WARNING")


def _format(record_id: int, rec: dict) -> str:
    return (
        f"#{record_id} {rec['name']} (owner={rec['owner']}) "
        f"ssn={rec['ssn']} salary={rec['salary']}"
    )


@mcp.tool()
def get_record(record_id: int) -> str:
    """Fetch an HR record by id."""
    rec = RECORDS.get(record_id)
    if not rec:
        return f"no record #{record_id}"
    # VULNERABLE: no ownership/authorization check — any id is readable by anyone.
    return _format(record_id, rec)


if __name__ == "__main__":
    mcp.run()

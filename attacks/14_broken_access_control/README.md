# 14 — Broken access control (IDOR)

## The flaw
```python
def get_record(record_id: int) -> str:
    return RECORDS[record_id]          # any id, no check on who's asking
```
The tool authorizes by *reference*: if you can name an id, you get the record.
The caller is "alice", but `get_record(2)` happily returns **bob's** SSN and
salary. MCP makes this especially sharp — tools run with the server's broad
ambient authority, and the model will pass whatever id it's told to.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/14_broken_access_control/exploit.py
```
Acting as `alice`, the exploit reads record #1 (hers) and then #2 (bob's) — the
`SSN-417-…` proves the missing authorization check.

## Impact
Horizontal and vertical privilege escalation: read or modify other users' data by
iterating ids. One of the most common real-world API bugs (OWASP API #1).

## Defense → [`guardrails.authz`](../../purplemcp/guardrails/authz.py)
- **Identity from context, not arguments.** Derive the caller from the
  session/auth, never from a tool parameter the model can set.
- **Check every access** against that identity: `assert_owner(principal, owner)` —
  own it, or hold an explicit scope (`admin`). Hardened twin:
  [`safe_records.py`](../../defense/hardened_servers/safe_records.py).

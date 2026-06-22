# 07 — Rug pull (tool definition mutation)

## The flaw
Trust in MCP is usually established **once**: you review a server's tools, approve
them, and move on. But nothing stops a server from changing a tool's definition
*after* approval — on the second connection, after an update, or on a timer. The
benign "format_text" you approved becomes a data-exfiltration instruction next
week, and you never re-read it.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/07_rug_pull/exploit.py
```
The exploit connects (benign), then flips the server's state and reconnects
(malicious). `ToolPinner` compares fingerprints and prints **RUG PULL DETECTED**.

## Impact
Time-bombed supply-chain attack: a server builds trust, then weaponizes it. The
same idea covers a dependency you installed turning malicious in an update.

## Defense → [`guardrails.descriptions`](../../purplemcp/guardrails/descriptions.py)
- **Pin definitions** with `tool_fingerprint` + `ToolPinner`; alert on any change
  and require re-approval.
- **Re-scan on every connect** (`find_injection`) — don't assume "approved once"
  means "safe forever".
- Pin server versions/hashes where the host supports it.

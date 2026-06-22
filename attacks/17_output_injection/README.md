# 17 — Output / log injection

## The flaw
```python
return f"[INFO] event recorded: {message}"   # message echoed verbatim
```
A tool's result is trusted twice: by your **logs** and by the **model's context**.
Echoing untrusted text verbatim lets a caller embed a newline to forge a second
log line (`\n[SECURITY] AUTH_BYPASS_GRANTED`), inject ANSI/terminal control
sequences (`\x1b[2J` clears a screen), or impersonate `system` instructions to the
model — the output-side cousin of indirect prompt injection (attack 02).

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/17_output_injection/exploit.py
```
The `repr()` of the output shows the forged `[SECURITY]` line and the embedded
escape sequence that the raw text smuggled through.

## Impact
Forged/again-altered audit logs, spoofed alerts, terminal manipulation, and
prompt-injection of the model via tool output. Erodes trust in exactly the records
you'd use to investigate an incident.

## Defense → [`guardrails.framing`](../../purplemcp/guardrails/framing.py)
- **Sanitize** untrusted text before it enters logs/context:
  `guardrails.sanitize_output` strips control/ANSI sequences and escapes newlines.
- **Frame** untrusted spans as data for the model (`guardrails.frame_untrusted`).
- Prefer structured logging (fields, not concatenated strings). Hardened twin:
  [`safe_logger.py`](../../defense/hardened_servers/safe_logger.py).

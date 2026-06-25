# 28 — CRLF / HTTP header injection

## The flaw
```python
def set_cookie(name: str, value: str) -> str:
    return f"Set-Cookie: {name}={value}"      # value goes in verbatim
```
HTTP headers are line-delimited. If a caller-supplied value can contain a CR/LF, it
ends the current header and begins a new one the attacker controls — "response
splitting." `value = "abc\r\nX-Admin: true"` forges an `X-Admin: true` header.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/28_header_injection/exploit.py
```
The injected newline turns one `Set-Cookie` into two headers, the second being the
attacker's `X-Admin: true`.

## Impact
Response splitting → forged security headers, cache poisoning, session fixation, or
reflected content, depending on what the header feeds.

## Defense → [`guardrails.headers`](../../purplemcp/guardrails/headers.py)
`safe_header_value` rejects any CR/LF or C0 control character before the value is
placed in a header, so the value can only ever be a single line. Hardened twin:
[`safe_header_builder.py`](../../defense/hardened_servers/safe_header_builder.py).

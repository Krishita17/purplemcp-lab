# 27 — Open redirect

## The flaw
```python
def build_redirect(target: str) -> str:
    return f"302 Location: {target}"      # any host, no checks
```
The tool turns a caller-supplied destination into a redirect without validating the
host. A link that looks like it belongs to your app (`https://app.example.com/...`)
can be made to bounce the victim to `https://evil.example.com/phish` — or to a
non-web scheme like `javascript:`.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/27_open_redirect/exploit.py
```
`build_redirect("https://evil.example.com/phish")` returns a redirect straight to the
attacker's host (`evil.example.com`).

## Impact
Phishing and trust abuse: users (and tokens in the URL) are sent off-site under your
domain's reputation; chained with SSO it can leak credentials.

## Defense → [`guardrails.redirects`](../../purplemcp/guardrails/redirects.py)
`safe_redirect` parses the target, requires an http(s) scheme, and refuses any host
that is not on the allowlist. Hardened twin:
[`safe_redirector.py`](../../defense/hardened_servers/safe_redirector.py).

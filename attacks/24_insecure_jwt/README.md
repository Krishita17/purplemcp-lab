# 24 — Insecure JWT verification (`alg:none` / unsigned)

## The flaw
```python
def whoami(token: str) -> str:
    payload = json.loads(_b64url_decode(token.split(".")[1]))  # decode, never verify
    if payload.get("role") == "admin":                         # trust the claim
        return f"... secret={_ADMIN_SECRET}"
```
The tool reads the JWT *payload* but never checks the *signature*. A JWT is just
three base64url chunks (`header.payload.signature`); anyone can craft one. Set the
header to `{"alg":"none"}`, claim `{"role":"admin"}`, leave the signature empty — and
a server that doesn't verify will believe it. No secret required.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/24_insecure_jwt/exploit.py
```
A forged `alg:none` token makes `whoami` return `role=admin` and leak
`JWT-ADMIN-SECRET-9921` — proof the unsigned token was trusted.

## Impact
Authentication bypass and privilege escalation: forge any identity/role and reach
whatever the tool gates behind it.

## Defense → [`guardrails.jwtsafe`](../../purplemcp/guardrails/jwtsafe.py)
`verify_jwt` ignores the header's `alg`, **requires HS256**, refuses a missing
signature, and compares the HMAC in constant time before returning a single claim —
so `alg:none` and forged tokens are rejected. Hardened twin:
[`safe_jwt_auth.py`](../../defense/hardened_servers/safe_jwt_auth.py).

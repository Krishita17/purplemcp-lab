# 20 — Mass assignment / privilege escalation

## The flaw
```python
def update_profile(updates: dict) -> str:
    USER.update(updates)         # binds EVERY key the caller sends
```
The tool trusts the *shape* of the input. The UI only shows "display name", but
nothing stops a caller from also sending `{"role": "admin", "is_admin": true}` —
and `dict.update` happily writes them. The model will forward whatever fields it's
told to, so a benign-looking "update my profile" escalates privilege.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/20_mass_assignment/exploit.py
```
The second call sets `display_name` *and* `role=admin` / `is_admin=True`.

## Impact
Vertical privilege escalation and integrity violation — set any server-owned
field (role, balance, ownership) via an "edit" endpoint.

## Defense → [`guardrails.authz.assert_assignable`](../../purplemcp/guardrails/authz.py)
Bind only an explicit **allowlist** of editable fields; reject everything else.
Privileged fields (`role`, `is_admin`) are server-controlled, never caller-set.
Hardened twin: [`safe_profile.py`](../../defense/hardened_servers/safe_profile.py).

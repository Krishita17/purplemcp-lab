# 23 — Argument / Flag Injection

**Family:** Classic appsec, now model-reachable · **Severity:** HIGH
**OWASP-LLM:** LLM05 Improper Output Handling · **CWE-88** Improper Neutralization of Argument Delimiters

## The flaw

This tool does the "secure" thing — it runs a fixed program with `shell=False`, so
there's no *command* injection. But it **splits** the caller's value into separate
argv elements:

```python
@mcp.tool()
def lookup(user: str) -> str:
    argv = [sys.executable, "-c", _HELPER, *user.split()]   # VULNERABLE: split → flags
    return subprocess.run(argv, capture_output=True, text=True).stdout
```

Splitting is the bug. Once `user` can become *more than one* argv element, a value
beginning with `-` is read by the program as an **option**, not data. Here
`user="alice --debug"` flips on a hidden operator-only switch that dumps an internal
secret — the same program, doing something you never intended.

## Run it

```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/23_argument_injection/exploit.py
```

`lookup("alice --debug")` returns `internal_api_key=ARGINJ-SECRET-5521`.

## Impact

Argument injection is quietly powerful because the binary is trusted. Real payloads:

- `tar --checkpoint=1 --checkpoint-action=exec=sh` → command execution
- `curl … -o /etc/cron.d/x` → arbitrary file write
- `git … --output=…`, `find … -exec …`, `ssh -o ProxyCommand=…`

## The defense

Use [`guardrails.safe_argv`](../../purplemcp/guardrails/argv.py): pass each user value
**whole** (never split), and place a literal `--` after the trusted prefix so every
following element is a positional operand, never an option. The hardened twin is
[`defense/hardened_servers/safe_runner.py`](../../defense/hardened_servers/safe_runner.py).

```python
from purplemcp.guardrails import safe_argv

argv = safe_argv([sys.executable, "-c", _HELPER], [user])   # [..., "--", user]
```

In the Defense Lab's **Verify**, `lookup("alice --debug")` leaks the secret on the
vulnerable server and returns a plain record (no secret) on the hardened twin.

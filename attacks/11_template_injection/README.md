# 11 — Template / format-string injection

## The flaw
```python
template.format(app=APP, user=username)   # template is controlled by the model
```
Python's format mini-language can traverse attributes and indexes. Even with an
*innocuous* object in the context, the template
`{app.__init__.__globals__[SECRET_TOKEN]}` walks `app → __init__ → __globals__`
and reads the module's globals — leaking `SECRET_TOKEN`. No f-string, no `eval`,
just `.format` on attacker-controlled text. The same primitive is how
Server-Side Template Injection (Jinja `{{ ... }}`) escalates to RCE.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/11_template_injection/exploit.py
```
The injected template returns `TMPL-SECRET-…` — pulled straight from the server's
globals.

## Impact
Disclosure of any object reachable from the template context: secrets, config,
and (via `__globals__`/`__builtins__`) often a path to arbitrary code execution.
A "format a message" tool becomes a memory-read primitive.

## Defense → [`guardrails.templating`](../../purplemcp/guardrails/templating.py)
- **Never let untrusted input be the format string / template.** Treat templates
  as code, not data.
- Use a substitution-only engine: `guardrails.safe_format` wraps
  `string.Template` (`$name`), which can't reach attributes, indexes, or globals.
- If you must use a real template engine, run it sandboxed (e.g. Jinja's
  `SandboxedEnvironment`) and pass only plain values. Hardened twin:
  [`safe_templater.py`](../../defense/hardened_servers/safe_templater.py).

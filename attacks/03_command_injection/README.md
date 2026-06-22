# 03 — Command injection

## The flaw
```python
subprocess.run(f"ping -c 1 {host}", shell=True)   # host comes from the model
```
With `shell=True`, the OS shell parses the whole string. Set
`host = "127.0.0.1; echo PWNED_$(whoami)"` and the shell runs `ping`, then `echo`,
then substitutes `whoami`. Any tool that shells out with interpolated input is a
remote code execution primitive handed to the model (and to anyone who can inject
into the model — see attack 02).

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/03_command_injection/exploit.py
```
The output contains `PWNED_BY_<your-username>` — proof the injected command ran.

## Impact
Full code execution as the server's user: read/write files, install software,
pivot into the network. This is as bad as it gets.

## Defense → [`guardrails.exec`](../../purplemcp/guardrails/exec.py)
- **Never `shell=True`.** Pass an argv *list*; metacharacters become inert data.
- **Allowlist the executable** so the model can't run arbitrary binaries.
- Prefer a native library over shelling out at all (e.g. an HTTP client instead
  of `curl`). The hardened twin lives in [`../../defense`](../../defense).

# 18 — Eval / expression injection

## The flaw
```python
def calculate(expr: str) -> str:
    return str(eval(expr))      # "math" via eval() == arbitrary code execution
```
`eval` doesn't evaluate *arithmetic* — it evaluates *Python*. So
`__import__('os').popen('…')` runs a shell, `(1).__class__.__bases__` walks the
type system, and module globals (secrets!) are one attribute away. LLM tools love
to expose a "calculator" or "formula" field — and reach for `eval`.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/18_eval_injection/exploit.py
```
`'PWN' + str(6*7)` returns `PWN42` (proof it evaluated a non-arithmetic
expression), then `os.popen('echo …')` proves full command execution.

## Impact
Remote code execution from a single text field — the most severe outcome there is.

## Defense → [`guardrails.safe_eval`](../../purplemcp/guardrails/safe_eval.py)
Parse with `ast` and walk the tree, allowing only numeric literals and the
arithmetic operators (`+ - * / // % **`). No `Name`, `Call`, `Attribute`, or
`Subscript` node is permitted, so nothing can reach code. Hardened twin:
[`safe_calculator.py`](../../defense/hardened_servers/safe_calculator.py).

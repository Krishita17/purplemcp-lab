# Clean example MCP servers

These are **safe-by-default reference servers**. They show the *right* way to
build a tool, and they're what the attack/defense pillars compare against. Each
runs over stdio and is registered in [`purplemcp/config.py`](../purplemcp/config.py).

| Server | Tools | What makes it safe |
| --- | --- | --- |
| [`calculator`](calculator/server.py) | add, subtract, multiply, divide, power, sqrt, percent_of, factorial, logarithm, mean | Explicit operations, **no `eval`** |
| [`text_tools`](text_tools/server.py) | sha256, sha1, base64_encode/decode, url_encode, word_count, slugify | Pure stdlib, no network, deterministic |
| [`filesystem`](filesystem/server.py) | list_dir, read_file, write_file | Every path forced through `guardrails.safe_resolve` (confined to one root) |
| [`web_fetch`](web_fetch/server.py) | fetch_url | `guardrails.safe_get` blocks SSRF, no redirects, size-capped |
| [`notes`](notes/server.py) | add/list/get/search/delete | SQLite with **parameterized queries** only |
| [`live_data`](live_data/server.py) | weather, crypto_price | **Real** keyless APIs (Open-Meteo, CoinGecko) |
| [`web_search`](web_search/server.py) | search | **Real** Tavily API — needs `TAVILY_API_KEY` |
| [`threat_intel`](threat_intel/server.py) | url_report, domain_report, file_hash_report, ip_reputation | **Real** VirusTotal + AbuseIPDB — needs `VT_API_KEY` / `ABUSEIPDB_API_KEY` |

## Try them

```bash
purplemcp tools -s filesystem
purplemcp call  -s filesystem -t write_file -a '{"path":"hello.txt","content":"hi"}'
purplemcp call  -s filesystem -t read_file  -a '{"path":"hello.txt"}'
# guardrail in action — this is rejected:
purplemcp call  -s filesystem -t read_file  -a '{"path":"../../../../etc/passwd"}'
```

Filesystem and notes operate inside [`../sandbox/`](../) (created on first use)
so nothing escapes the repo. Override with `PURPLEMCP_FS_ROOT` /
`PURPLEMCP_NOTES_DB`.

## Build your own

Copy one of these, then:
1. `import` the primitives you need from `purplemcp.guardrails`;
2. run `purplemcp scan servers/yourserver/server.py` to check it;
3. add it to the registry in `purplemcp/config.py`.

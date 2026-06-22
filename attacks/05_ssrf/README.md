# 05 — Server-Side Request Forgery (SSRF)

## The flaw
```python
httpx.get(url, follow_redirects=True)   # url comes from the model
```
No checks on scheme or destination. The server becomes a proxy into everything
*it* can reach but an outsider can't:
- `http://169.254.169.254/latest/meta-data/` → cloud instance credentials,
- `http://localhost:…/` → internal admin panels and databases,
- `http://10.x / 192.168.x / 172.16.x` → the internal network,
- `file://`, `gopher://` → local files / protocol smuggling.

Following redirects makes it worse: a public URL can `302` to an internal one.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/05_ssrf/exploit.py
```
The exploit starts a localhost-only "internal" service and the vulnerable tool
reads its secret — something no external client could do.

## Impact
Cloud credential theft, internal recon, hitting internal APIs with the server's
trust. SSRF is a top cause of cloud breaches.

## Defense → [`guardrails.net`](../../purplemcp/guardrails/net.py)
`safe_get` / `assert_url_allowed` allow only http(s), resolve the host and reject
any private/loopback/link-local IP, don't follow redirects, and cap size — plus
an optional host allowlist. Used by the clean
[`servers/web_fetch`](../../servers/web_fetch/server.py).

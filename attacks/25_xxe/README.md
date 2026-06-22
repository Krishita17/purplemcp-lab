# 25 — XML External Entity (XXE)

## The flaw
```python
parser = xml.sax.make_parser()
parser.setFeature(feature_external_ges, True)   # resolve external entities
parser.parse(io.BytesIO(xml_text.encode()))
```
With external general entities enabled, a document can declare
`<!ENTITY xxe SYSTEM "file:///etc/hosts">` and expand `&xxe;` into the contents of a
local file. The same trick points at `http://169.254.169.254/…` to turn the parser
into an SSRF gadget.

## Run it
```bash
export PURPLEMCP_LAB_ENABLED="i-understand-this-is-a-lab"
python attacks/25_xxe/exploit.py
```
The payload's `&xxe;` entity makes `parse_profile` return the contents of
`/etc/hosts` (which contains `localhost`) — proof the external file was read.

## Impact
Arbitrary local-file disclosure (secrets, configs) and SSRF to internal/metadata
endpoints, from a single XML field.

## Defense → [`guardrails.safexml`](../../purplemcp/guardrails/safexml.py)
`safe_parse_xml` rejects any document containing a `DOCTYPE`/`ENTITY` declaration
*before* parsing, so entities never resolve, then parses with the stdlib (which does
not expand external entities). Hardened twin:
[`safe_xml_parser.py`](../../defense/hardened_servers/safe_xml_parser.py).

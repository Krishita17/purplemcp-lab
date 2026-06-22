# 01 — What is MCP, concretely?

The **Model Context Protocol (MCP)** is an open standard for connecting LLMs to
external capabilities. If function-calling is "the model can ask to run a
function," MCP is "the model can discover and run functions exposed by separate,
swappable servers." Think USB-C for AI tools.

## The three roles

- **Server** — exposes capabilities. Three kinds:
  - **Tools**: actions the model can invoke (`read_file`, `ping`, `add`). This
    repo focuses on tools, because that's where the risk is.
  - **Resources**: read-only data the host can fetch (files, records).
  - **Prompts**: reusable prompt templates.
- **Client** — the protocol connection to one server (speaks JSON-RPC).
- **Host** — the app the model runs in (Claude Desktop, an IDE, or PurpleMCP's
  own host). It owns one client per server and runs the tool-calling loop.

```
 Host (owns the model + the loop)
   ├── Client ──► Server A   (tools: read_file, write_file)
   ├── Client ──► Server B   (tools: fetch_url)
   └── Client ──► Server C   (tools: query_db)
```

## The lifecycle of a tool call

1. Host connects to a server and calls `initialize`.
2. Host calls `list_tools` → gets each tool's **name, description, JSON schema**.
3. Host gives those tools to the model.
4. Model replies "call `read_file({"path": "notes.txt"})`".
5. Host calls `call_tool` on the server, gets the result.
6. Host feeds the result back to the model, which continues or answers.

That loop is implemented in
[`purplemcp/host/agent.py`](../purplemcp/host/agent.py) — read it; it's ~40 lines.

## Transports

- **stdio** — the host launches the server as a subprocess and talks over
  stdin/stdout. Local, simple; what all the bundled servers use.
- **streamable-HTTP** — the server is a web service; the host connects over HTTP.
  Used for remote/hosted servers. PurpleMCP supports both (see `ServerSpec`).

## Why the security angle matters

Step 3 is the catch: **tool descriptions are trusted text fed to the model**, and
step 6 means **tool output re-enters the model's context**. Both are attacker
surfaces (see [attacks 01 and 02](../attacks/)). Every tool is also real code
doing real things — files, shells, network — so a bug in a tool is a bug with
teeth. That's the whole reason this repo pairs every capability with an attack
and a defense.

Next: [02 — architecture](02-architecture.md).

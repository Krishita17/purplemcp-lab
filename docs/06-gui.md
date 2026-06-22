# 🖥️ The Desktop GUI

`purplemcp gui` launches a native desktop **security console** built with
[PySide6](https://doc.qt.io/qtforpython/) (Qt for Python). It is a thin,
beautiful front-end over the exact same core the CLI drives — `MCPHost`, the
provider adapters, the agent loop, the scanner, and the guardrails. There is no
web server and no browser: it's a real desktop app.

```bash
pip install -e ".[gui]"   # one-time: installs PySide6
purplemcp gui             # or:  python -m purplemcp.gui
```

Most of the GUI works offline — the Tool Explorer, Scanner, Attack Lab, and
Defense Lab drive the MCP protocol directly and never call an LLM. The Chat
Playground needs a real model, the AI Models page talks to Ollama / the cloud
providers, and the server catalog launches third-party servers via `npx`/`uvx`.

---

## How it's wired

Qt is synchronous and owns its own event loop; the PurpleMCP core is `asyncio`
and spawns MCP servers as stdio subprocesses. The GUI bridges them in
[`purplemcp/gui/async_bridge.py`](../purplemcp/gui/async_bridge.py):

- a **single persistent asyncio loop** runs on a daemon thread;
- one-shot work (list/call a tool, scan, verify a defense, pull a model) is
  submitted as a coroutine and its result comes back on the GUI thread via a Qt
  signal; streaming work (an exploit subprocess, a model pull) emits progress
  events the same way;
- the Chat Playground holds a **long-lived session task** that owns one
  `MCPHost` + `Agent` for its whole life (so anyio's task-scoped transports open
  and close in the same task) and takes user turns off a queue.

Emitting Qt signals from the loop thread to GUI-thread slots uses queued
connections, which is thread-safe — that's the whole trick.

---

## The pages

The sidebar groups everything into **Overview**, **Connect** (models, servers,
tools, chat), **Red team** (Attack Lab), and **Blue team** (Defense Lab, Scanner).

### Dashboard  ·  *Overview*
Provider readiness (which keys are set), the registered MCP servers, and lab
stats — attack modules and hardened twins — at a glance.

![Dashboard](images/gui/1_dashboard.png)

### AI Models  ·  *Connect*
Manage the models that drive the tools. For **local Ollama**: see installed
models, **pull a new one with a live progress bar**, test it with a one-shot
generation, or delete it. For **cloud providers**: paste an API key, **test it
live**, and save it to your (gitignored) `.env`. Set the default provider too.

![AI Models](images/gui/7_models.png)

### MCP Servers  ·  *Connect*
The registry of servers the host can launch — bundled examples plus your own.
**Add a custom server** (stdio command/args or an http URL), or one-click **add
from a catalog of real published servers** (filesystem, fetch, git, sqlite,
memory, …). Install any server into Claude Desktop or copy its `mcp.json`.

![MCP Servers](images/gui/8_servers.png)

### Tool Explorer  ·  *Connect*
Connect to any registered server, browse its tools, read each tool's JSON input
schema, and **call a tool through an auto-generated form**. No model in the loop
— this is the protocol, raw.

![Tool Explorer](images/gui/2_explorer.png)

### Chat Playground  ·  *Connect*
Pick a provider/model and any set of servers, start a session, and chat. As the
agent works, every **tool call and its result stream in live** as inline cards.

![Chat Playground](images/gui/3_chat.png)

### Attack Lab  ·  *Red team*
Browse all 23 modules grouped by family (MCP-specific vs classic appsec). Arm the
lab, pick an attack, and **Run exploit** — it runs the module's *real*
`exploit.py` as a subprocess and streams its output live (section **1 · Live
exploit output**). Below it, a **2 · Manual terminal** lists the exact commands
behind the demo — the `python …/exploit.py` and `purplemcp scan …` calls — each
one **copyable** (paste into your own shell) *and* **runnable in place**. The
module writeup is rendered alongside.

![Attack Lab](images/gui/5_attacks.png)

### Defense Lab  ·  *Blue team*
The "how we fixed it" half, split so you can **read it on the left and watch it
protect on the right**.

- **Left — explanation:** the threat, a plain-English **mechanism**, a numbered
  *how it protects* step-by-step, and the actual **guardrail source code**
  (syntax-highlighted).
- **Right — run it live:** **1 · Verify** replays the same payload at the
  vulnerable server *and* its hardened twin, side by side, so you watch it get
  exploited (red) then blocked (blue); **2 · Manual terminal** gives you the
  copy-and-run commands (`purplemcp scan …`, `python defense/compare.py <tool>`,
  `purplemcp bench`). The verdict is computed honestly — an explicit
  attack-success "proof" string plus refusal phrases, not a black box.

![Defense Lab](images/gui/6_defense.png)

### Security Scanner  ·  *Blue team*
Run the [scanner](../purplemcp/scanner.py) two ways: **static** over a file or
directory (AST analysis — point it at `attacks/` to light it up), or **dynamic**
against a live server's advertised tool definitions. Results come back as a
severity distribution bar, summary pills, and per-finding cards.

![Security Scanner](images/gui/4_scanner.png)

---

## Safety

The Attack Lab and Defense Lab launch intentionally-vulnerable servers, so they
are gated exactly like the CLI lab: nothing insecure starts until you tick **Arm
the lab** (a single shared switch across both pages), which is the only thing that
injects the `PURPLEMCP_LAB_ENABLED` opt-in token into a vulnerable server's
environment. The sidebar shows a red **Lab ARMED** indicator while it's on.
Exfiltration demos only ever reach a fake local sink. Read
[ETHICS.md](../ETHICS.md) and only run this on a machine you own.

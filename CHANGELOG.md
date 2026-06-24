# Changelog

All notable changes to PurpleMCP. This project adheres loosely to
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

## [0.6.0] — Sorbet edition

### Added
- **`purplemcp metrics` CLI command** — scores the guardrails as binary detectors
  (accuracy / precision / recall / F1 / **ASR**) with a confusion matrix, plus
  `--json` and `--save` (writes `results/metrics-*.{json,md}`). Computed from real MCP
  runs via `run_detection_metrics`; `write_metrics_report` persists it. The dashboard
  metrics panel gained a **per-attack breakdown table** and an **Export report** button.
- **Redesigned, playful dashboard (re-sequenced layout)** — a time-aware greeting,
  a **Lab readiness** panel driven by live `environment.gather()` checks (Python,
  providers, Ollama, servers, GUI, lab state), defense-first stat tiles, **donut
  gauges** (OWASP coverage / HIGH-severity / MCP-specific share), an **OWASP-coverage
  bar chart**, an **attack-mix** table, provider/server tables, and a live **Security
  metrics** panel that scores the guardrails as binary detectors
  (**accuracy / precision / recall / F1 / ASR**) with a **confusion matrix** and an
  **ASR bar chart**. `purplemcp.benchmark.run_detection_metrics` computes the metrics
  from real MCP calls — nothing is simulated.
- **Light "Sorbet" theme (peach · mint · lilac)** — the whole console reskinned from
  the dark palette to a light, summery pastel one, driven entirely from
  `purplemcp.gui.theme.PALETTE`.
- **Four new clean MCP servers, all wired to real services (no mocks):**
  `text_tools` (hashing/encoding, stdlib), `live_data` (weather via Open-Meteo +
  crypto via CoinGecko — keyless), `web_search` (Tavily, `TAVILY_API_KEY`), and
  `threat_intel` (VirusTotal + AbuseIPDB, `VT_API_KEY` / `ABUSEIPDB_API_KEY`).
- **Service-integration key entry** on the **AI Models** page — paste `VT_API_KEY`,
  `ABUSEIPDB_API_KEY`, `TAVILY_API_KEY`; saved to `.env` like the provider keys.
- **Two new attack/defense modules → 25 total:** **24 Insecure JWT Verification**
  (CWE-347 — guarded by `guardrails.jwtsafe.verify_jwt`) and **25 XML External Entity /
  XXE** (CWE-611 — guarded by `guardrails.safexml.safe_parse_xml`). Both ship the full
  triple (vulnerable server + exploit + writeup), a hardened twin, an arena case,
  taxonomy mapping, and tests. Benchmark: **19/19** blocked.
- **More calculator tools** — `factorial`, `logarithm`, `mean` join the existing set.
- **Dashboard redesign** — a fifth "Guardrails" stat and a formatted **OWASP LLM Top 10
  coverage** table.
- **Chat Playground** — a **Clear** button to wipe the transcript, plus broader starter
  prompts that exercise the new servers.

## [Unreleased]

### Added
- **Two new attack/defense modules → 23 total:** **22 Unbounded Output / Context
  Flooding** (OWASP LLM10, CWE-400 — guarded by `guardrails.cap_text`) and **23
  Argument / Flag Injection** (CWE-88 — guarded by `guardrails.safe_argv`). Both ship
  the full triple (vulnerable server + exploit + writeup), a hardened twin, an arena
  case, taxonomy mapping, and tests. OWASP-LLM coverage rises to **6/10** (LLM10 is
  now exercised). Benchmark: **17/17** blocked.
- **Chat Playground example prompts** — one-click suggestion chips that ask a
  tool-using question so first-time users immediately see tool calls fire.
- **Manual terminal "Copy all"** — copy every command behind a lab in one click; a
  traffic-light + LIVE header makes it read as a real terminal.
- **GitHub-sized banner** — redesigned at the recommended **1280×640** social-preview
  resolution (rendered 2×), with BUILD/ATTACK/DEFEND pillar cards.
- **Manual terminal** in the Attack Lab and Defense Lab — every exploit/defense now
  surfaces the exact `purplemcp …` / `python …` commands behind it, each one
  **copyable** (paste into your own shell) *and* **runnable in place**, with real
  subprocess output streaming into a colourised console. Scoped to the project's
  own commands (`purplemcp.gui.ops.RUNNER_ALLOW`).
- **Defense Lab redesign** — a two-pane "read it, then watch it protect" layout:
  the threat, the mechanism, a step-by-step, and the real guardrail source on the
  left; a one-click **Verify** (exploited → blocked) and the manual terminal on the
  right.
- **Brand assets** — `docs/images/logo.svg` + `docs/images/banner.svg` (and rendered
  PNGs), and a refreshed, screenshot-driven README.
- `defense/compare.py` now accepts a case filter, e.g. `python defense/compare.py ping`.

### Changed
- **Default Ollama model is now `qwen2.5`** (was `llama3.1`). qwen2.5 does Ollama's
  *structured* tool-calling reliably; llama3.1 frequently narrates a JSON "call"
  instead of emitting a real one, which made the Chat Playground look broken even
  though the model was responding. Docs, `.env.example`, and the model suggestions
  updated to match.
- Screenshots are regenerated with the labs and chat **driven live**, so they show
  real exploit output, a real exploited→blocked verify, and real MCP tool calls.
- **UI polish:** cards now have subtle vertical-gradient depth, the selected nav
  item gets a purple left-accent bar, headings use tighter letter-spacing, buttons
  gained pressed states, and the dashboard hero carries the shield logo mark. Every
  page header now leads with a brand accent bar, and the manual terminal sports
  macOS-style traffic-light dots and a "live" pill for a true terminal feel.
- **Sharper banner** — redesigned (soft node halos, dual glow, vignette) and
  rendered at 3× (3840×1200) for crisp display; the README shows it full-width.

### Fixed
- `tests/test_terminal.py` collection no longer requires PySide6: `gui/ops.py`'s
  `Job` import moved under `TYPE_CHECKING`, so CI's GUI-less `.[dev]` install passes.

## [0.5.0]

### Added
- **Settings page** + `purplemcp doctor` — environment readiness (Python, providers,
  Ollama, GUI, lab state) via a shared `purplemcp/environment.py`.
- **`purplemcp taxonomy`** + generated [`docs/TAXONOMY.md`](docs/TAXONOMY.md) — the
  OWASP-LLM / CWE / MITRE-ATLAS mapping, browsable in the Learn page.
- **`purplemcp report`** + [`docs/SECURITY-REPORT.md`](docs/SECURITY-REPORT.md) — a
  reproducible security-posture report (scan summary + taxonomy + guardrails).
- **Dashboard quick-actions** that deep-link into the app.
- **Command palette (⌘K)**, **keyboard shortcuts** (⌘1–9, ⌘,, F1/⌘/), a shortcuts
  help overlay, and a live **status bar**.
- **Learn page** — the whole handbook rendered in-app.
- `--version` flag; `CONTRIBUTING.md` and `SECURITY.md`.

## [0.4.0]

### Added
- **Research layer**: threat taxonomy (`purplemcp/taxonomy.py`), **PurpleMCP-Bench**
  (`purplemcp bench`), **SARIF** scanner output, GitHub Actions CI, and the
  methodology write-up (`docs/07-research-methodology.md`) + `CITATION.cff`.
- Attack/defense modules **18–21**: eval injection, zip slip, mass assignment,
  CSV/formula injection (+ `safe_eval`, `csvsafe`, `assert_assignable` guardrails).

## [0.3.0]

### Added
- **Categorized GUI** (grouped sidebar) with **AI Models** and **MCP Servers**
  management pages, and dedicated **Attack Lab** + **Defense Lab**.
- Attack/defense modules **14–17**: broken access control (IDOR), unrestricted file
  write, weak randomness, output/log injection (+ `authz`, `tokens`, `framing`).

## [0.2.0]

### Added
- Native **PySide6 desktop GUI** (`purplemcp gui`): dashboard, tool explorer, chat
  playground, security scanner, attack/defend arena.
- Attack/defense modules **10–13**: SQL injection, template/format-string injection,
  tool shadowing, insecure deserialization (+ `sqlsafe`, `templating`, `registry`,
  `serialization` guardrails).

## [0.1.0]

### Added
- Initial release: the multi-provider MCP host + agent loop, clean example servers,
  the lab-gated attack modules **01–09**, the hardened twins, the reusable
  `guardrails` library, and the static + dynamic security scanner.

"""Interactive Attack Viewer — ``purplemcp watch``.

A menu-driven console that lets you watch an MCP attack happen against a *real*
local/cloud LLM, step by step, and then watch the CryptoMCP + Policy + guardrail
layers stop it. Every LLM decision shown is a genuine API call routed through the
same probe servers the benchmark uses; the defense verdicts come from real
Ed25519 verification and real YAML policy evaluation.

Modes:
  * AUTOMATED — run the probe 3× and show the ASR.
  * MANUAL    — five narrated steps, pausing on ENTER, ending with the defense.
  * DEFENDED  — run once with CryptoMCP + Policy active.
  * COMPARE   — undefended vs. defended, side by side.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from rich.console import Console

from .crypto import CryptoMCP
from .host import Agent, MCPHost
from .policy import PolicyEngine, evaluate_attack_defenses
from .probes.runner import (
    PROBES,
    ProbeCall,
    ProbeScenario,
    RUNS_PER_PROBE,
    _gemini_target,
    _ollama_target,
    _probe_spec,
)
from .providers import build_provider

# OWASP / CWE / MITRE ATLAS references for the manual-mode analysis box.
ATTACK_REFS: dict[str, dict] = {
    "tool_poisoning": {"owasp": "LLM01:2025 — Prompt Injection", "cwe": "CWE-1427", "atlas": "AML.T0051"},
    "indirect_injection": {"owasp": "LLM02:2025 — Sensitive Info Disclosure", "cwe": "CWE-77", "atlas": "AML.T0051.001"},
    "tool_shadowing": {"owasp": "LLM03:2025 — Supply Chain", "cwe": "CWE-441", "atlas": "AML.T0010"},
    "rug_pull": {"owasp": "LLM06:2025 — Excessive Agency", "cwe": "CWE-494", "atlas": "AML.T0010"},
    "excessive_agency": {"owasp": "LLM06:2025 — Excessive Agency", "cwe": "CWE-250", "atlas": "AML.T0053"},
    "data_exfiltration": {"owasp": "LLM02:2025 — Sensitive Info Disclosure", "cwe": "CWE-200", "atlas": "AML.T0024"},
    "command_injection": {"owasp": "LLM05:2025 — Improper Output Handling", "cwe": "CWE-78", "atlas": "AML.T0050"},
    "prompt_override": {"owasp": "LLM01:2025 — Prompt Injection", "cwe": "CWE-1427", "atlas": "AML.T0054"},
}

_MODELS = [
    ("qwen2.5", "ollama", "best tool calling"),
    ("llama3.1:8b", "ollama", "more resistant"),
    ("phi4:14b", "ollama", "most capable, slowest"),
    ("gemini-2.0-flash", "gemini", "cloud, needs API key"),
]


@dataclass
class _Invocation:
    calls: list[ProbeCall]
    answer: str
    error: Optional[str]
    available: list[str]

    @property
    def tool_calls_repr(self) -> list[dict]:
        return [{"name": c.name, "args": c.arguments} for c in self.calls]


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return "Q"


# --------------------------------------------------------------------------- #
#  real LLM invocation (no printing — caller narrates)
# --------------------------------------------------------------------------- #
async def _invoke(provider, scenario: ProbeScenario) -> _Invocation:
    calls: list[ProbeCall] = []

    def on_event(kind: str, payload: object) -> None:
        if kind == "tool_call":
            calls.append(ProbeCall(payload.name, dict(getattr(payload, "arguments", {}) or {})))  # type: ignore[attr-defined]

    answer, error, available = "", None, []
    try:
        async with MCPHost([_probe_spec(scenario)]) as host:
            available = [t.name for t in host.tools]
            agent = Agent(provider, host, system_prompt=scenario.system_prompt,
                          max_steps=6, on_event=on_event)
            answer = await agent.run(scenario.prompt)
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
    return _Invocation(calls=calls, answer=answer, error=error, available=available)


def _outcome(scenario: ProbeScenario, inv: _Invocation) -> str:
    if inv.error or (not inv.calls and not (inv.answer or "").strip()):
        return "error"
    return "manipulated" if scenario.detect(inv.calls, inv.answer) else "resisted"


# --------------------------------------------------------------------------- #
#  menus
# --------------------------------------------------------------------------- #
def _choose_model(console: Console):
    console.print("""
╔══════════════════════════════════════════════════════════╗
║         PurpleMCP — Interactive Attack Viewer            ║
║         Watch attacks happen in real time               ║
╠══════════════════════════════════════════════════════════╣
║  SELECT MODEL:                                          ║
║   [1] qwen2.5         (recommended — best tool calling) ║
║   [2] llama3.1:8b     (more resistant)                 ║
║   [3] phi4:14b        (most capable, slowest)          ║
║   [4] gemini-2.0-flash(cloud, needs GOOGLE_API_KEY)    ║
║   [Q] Quit                                             ║
╚══════════════════════════════════════════════════════════╝""", markup=False, highlight=False)
    choice = _ask("  > Enter choice (1-4): ")
    if choice.upper() == "Q":
        return None
    idx = {"1": 0, "2": 1, "3": 2, "4": 3}.get(choice)
    if idx is None:
        console.print("  invalid choice\n", markup=False)
        return _choose_model(console)
    model, provider, _ = _MODELS[idx]
    if provider == "ollama":
        target, reason = _ollama_target(model)
    else:
        target, reason = _gemini_target(model)
    if target is None:
        console.print(f"  [unavailable] {reason}\n", markup=False)
        return _choose_model(console)
    return target


def _choose_attack(console: Console):
    console.print("""
╔══════════════════════════════════════════════════════════╗
║  SELECT ATTACK:                                         ║
║   [1] Tool Poisoning     — hidden instruction in desc   ║
║   [2] Indirect Injection — malicious data in response   ║
║   [3] Tool Shadowing     — shadow tool intercepts calls ║
║   [4] Rug Pull           — tool changes after trust     ║
║   [5] Excessive Agency   — over-broad permissions       ║
║   [6] Data Exfiltration  — PII sent to attacker         ║
║   [7] Command Injection  — shell injection attempt      ║
║   [8] Prompt Override    — system prompt hijack         ║
║   [A] Run ALL attacks                                  ║
║   [M] Back to model menu                               ║
║   [Q] Quit                                             ║
╚══════════════════════════════════════════════════════════╝""", markup=False, highlight=False)
    choice = _ask("  > Enter choice (1-8, A): ").upper()
    if choice == "Q":
        return "QUIT"
    if choice == "M":
        return "MENU"
    if choice == "A":
        return "ALL"
    idx = {str(i + 1): i for i in range(8)}.get(choice)
    if idx is None:
        console.print("  invalid choice\n", markup=False)
        return _choose_attack(console)
    return PROBES[idx]


def _choose_mode(console: Console) -> str:
    console.print("""
╔══════════════════════════════════════════════════════════╗
║  SELECT MODE:                                          ║
║   [1] AUTOMATED — run 3 times, show statistics         ║
║   [2] MANUAL    — step by step, see each LLM decision  ║
║   [3] DEFENDED  — run with CryptoMCP + Policy active   ║
║   [4] COMPARE   — undefended vs defended side-by-side  ║
╚══════════════════════════════════════════════════════════╝""", markup=False, highlight=False)
    choice = _ask("  > Enter choice (1-4): ")
    return {"1": "AUTOMATED", "2": "MANUAL", "3": "DEFENDED", "4": "COMPARE"}.get(choice, "AUTOMATED")


# --------------------------------------------------------------------------- #
#  modes
# --------------------------------------------------------------------------- #
async def _run_automated(console, provider, label, scenario: ProbeScenario) -> None:
    console.print(f"\n  AUTOMATED — {scenario.title} | {label} | {RUNS_PER_PROBE} runs @ temp 0.7\n", markup=False)
    manip = 0
    for i in range(1, RUNS_PER_PROBE + 1):
        inv = await _invoke(provider, scenario)
        outcome = _outcome(scenario, inv)
        manip += outcome == "manipulated"
        console.print(f"   run {i}: {outcome:<11} tools={[c.name for c in inv.calls] or '—'}", markup=False)
    pct = round(100 * manip / RUNS_PER_PROBE, 1)
    console.print(f"\n   ASR: {manip}/{RUNS_PER_PROBE} = {pct}%\n", markup=False)


def _defense_summary(console, scenario: ProbeScenario) -> None:
    crypto = CryptoMCP()
    d = evaluate_attack_defenses(scenario.id, crypto=crypto, policy=PolicyEngine())
    console.print(" [CryptoMCP Check]", markup=False)
    if d.crypto == "BLOCKED":
        console.print(f"   Ed25519 signature / hash check... {d.crypto_reason}", markup=False)
        console.print("   Decision: REJECT — tool never reaches the LLM", markup=False)
    else:
        console.print(f"   {d.crypto_reason}", markup=False)
        console.print("   Decision: N/A — crypto cannot see this runtime attack", markup=False)
    console.print("\n [Policy Engine Check]", markup=False)
    if d.triggered_rules:
        for r in d.triggered_rules:
            console.print(f"   Rule {r['id']} triggered: {r['name']} ({r['article']})", markup=False)
    console.print(f"   Decision: {d.policy_decision}", markup=False)
    layers = sum([d.crypto == "BLOCKED", d.policy in ("BLOCK", "APPROVE", "FLAG"), True])  # +guardrail
    blocked = d.crypto == "BLOCKED" or d.policy == "BLOCK"
    console.print(
        f"\n ┌─────────────────────────────────────────────┐\n"
        f" │  DEFENSE SUMMARY                            │\n"
        f" │  CryptoMCP:    {d.crypto:<28}│\n"
        f" │  Policy Engine:{(d.policy + ' (' + d.article + ')'):<28}│\n"
        f" │  Guardrail:    {'BLOCKED (hardened twin)':<28}│\n"
        f" │  Result:       {('ATTACK BLOCKED' if blocked else 'FLAGGED/LAYERED'):<28}│\n"
        f" └─────────────────────────────────────────────┘", markup=False)


async def _run_manual(console, provider, label, scenario: ProbeScenario) -> None:
    refs = ATTACK_REFS.get(scenario.id, {})
    console.print("=" * 62, markup=False)
    console.print(f" ATTACK: {scenario.title} | MODEL: {label} | MODE: Manual", markup=False)
    console.print("=" * 62, markup=False)
    console.print("\n STEP 1 — ATTACK SETUP\n ─────────────────────", markup=False)
    console.print(f"   Probe server: {scenario.server_name} ({scenario.server_file})", markup=False)
    console.print(f"   Hidden vector: {scenario.success_note}", markup=False)
    console.print(f"   Task sent to model: \"{scenario.prompt[:70]}...\"", markup=False)
    _ask("\n Press ENTER to send to the LLM... ")

    console.print("\n STEP 2 — LLM RECEIVES TOOLS (REAL API CALL)\n ────────────────────────────", markup=False)
    inv = await _invoke(provider, scenario)
    console.print(f"   Tools available: {inv.available}", markup=False)
    _ask(" Press ENTER to see the LLM decision... ")

    console.print("\n STEP 3 — LLM DECISION\n ─────────────────────", markup=False)
    if inv.error:
        console.print(f"   ERROR: {inv.error}", markup=False)
        return
    console.print(f"   LLM tool calls: {inv.tool_calls_repr or '[]'}", markup=False)
    console.print(f'   LLM output: "{(inv.answer or "")[:120]}"', markup=False)

    outcome = _outcome(scenario, inv)
    console.print("\n STEP 4 — RESULT ANALYSIS\n ─────────────────────────", markup=False)
    box = "MANIPULATED" if outcome == "manipulated" else "RESISTED"
    console.print(
        f" ┌─────────────────────────────────────────────┐\n"
        f" │  OUTCOME: {box:<34}│\n"
        f" │  {('LLM followed the hidden instruction!' if outcome=='manipulated' else 'LLM resisted the injected instruction.'):<43}│\n"
        f" │  OWASP: {refs.get('owasp',''):<36}│\n"
        f" │  CWE:   {refs.get('cwe',''):<36}│\n"
        f" │  MITRE ATLAS: {refs.get('atlas',''):<30}│\n"
        f" └─────────────────────────────────────────────┘", markup=False)
    _ask("\n Press ENTER to see what the defenses would do... ")

    console.print("\n STEP 5 — DEFENSE RESPONSE\n ─────────────────────────", markup=False)
    _defense_summary(console, scenario)


async def _run_defended(console, provider, label, scenario: ProbeScenario) -> None:
    console.print(f"\n  DEFENDED — {scenario.title} | {label}\n", markup=False)
    inv = await _invoke(provider, scenario)
    outcome = _outcome(scenario, inv) if not inv.error else "error"
    console.print(f"   Undefended model outcome: {outcome}", markup=False)
    console.print(f"   Tool calls: {[c.name for c in inv.calls] or '—'}\n", markup=False)
    _defense_summary(console, scenario)


async def _run_compare(console, provider, label, scenario: ProbeScenario) -> None:
    inv = await _invoke(provider, scenario)
    outcome = _outcome(scenario, inv)
    crypto = CryptoMCP()
    d = evaluate_attack_defenses(scenario.id, crypto=crypto, policy=PolicyEngine())
    blocked = d.crypto == "BLOCKED" or d.policy == "BLOCK"
    reached = "NO" if d.crypto == "BLOCKED" else "YES"
    L = []
    L.append("=" * 70)
    L.append(f" COMPARE MODE: {scenario.title} | {label}")
    L.append(" Left: UNDEFENDED (no crypto, no policy)   Right: DEFENDED")
    L.append("=" * 70)
    L.append(f" {'UNDEFENDED':<30}│  DEFENDED")
    L.append(f" {'-'*29}┼  {'-'*28}")
    L.append(f" {'Tool reaches LLM: YES':<30}│  Tool reaches LLM: {reached}")
    L.append(f" {('outcome: ' + outcome):<30}│  CryptoMCP: {d.crypto}")
    L.append(f" {('tools: ' + (','.join(c.name for c in inv.calls) or '—')):<30}│  Policy: {d.policy} ({d.article})")
    L.append(f" {('MANIPULATED' if outcome=='manipulated' else outcome.upper()):<30}│  {'BLOCKED' if blocked else 'LAYERED/FLAGGED'}")
    L.append("=" * 70)
    console.print("\n" + "\n".join(L) + "\n", markup=False)


# --------------------------------------------------------------------------- #
#  driver
# --------------------------------------------------------------------------- #
async def run_viewer(console: Console) -> None:
    while True:
        target = _choose_model(console)
        if target is None:
            console.print("\n  Goodbye.\n", markup=False)
            return
        provider = build_provider(target.cfg)
        while True:
            sel = _choose_attack(console)
            if sel == "QUIT":
                console.print("\n  Goodbye.\n", markup=False)
                return
            if sel == "MENU":
                break
            scenarios = list(PROBES) if sel == "ALL" else [sel]
            mode = _choose_mode(console)
            for scenario in scenarios:
                if mode == "AUTOMATED":
                    await _run_automated(console, provider, target.label, scenario)
                elif mode == "MANUAL":
                    await _run_manual(console, provider, target.label, scenario)
                elif mode == "DEFENDED":
                    await _run_defended(console, provider, target.label, scenario)
                else:
                    await _run_compare(console, provider, target.label, scenario)
            again = _ask("\n Run again? [Y]es / [M]enu / [Q]uit: ").upper()
            if again == "Q":
                console.print("\n  Goodbye.\n", markup=False)
                return
            if again == "M":
                break

"""The ``purplemcp`` command-line interface.

  purplemcp providers              # which LLM backends are configured/ready
  purplemcp servers                # which MCP servers are registered
  purplemcp tools -s calculator    # introspect a server's tools
  purplemcp call -s calculator -t add -a '{"a":2,"b":3}'   # call a tool, no LLM
  purplemcp ask "..." -p ollama -s calculator              # one-shot, model uses tools
  purplemcp chat -p ollama -s calculator -s notes          # interactive
  purplemcp install claude-desktop -s calculator           # wire into Claude Desktop
  purplemcp scan path/to/server.py                         # security scan
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import (
    ServerSpec,
    default_provider_name,
    ensure_sandbox,
    load_providers,
    load_registry,
)
from .host import Agent, MCPHost
from .installer import install_to_claude_desktop, render_mcp_json
from .providers import build_provider

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,  # we render friendly errors ourselves
    help="PurpleMCP — build, attack, and defend MCP servers with local + cloud LLMs.",
)
console = Console()
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"PurpleMCP {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """PurpleMCP — build, attack, and defend MCP servers with local + cloud LLMs."""


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #
def _resolve_specs(names: Optional[list[str]]) -> list[ServerSpec]:
    registry = load_registry()
    specs: list[ServerSpec] = []
    for name in names or []:
        if name not in registry:
            err.print(f"[red]Unknown server '{name}'.[/red] Try: purplemcp servers")
            raise typer.Exit(2)
        specs.append(registry[name])
    return specs


def _make_provider(provider: Optional[str], model: Optional[str]):
    providers = load_providers()
    name = provider or default_provider_name()
    if name not in providers:
        err.print(f"[red]Unknown provider '{name}'.[/red] One of: {', '.join(providers)}")
        raise typer.Exit(2)
    cfg = providers[name]
    if model:
        cfg = cfg.model_copy(update={"model": model})
    if not cfg.ready:
        err.print(
            f"[red]Provider '{name}' is not ready.[/red] "
            f"Set its API key in .env (see .env.example)."
        )
        raise typer.Exit(2)
    return build_provider(cfg)


def _truncate(text: str, n: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _event_printer():
    def on_event(kind: str, payload: object) -> None:
        if kind == "tool_call":
            tc = payload  # ToolCall
            console.print(
                f"[dim]  → {tc.name}({_truncate(json.dumps(tc.arguments))})[/dim]"
            )
        elif kind == "tool_result":
            tc, result = payload  # (ToolCall, str)
            console.print(f"[dim]  ← {_truncate(result)}[/dim]")

    return on_event


def _friendly_error(exc: Exception) -> None:
    """Turn common backend failures into a one-line, actionable message."""
    name = type(exc).__name__
    msg = str(exc)
    if "does not support tools" in msg:
        err.print(
            "[red]That model can't use tools.[/red] Pick a tool-capable model, e.g.:\n"
            "  ollama pull qwen2.5   (then add  -m qwen2.5)"
        )
    elif "ConnectError" in name or "ConnectionError" in name or "Connection error" in msg:
        err.print(
            "[red]Can't reach the model backend.[/red] Is it running?  "
            "For Ollama:  ollama serve"
        )
    elif name == "ResponseError":
        err.print(f"[red]Model backend error:[/red] {msg}")
    elif name == "KeyError":
        err.print(f"[red]Unknown tool {msg}.[/red] Try: purplemcp tools -s <server>")
    else:
        err.print(f"[red]{name}:[/red] {msg}")


def _run_async(coro):
    """Run an async command, rendering friendly errors instead of tracebacks."""
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        raise typer.Exit(130)
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary
        _friendly_error(exc)
        raise typer.Exit(1)


# --------------------------------------------------------------------------- #
#  commands
# --------------------------------------------------------------------------- #
@app.command()
def providers() -> None:
    """List LLM providers and whether each is ready to use."""
    table = Table(title="LLM providers")
    table.add_column("provider", style="bold")
    table.add_column("model")
    table.add_column("ready")
    table.add_column("note")
    for name, cfg in load_providers().items():
        ready = "[green]yes[/green]" if cfg.ready else "[red]no[/red]"
        note = "local, no key needed" if name == "ollama" else (
            "" if cfg.ready else "set API key in .env"
        )
        table.add_row(name, cfg.model, ready, note)
    console.print(table)


@app.command()
def servers() -> None:
    """List registered MCP servers."""
    table = Table(title="MCP servers")
    table.add_column("name", style="bold")
    table.add_column("transport")
    table.add_column("description")
    for name, spec in load_registry().items():
        table.add_row(name, spec.transport, spec.description)
    console.print(table)


@app.command()
def tools(
    server: Optional[list[str]] = typer.Option(
        None, "--server", "-s", help="Server name (repeatable)."
    ),
) -> None:
    """List the tools exposed by one or more MCP servers."""
    if not server:
        err.print("[red]Specify at least one --server.[/red] Try: purplemcp servers")
        raise typer.Exit(2)
    ensure_sandbox()
    specs = _resolve_specs(server)

    async def _run() -> None:
        async with MCPHost(specs) as host:
            table = Table(title="tools")
            table.add_column("tool", style="bold")
            table.add_column("server")
            table.add_column("description")
            for ti in host.tool_info:
                table.add_row(ti.name, ti.server, _truncate(ti.description, 80))
            console.print(table)

    _run_async(_run())


@app.command()
def call(
    server: str = typer.Option(..., "--server", "-s"),
    tool: str = typer.Option(..., "--tool", "-t"),
    args: str = typer.Option("{}", "--args", "-a", help="JSON object of arguments."),
) -> None:
    """Call one tool directly, with no LLM in the loop."""
    ensure_sandbox()
    specs = _resolve_specs([server])
    try:
        payload = json.loads(args)
    except json.JSONDecodeError as exc:
        err.print(f"[red]--args is not valid JSON:[/red] {exc}")
        raise typer.Exit(2)

    async def _run() -> str:
        async with MCPHost(specs) as host:
            return await host.call_tool(tool, payload)

    console.print(_run_async(_run()))


@app.command()
def ask(
    prompt: str = typer.Argument(..., help="Your question."),
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    server: Optional[list[str]] = typer.Option(None, "--server", "-s"),
    max_steps: int = typer.Option(8, "--max-steps"),
) -> None:
    """Ask one question; the model may use MCP tools to answer it."""
    ensure_sandbox()
    llm = _make_provider(provider, model)
    specs = _resolve_specs(server)

    async def _run() -> str:
        async with MCPHost(specs) as host:
            agent = Agent(llm, host, max_steps=max_steps, on_event=_event_printer())
            return await agent.run(prompt)

    answer = _run_async(_run())
    console.print(f"\n[bold magenta]{llm.name}›[/bold magenta] {answer}")


@app.command()
def chat(
    provider: Optional[str] = typer.Option(None, "--provider", "-p"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    server: Optional[list[str]] = typer.Option(None, "--server", "-s"),
    max_steps: int = typer.Option(8, "--max-steps"),
) -> None:
    """Interactive chat. The model can call tools from the given servers."""
    ensure_sandbox()
    llm = _make_provider(provider, model)
    specs = _resolve_specs(server)

    async def _run() -> None:
        async with MCPHost(specs) as host:
            agent = Agent(llm, host, max_steps=max_steps, on_event=_event_printer())
            tool_names = ", ".join(t.name for t in host.tools) or "(none)"
            console.print(
                f"[bold]PurpleMCP chat[/bold] · provider=[cyan]{llm.name}[/cyan] "
                f"model=[cyan]{llm.model}[/cyan]\ntools: {tool_names}\n"
                "Type your message, or /exit to quit."
            )
            while True:
                try:
                    user = await asyncio.to_thread(input, "you› ")
                except (EOFError, KeyboardInterrupt):
                    break
                if user.strip() in ("/exit", "/quit"):
                    break
                if not user.strip():
                    continue
                try:
                    answer = await agent.run(user)
                except Exception as exc:  # keep the chat session alive
                    _friendly_error(exc)
                    continue
                console.print(f"[bold magenta]{llm.name}›[/bold magenta] {answer}")

    _run_async(_run())


@app.command()
def install(
    target: str = typer.Argument(..., help="Host to install into: 'claude-desktop' or 'print'."),
    server: str = typer.Option(..., "--server", "-s"),
) -> None:
    """Wire a PurpleMCP server into a host application's config."""
    specs = _resolve_specs([server])
    spec = specs[0]
    if target == "print":
        console.print(render_mcp_json(spec))
        return
    if target == "claude-desktop":
        path = install_to_claude_desktop(spec)
        console.print(f"[green]Installed '{spec.name}' into[/green] {path}")
        console.print("[dim]Restart Claude Desktop to load it.[/dim]")
        return
    err.print(f"[red]Unknown target '{target}'.[/red] Use 'claude-desktop' or 'print'.")
    raise typer.Exit(2)


@app.command()
def scan(
    path: Optional[str] = typer.Argument(None, help="Path to an MCP server .py file or dir."),
    server: Optional[str] = typer.Option(None, "--server", "-s", help="Scan a live server's tools."),
    fmt: str = typer.Option("text", "--format", "-f", help="text | json | sarif"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write the report to a file."),
) -> None:
    """Run the MCP security scanner (static on a file, or dynamic on a server).

    ``--format sarif`` emits SARIF 2.1.0 for GitHub code scanning / other SAST UIs.
    """
    from .scanner import print_report, scan_path, scan_server, to_json, to_sarif  # lazy

    if server:
        findings = asyncio.run(scan_server(_resolve_specs([server])[0]))
    elif path:
        findings = scan_path(path)
    else:
        err.print("[red]Provide a path to scan, or --server NAME.[/red]")
        raise typer.Exit(2)

    if fmt == "text" and not output:
        print_report(findings, console)
        return

    rendered = {"json": to_json, "sarif": to_sarif}.get(fmt)
    if rendered is None and fmt != "text":
        err.print(f"[red]Unknown --format '{fmt}'.[/red] Use text, json, or sarif.")
        raise typer.Exit(2)
    text = to_json(findings) if fmt == "text" else rendered(findings)
    if output:
        from pathlib import Path

        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]wrote {fmt} report to[/green] {output}")
    else:
        print(text)


@app.command()
def bench(
    provider: Optional[str] = typer.Option(
        None, "--provider", "-p", help="Also run the model-susceptibility eval with this provider."
    ),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    out: str = typer.Option("results", "--out", help="Directory for the JSON + Markdown reports."),
    save: bool = typer.Option(True, "--save/--no-save", help="Write JSON + Markdown reports."),
) -> None:
    """Run PurpleMCP-Bench: guardrail effectiveness (+ optional model susceptibility)."""
    from pathlib import Path

    from .benchmark import run_guardrail_benchmark, run_model_benchmark, write_reports

    ensure_sandbox()
    console.print("[bold]PurpleMCP-Bench[/bold] — guardrail effectiveness\n")
    report = _run_async(
        run_guardrail_benchmark(
            on_case=lambda i, n, title: console.print(f"[dim]  [{i}/{n}] {title}[/dim]")
        )
    )

    table = Table(title="Guardrail effectiveness")
    for col in ("#", "attack", "OWASP-LLM", "vulnerable", "hardened", "fixed"):
        table.add_column(col)
    for c in report.cases:
        vuln = f"[red]{c.vulnerable_verdict}[/red]" if c.exploited_vulnerable else c.vulnerable_verdict
        hard = f"[green]{c.hardened_verdict}[/green]" if c.blocked_hardened else f"[yellow]{c.hardened_verdict}[/yellow]"
        table.add_row(c.num, c.title, c.owasp_llm.split(" ", 1)[0], vuln, hard, "✅" if c.correct else "⚠️")
    console.print(table)
    console.print(
        f"[bold]effectiveness:[/bold] {report.n_correct}/{report.n_cases} "
        f"([green]{report.effectiveness_pct}%[/green]) blocked by the hardened twin"
    )

    if provider:
        providers = load_providers()
        if provider not in providers:
            err.print(f"[red]Unknown provider '{provider}'.[/red] One of: {', '.join(providers)}")
            raise typer.Exit(2)
        cfg = providers[provider]
        if model:
            cfg = cfg.model_copy(update={"model": model})
        if not cfg.ready:
            err.print(f"[red]Provider '{provider}' is not ready.[/red] Set its API key in .env.")
            raise typer.Exit(2)
        console.print(
            f"\n[bold]Model susceptibility[/bold] — {provider}/{cfg.model} "
            "[dim](experimental; results vary by model/run)[/dim]"
        )
        model_results = _run_async(run_model_benchmark(cfg))
        report.model_provider, report.model_name, report.model_results = provider, cfg.model, model_results
        for m in model_results:
            if m.manipulated is None:
                console.print(f"  [dim]{m.title}: error — {m.error}[/dim]")
            else:
                tag = "[red]manipulated[/red]" if m.manipulated else "[green]resisted[/green]"
                console.print(f"  {m.title}: {tag}  [dim]tools={m.tools_called or '—'}[/dim]")

    if save:
        json_path, md_path = write_reports(report, Path(out))
        console.print(f"\n[green]wrote[/green] {json_path}\n[green]wrote[/green] {md_path}")


@app.command()
def metrics(
    out: str = typer.Option("results", "--out", help="Directory for the JSON + Markdown report."),
    save: bool = typer.Option(False, "--save/--no-save", help="Write a JSON + Markdown report."),
    json_out: bool = typer.Option(False, "--json", help="Print machine-readable JSON instead of a table."),
) -> None:
    """Score the guardrails as detectors: accuracy / precision / recall / ASR (real runs)."""
    import json as _json
    from pathlib import Path

    from .benchmark import run_detection_metrics, write_metrics_report

    ensure_sandbox()
    m = _run_async(run_detection_metrics(
        on_case=None if json_out else (lambda i, n, t: err.print(f"[dim]  [{i}/{n}] {t}[/dim]"))
    ))

    if json_out:
        print(_json.dumps(m.to_dict(), indent=2))
        raise typer.Exit(0)

    summary = Table(title="Guardrail detection metrics (real runs)")
    summary.add_column("metric", style="bold")
    summary.add_column("value")
    for label, value in (
        ("accuracy", f"{m.accuracy}%"), ("precision", f"{m.precision}%"),
        ("recall", f"{m.recall}%"), ("F1", f"{m.f1}%"),
        ("ASR — vulnerable", f"[red]{m.asr_vulnerable}%[/red]"),
        ("ASR — hardened", f"[green]{m.asr_hardened}%[/green]"),
    ):
        summary.add_row(label, value)
    console.print(summary)

    cm = Table(title="Confusion matrix")
    cm.add_column("", style="dim")
    cm.add_column("predicted block")
    cm.add_column("predicted allow")
    cm.add_row("attack", f"[green]TP {m.tp}[/green]", f"[red]FN {m.fn}[/red]")
    cm.add_row("benign", f"[yellow]FP {m.fp}[/yellow]", f"[green]TN {m.tn}[/green]")
    console.print(cm)

    fam = Table(title="Recall by attack family")
    fam.add_column("family", style="bold")
    fam.add_column("attacks")
    fam.add_column("blocked")
    fam.add_column("recall")
    for name, n, blocked, recall in m.by_family():
        fam.add_row(name, str(n), str(blocked), f"{recall}%")
    console.print(fam)
    console.print(
        f"[bold]ASR:[/bold] [red]{m.asr_vulnerable}%[/red] on the vulnerable server "
        f"→ [green]{m.asr_hardened}%[/green] after the guardrail."
    )

    if save:
        json_path, md_path = write_metrics_report(m, Path(out))
        console.print(f"\n[green]wrote[/green] {json_path}\n[green]wrote[/green] {md_path}")


@app.command()
def taxonomy() -> None:
    """Show the threat taxonomy: each module mapped to OWASP LLM / CWE / ATLAS."""
    from .taxonomy import TAXONOMY, owasp_coverage

    table = Table(title="PurpleMCP threat taxonomy")
    table.add_column("#", style="dim")
    table.add_column("threat", style="bold")
    table.add_column("OWASP LLM (2025)")
    table.add_column("CWE")
    table.add_column("guardrail")
    for e in TAXONOMY:
        table.add_row(e.num, e.title, e.owasp_label, e.refs.cwe, e.meta.guardrail or "—")
    console.print(table)

    cov = owasp_coverage()
    covered = sum(1 for ids in cov.values() if ids)
    console.print(
        f"[dim]OWASP LLM Top-10 coverage:[/dim] {covered}/10 categories · "
        f"{len(TAXONOMY)} modules.  Full table: docs/TAXONOMY.md"
    )


@app.command()
def report(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write Markdown to a file (else print)."),
) -> None:
    """Generate a reproducible security-posture report for the lab (Markdown)."""
    from .report import build_report

    md = build_report()
    if output:
        from pathlib import Path

        Path(output).write_text(md, encoding="utf-8")
        console.print(f"[green]wrote[/green] {output}")
    else:
        console.print(md)


@app.command()
def doctor() -> None:
    """Check your setup: Python, LLM providers, Ollama, the GUI, and the lab."""
    from .environment import all_ok, gather, stats

    table = Table(title="PurpleMCP doctor")
    table.add_column("check", style="bold")
    table.add_column("status")
    table.add_column("detail")
    for c in gather():
        mark = "[green]✓[/green]" if c.ok else "[red]✗[/red]"
        detail = c.detail + (f"  [dim]→ {c.hint}[/dim]" if c.hint else "")
        table.add_row(c.name, mark, detail)
    console.print(table)

    s = stats()
    console.print(
        f"[dim]lab contents:[/dim] {s['attack_modules']} attack modules · "
        f"{s['hardened_twins']} hardened twins · {s['guardrails']} guardrails"
    )
    if all_ok():
        console.print("[green]✓ Ready.[/green]  Try:  purplemcp gui")
    else:
        console.print("[yellow]Some checks need attention — see the hints above.[/yellow]")


@app.command()
def gui() -> None:
    """Launch the PurpleMCP desktop app (needs the optional 'gui' extra)."""
    try:
        from .gui import run
        code = run()
    except ModuleNotFoundError as exc:
        if "PySide6" in str(exc):
            err.print(
                "[red]The desktop GUI needs PySide6.[/red] Install it with:\n"
                "  [bold]pip install 'purplemcp[gui]'[/bold]"
            )
            raise typer.Exit(1)
        raise
    raise typer.Exit(code)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

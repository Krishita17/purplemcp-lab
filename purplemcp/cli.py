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
    model: Optional[list[str]] = typer.Option(
        None, "--model", "-m",
        help="Model(s) for the susceptibility eval. Repeatable for a cross-model table.",
    ),
    out: str = typer.Option("results", "--out", help="Directory for the JSON + Markdown reports."),
    save: bool = typer.Option(True, "--save/--no-save", help="Write JSON + Markdown reports."),
) -> None:
    """Run PurpleMCP-Bench: guardrail effectiveness (+ optional model susceptibility)."""
    from pathlib import Path

    from .benchmark import run_guardrail_benchmark, write_reports

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

    if save:
        json_path, md_path = write_reports(report, Path(out))
        console.print(f"\n[green]wrote[/green] {json_path}\n[green]wrote[/green] {md_path}")

    # ----------------------------------------------------------------- #
    #  Model-susceptibility probes (8 attack classes × 3 runs @ temp 0.7)
    # ----------------------------------------------------------------- #
    if provider:
        from .benchmark import run_detection_metrics
        from .probes import (
            render_cross_model_table,
            render_paper_report,
            resolve_targets,
            run_susceptibility,
            write_metrics_csv,
            write_susceptibility_reports,
        )

        console.print(
            "\n[bold]Model susceptibility[/bold] "
            "[dim](8 attack classes · 3 runs each · temperature 0.7 · real LLM calls)[/dim]"
        )
        targets, skips = resolve_targets(provider, list(model) if model else None)
        for s in skips:
            console.print(f"  [yellow]skipping {s['target']}[/yellow]: {s['reason']}")
        if not targets:
            err.print(
                "[red]No model backends are available to probe.[/red] "
                "Start Ollama (`ollama serve`) or set a valid GOOGLE_API_KEY."
            )
        else:
            ge = {
                "total_attacks": report.n_cases,
                "blocked_by_hardened_twin": report.n_correct,
                "effectiveness_rate": round(report.n_correct / report.n_cases, 3)
                if report.n_cases else 0.0,
            }
            sus = _run_async(run_susceptibility(
                targets, guardrail_effectiveness=ge, skipped=skips, console=console
            ))
            # Guardrail confusion matrix (real runs) so the paper report has
            # precision/recall/F1/accuracy, and `metrics` can re-render later.
            console.print("\n[dim]scoring guardrails as a classifier (confusion matrix)…[/dim]")
            dm = _run_async(run_detection_metrics(on_case=None))
            sus.guardrail_metrics = {**dm.to_dict(), "n_attacks": dm.n_attacks}
            console.print()
            render_cross_model_table(sus, console)
            console.print()
            render_paper_report(sus, console)
            if save:
                sj, sm = write_susceptibility_reports(sus, Path(out))
                csv_path = write_metrics_csv(sus, Path(out))
                console.print(
                    f"\n[green]wrote[/green] {sj}\n[green]wrote[/green] {sm}"
                    f"\n[green]wrote[/green] {csv_path}"
                )


@app.command()
def metrics(
    out: str = typer.Option("results", "--out", help="Directory to read results from / write the CSV to."),
    save: bool = typer.Option(False, "--save/--no-save", help="Write the metrics CSV."),
    json_out: bool = typer.Option(False, "--json", help="Print the loaded report as JSON instead of the tables."),
) -> None:
    """Paper-ready metrics: per-model ASR, confusion matrix, precision/recall/F1.

    Reads the most recent ``results/susceptibility-*.json`` and re-renders the
    full report — so the paper author can regenerate the tables anytime without
    re-running the benchmark. If that file has no stored guardrail confusion
    matrix (older runs), it is recomputed live from real guardrail runs.
    """
    import glob
    import json as _json
    from pathlib import Path

    from .benchmark import run_detection_metrics
    from .probes import SusceptibilityReport, render_paper_report, write_metrics_csv

    ensure_sandbox()
    out_dir = Path(out)
    files = sorted(glob.glob(str(out_dir / "susceptibility-*.json")))
    if not files:
        err.print(
            f"[red]No susceptibility-*.json found in {out_dir}/.[/red] "
            "Run:  purplemcp bench --provider ollama -m qwen2.5 --save"
        )
        raise typer.Exit(2)

    latest = Path(files[-1])
    report = SusceptibilityReport.from_dict(_json.loads(latest.read_text(encoding="utf-8")))
    console.print(f"[dim]loaded {latest}[/dim]")

    # If the saved run didn't store the guardrail confusion matrix, compute it now.
    if not report.guardrail_metrics:
        console.print("[dim]no stored guardrail metrics — scoring guardrails live…[/dim]")
        dm = _run_async(run_detection_metrics(
            on_case=lambda i, n, t: err.print(f"[dim]  [{i}/{n}] {t}[/dim]")
        ))
        report.guardrail_metrics = {**dm.to_dict(), "n_attacks": dm.n_attacks}

    if json_out:
        print(_json.dumps(report.to_dict(), indent=2))
        raise typer.Exit(0)

    render_paper_report(report, console)

    if save:
        csv_path = write_metrics_csv(report, out_dir)
        console.print(f"\n[green]wrote[/green] {csv_path}")


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

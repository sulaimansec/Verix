"""CLI entry point.

Non-interactive:  python cli.py --target https://example.com --confirm-scope
Interactive:      python cli.py            (prompts for the essentials, then runs)
"""
from __future__ import annotations

import asyncio
from typing import Optional

import pyfiglet
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from ai_brain import BrainError
from config import Config
from runner import run_scan

app = typer.Typer(add_completion=False)
console = Console()


def _banner() -> None:
    art = pyfiglet.figlet_format("Verix", font="slant")
    console.print(Panel.fit(f"[bold cyan]{art}[/bold cyan]"
                             "[bold white]Autonomous Security Engine[/bold white]",
                             border_style="cyan"))


def _interactive_params() -> dict:
    _banner()
    console.print("[dim]Answer a few questions to configure the scan.[/dim]\n")
    target = Prompt.ask("[bold]Target URL[/bold]", default="https://")
    confirm_scope = Confirm.ask(
        "[bold yellow]Do you have explicit authorization to test this target?[/bold yellow]", default=False
    )
    console.print("[dim]  1 = quick (target page only), 2-3 = standard, 4-5 = thorough & slow[/dim]")
    depth = IntPrompt.ask("[bold]Scan depth[/bold]", choices=["1", "2", "3", "4", "5"], default=2)
    ai_checks = Confirm.ask("[bold]Enable AI/LLM-specific checks (Claude-driven)?[/bold]", default=True)
    return {"target": target, "confirm_scope": confirm_scope, "depth": depth, "ai_checks": ai_checks}


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", help="Base URL to test, e.g. https://example.com"),
    depth: int = typer.Option(2, "--depth", help="Crawl depth from the target URL"),
    ai_checks: bool = typer.Option(True, "--ai-checks/--no-ai-checks", help="Enable Claude-driven hypothesis/payload/analysis"),
    confirm_scope: bool = typer.Option(False, "--confirm-scope", help="Required: confirms you are authorized to test this target"),
    max_concurrency: int = typer.Option(5, "--max-concurrency"),
    rate_limit: float = typer.Option(3.0, "--rate-limit", help="Max requests/sec against the target"),
    output_dir: str = typer.Option("./verix-reports", "--output-dir"),
    allow_unsafe_methods: bool = typer.Option(False, "--allow-unsafe-methods", help="Permit PUT/DELETE/PATCH probing (off by default)"),
):
    """Run a scan. With no --target, drops into an interactive prompt."""
    if target is None:
        params = _interactive_params()
        target, confirm_scope, depth, ai_checks = params["target"], params["confirm_scope"], params["depth"], params["ai_checks"]

    if not confirm_scope:
        console.print("[red]✗ Scope not confirmed — aborting. Pass --confirm-scope (or answer Y) once authorized.[/red]")
        raise typer.Exit(code=1)

    try:
        config = Config(
            target=target,
            depth=depth,
            ai_checks=ai_checks,
            confirm_scope=confirm_scope,
            max_concurrency=max_concurrency,
            rate_limit_rps=rate_limit,
            output_dir=output_dir,
            allow_unsafe_methods=allow_unsafe_methods,
        )
    except ValueError as exc:
        console.print(f"[red]✗ {exc}[/red]")
        raise typer.Exit(code=1)

    asyncio.run(_run(config))


async def _run(config: Config) -> None:
    def on_stage(msg: str) -> None:
        console.print(f"[cyan]▸[/cyan] {msg}")

    try:
        with console.status("[bold cyan]Working...", spinner="dots"):
            recon, findings, md_path, html_path = await run_scan(config, on_stage=on_stage)
    except BrainError as exc:
        console.print(Panel.fit(str(exc), title="[red]Claude didn't cooperate[/red]", border_style="red"))
        raise typer.Exit(code=1)

    table = Table(title="Findings")
    for col in ("Severity", "Category", "Endpoint", "CVSS"):
        table.add_column(col)
    for f in findings[:25]:
        table.add_row(f.severity, f.category, f.endpoint, str(f.cvss))
    console.print(table)

    console.print(Panel.fit(
        f"[bold green]Scan complete[/bold green]\n"
        f"{len(recon.pages)} pages · {len(findings)} findings\n\n"
        f"Reports:\n  {md_path}\n  {html_path}",
        border_style="green",
    ))


if __name__ == "__main__":
    app()

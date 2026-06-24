"""TaintScope command-line interface.

Usage::

    taintscope scan ./examples/vulnerable_app.php ./examples/vuln.py
    taintscope scan --lang php ./wp-plugin/
    taintscope scan --json findings.json ./target/
    taintscope scan --llm ./target/        # enable LLM post-filtering
    taintscope serve --port 8000           # start the findings API
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .taint.engine import TaintEngine, Finding

console = Console()


def _collect_files(paths: List[str], lang: str) -> List[str]:
    exts = {"php": (".php",), "python": (".py",), "auto": (".php", ".py")}
    wanted = exts.get(lang, exts["auto"])
    out: List[str] = []
    for p in paths:
        pp = Path(p)
        if pp.is_file():
            if pp.suffix in wanted:
                out.append(str(pp))
        elif pp.is_dir():
            for ext in wanted:
                out.extend(str(x) for x in pp.rglob(f"*{ext}"))
    return out


def _print_findings(findings: List[Finding]) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(title=f"TaintScope — {len(findings)} finding(s)")
    table.add_column("#", style="dim")
    table.add_column("Lang")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Source")
    table.add_column("Sink")
    table.add_column("Location")
    table.add_column("LLM", overflow="fold")
    for i, f in enumerate(findings, 1):
        llm = ""
        if f.llm_verdict:
            llm = f"{f.llm_verdict} ({f.llm_confidence:.2f})" if f.llm_confidence is not None else f.llm_verdict
        table.add_row(
            str(i),
            f.language,
            f.category,
            f.severity,
            f.source,
            f.sink,
            f.sink_location or "",
            llm,
        )
    console.print(table)
    console.print("\n[bold]Data flows:[/bold]")
    for i, f in enumerate(findings, 1):
        console.print(f"  [cyan]#{i}[/cyan] [{f.severity}] {f.category} {f.source} -> {f.sink}")
        console.print(f"     {f.flow}")


@click.group()
@click.version_option(__version__, prog_name="taintscope")
def main() -> None:
    """TaintScope — PHP/Python taint analysis engine."""


@main.command()
@click.argument("paths", nargs=-1, required=True)
@click.option("--lang", type=click.Choice(["php", "python", "auto"]), default="auto")
@click.option("--json", "json_out", type=click.Path(dir_okay=False), default=None, help="Write findings as JSON to this path.")
@click.option("--llm", is_flag=True, help="Enable LLM-based false-positive filtering (requires OPENAI_API_KEY).")
@click.option("--db", is_flag=True, help="Persist findings to PostgreSQL (requires TAINTSCOPE_DB_ENABLED).")
@click.option("--quiet", is_flag=True, help="Only print findings, no banner.")
@click.option("--verbose", is_flag=True, help="Show parse errors and skipped files.")
def scan(paths, lang, json_out, llm, db, quiet, verbose) -> None:
    """Scan files/directories for taint vulnerabilities."""
    files = _collect_files(list(paths), lang)
    if not files:
        console.print("[red]No PHP/Python files found to scan.[/red]")
        sys.exit(1)
    if not quiet:
        console.print(f"[bold]TaintScope[/bold] v{__version__} — scanning {len(files)} file(s)")

    engine = TaintEngine()
    findings = engine.analyze_paths(files)

    if verbose and engine.parse_errors:
        console.print(f"\n[dim]Skipped {len(engine.parse_errors)} file(s) due to parse errors:[/dim]")
        for path, err in engine.parse_errors[:20]:
            console.print(f"  [dim]{path}: {err[:80]}[/dim]")
        if len(engine.parse_errors) > 20:
            console.print(f"  [dim]... and {len(engine.parse_errors) - 20} more[/dim]")

    if llm:
        from .llm.classifier import LLMClassifier

        clf = LLMClassifier()
        if not clf.enabled:
            console.print("[yellow]--llm given but LLM is disabled (set OPENAI_API_KEY and TAINTSCOPE_LLM_ENABLED=1).[/yellow]")
        else:
            console.print("[dim]Classifying findings with LLM...[/dim]")
            clf.classify(findings)

    if db:
        from .storage.db import get_database

        database = get_database()
        if database is None:
            console.print("[yellow]--db given but DB is disabled (set TAINTSCOPE_DB_ENABLED=1).[/yellow]")
        elif findings:
            database.save_findings(findings)
            console.print(f"[dim]Persisted {len(findings)} finding(s) to PostgreSQL.[/dim]")

    _print_findings(findings)

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([x.to_dict() for x in findings], f, indent=2)
        console.print(f"[dim]Wrote {len(findings)} finding(s) to {json_out}[/dim]")

    sys.exit(1 if findings else 0)


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
def serve(host, port) -> None:
    """Start the FastAPI findings API."""
    import uvicorn

    uvicorn.run("taintscope.api.main:app", host=host, port=port, reload=False)


@main.command()
@click.argument("path")
@click.option("--lang", type=click.Choice(["php", "python", "auto"]), default="auto")
def dump_ast(path, lang) -> None:
    """Dump the normalized AST IR for a file (debugging)."""
    p = Path(path)
    if p.suffix == ".php":
        from .ast.php_parser import PhpParser

        program = PhpParser().parse_file(str(p))
    elif p.suffix == ".py":
        from .ast.py_parser import PyParser

        program = PyParser().parse_file(str(p))
    else:
        console.print("[red]Unsupported file type.[/red]")
        sys.exit(1)
    _dump_node(program, 0)


def _dump_node(node, depth: int) -> None:
    indent = "  " * depth
    loc = f" @ {node.location}" if node.location else ""
    extras = ""
    if node.attrs:
        extras = " " + json.dumps({k: v for k, v in node.attrs.items() if not k.startswith("_")}, default=str)
    console.print(f"{indent}{node.kind}{loc}{extras}")
    for c in node.children:
        _dump_node(c, depth + 1)


if __name__ == "__main__":
    main()

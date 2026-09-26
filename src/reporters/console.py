"""Rich terminal console reporter with interactive tables and badges."""
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from src.models.finding import Finding, Severity, VerificationVerdict

import sys

console = Console(
    file=open(sys.stdout.fileno(), mode="w", encoding="utf-8", errors="replace", closefd=False)
    if sys.platform == "win32" else None,
    highlight=True,
)


SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red on black",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold blue",
}

VERDICT_STYLES = {
    VerificationVerdict.VERIFIED_TRUE_POSITIVE: "[bold green]✓ VERIFIED TRUE POSITIVE[/bold green]",
    VerificationVerdict.LIKELY_TRUE_POSITIVE: "[bold cyan]? LIKELY TRUE POSITIVE[/bold cyan]",
    VerificationVerdict.SUSPECTED_FALSE_POSITIVE: "[yellow]⚠ SUSPECTED FALSE POSITIVE[/yellow]",
    VerificationVerdict.DISPROVED_FALSE_POSITIVE: "[dim red]✗ DISPROVED FALSE POSITIVE[/dim red]",
    VerificationVerdict.UNVERIFIED: "[dim]UNVERIFIED[/dim]",
}

def print_summary_table(findings: List[Finding]):
    table = Table(title="[bold magenta]Sentinel Bug & Security Scan Summary[/bold magenta]", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=12)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Category", width=15)
    table.add_column("CWE", width=10)
    table.add_column("Location", width=28)
    table.add_column("JVE Verdict & Score", justify="center")

    for f in findings:
        sev_badge = Text(f.severity.value, style=SEVERITY_STYLES.get(f.severity, "white"))
        loc = f"{f.file_path}:{f.start_line}"
        cwe_str = f.cwe.cwe_id if f.cwe else "-"
        verdict_str = VERDICT_STYLES.get(f.jve.verdict, "UNVERIFIED") if f.jve else "-"
        score_str = f"({int(f.jve.confidence_score*100)}%)" if f.jve else ""
        table.add_row(f.id, sev_badge, f.category.value, cwe_str, loc, f"{verdict_str} {score_str}")

    console.print()
    console.print(table)
    console.print()


def print_detailed_findings(findings: List[Finding]):
    for f in findings:
        sev_color = "red" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow"
        title = f"[{sev_color} bold][{f.severity.value}] {f.title} ({f.id})[/{sev_color} bold]"
        
        details = [
            f"[bold]Location:[/bold] {f.file_path}:{f.start_line}-{f.end_line}",
            f"[bold]Category:[/bold] {f.category.value}" + (f" | [bold]CWE:[/bold] {f.cwe.cwe_id} ({f.cwe.name})" if f.cwe else ""),
            f"\n[bold]Description:[/bold]\n{f.description}\n",
        ]

        if f.tainted_flow:
            details.append("[bold cyan]Data / Execution Flow:[/bold cyan]")
            for step in f.tainted_flow:
                details.append(f"  • {step}")
            details.append("")

        if f.jve:
            details.append(f"[bold magenta]Joint Verification Engine (JVE):[/bold magenta]")
            details.append(f"  Verdict: {VERDICT_STYLES.get(f.jve.verdict, 'UNVERIFIED')} (Confidence: {int(f.jve.confidence_score*100)}%)")
            if f.jve.mitigating_controls_detected:
                details.append(f"  Mitigations Detected: {', '.join(f.jve.mitigating_controls_detected)}")
            details.append(f"  Notes: {f.jve.verifier_notes}\n")

        if f.suggested_fix:
            details.append(f"[bold green]Suggested Remediation:[/bold green] {f.suggested_fix.summary}")
            if f.suggested_fix.diff:
                details.append(f"\n[dim]{f.suggested_fix.diff}[/dim]")

        console.print(Panel("\n".join(details), title=title, border_style=sev_color, expand=True))

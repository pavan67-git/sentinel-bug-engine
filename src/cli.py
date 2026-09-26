"""Enterprise Sentinel Bug & Security Engine CLI."""
import os
import sys
import argparse
from typing import List
from src.parsers.universal import UniversalParser, CodeChunk
from src.scanner import Scanner
from src.rules.static_patterns import RULES
from src.models.finding import Finding, Severity, VerificationVerdict, FixPatch
from src.jve.engine import JointVerificationEngine
from src.llm.provider import LLMProvider
from src.reporters.console import print_summary_table, print_detailed_findings, console
from src.reporters.sarif import generate_sarif

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

def scan_path(
    target_path: str,
    min_severity: Severity = Severity.MEDIUM,
    enable_llm: bool = False,
    run_jve: bool = True,
    include_false_positives: bool = False,
) -> List[Finding]:
    """Delegate scanning to the core Scanner implementation by creating an instance."""
    scanner = Scanner(
        target_path=target_path,
        min_severity=min_severity,
        enable_llm=enable_llm,
        run_jve=run_jve,
        include_false_positives=include_false_positives,
    )
    return scanner.scan_path()


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel: Enterprise Multi-Language Bug & Security Detection Engine with JVE"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Scan source code for bugs and security vulnerabilities")
    scan_parser.add_argument("target", help="File or directory path to scan")
    scan_parser.add_argument("--min-severity", default="MEDIUM", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], help="Minimum severity threshold")
    scan_parser.add_argument("--format", default="console", choices=["console", "sarif", "both"], help="Output format")
    scan_parser.add_argument("--sarif-out", default="sentinel-results.sarif", help="Path to write SARIF output")
    scan_parser.add_argument("--enable-llm", action="store_true", help="Enable LLM reasoning pass")
    scan_parser.add_argument("--no-jve", action="store_true", help="Disable Joint Verification Engine (JVE)")
    scan_parser.add_argument("--include-fp", action="store_true", help="Include disproved false positives in report")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        min_sev = Severity(args.min_severity.upper())
        findings = scan_path(
            target_path=args.target,
            min_severity=min_sev,
            enable_llm=args.enable_llm,
            run_jve=not args.no_jve,
            include_false_positives=args.include_fp
        )

        if args.format in ["console", "both"]:
            if findings:
                print_summary_table(findings)
                print_detailed_findings(findings)
            else:
                console.print("\n[bold green]✓ Scan complete: Zero high-severity vulnerabilities or bugs detected![/bold green]\n")

        if args.format in ["sarif", "both"]:
            sarif_json = generate_sarif(findings)
            with open(args.sarif_out, "w", encoding="utf-8") as f:
                f.write(sarif_json)
            console.print(f"[cyan]SARIF 2.1.0 report exported to: [bold]{args.sarif_out}[/bold][/cyan]")

        # Exit code for CI/CD pipelines: 1 if CRITICAL/HIGH bugs found, 0 otherwise
        has_critical_or_high = any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in findings)
        sys.exit(1 if has_critical_or_high else 0)


if __name__ == "__main__":
    main()

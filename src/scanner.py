# src/scanner.py
"""Core scanning implementation for Sentinel Bug Engine.

Provides a `Scanner` class with a static `scan_path` method that walks the
target directory, detects source files via the universal parser, and applies
the static rule catalog (`src.rules.static_patterns.RULES`).

The implementation mirrors the logic previously embedded in `src/cli.py`
but is isolated here so the CLI can delegate to it.  It returns a list of
`Finding` objects ready for reporting, JVE verification, or LLM analysis.
"""

import os
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any
import re

from src.parsers.universal import UniversalParser
from src.rules.static_patterns import RULES
from src.models.finding import Finding, Severity, VerificationVerdict, FixPatch, Category
from src.jve.engine import JointVerificationEngine
from src.llm.provider import LLMProvider
from src.reporters.console import console

# Severity ordering used for filtering (same as CLI)
SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Mapping Semgrep severity levels to our Severity enum
SEMGREP_TO_SEVERITY = {
    "error": Severity.CRITICAL,
    "warning": Severity.HIGH,
    "info": Severity.MEDIUM,
    "style": Severity.LOW,
    "experimental": Severity.INFO,
}



class Scanner:
    """Stateless scanner utility.

    The class is deliberately lightweight – it does not keep internal state
    between calls, making it safe to invoke multiple times (e.g., from a CI
    job or a web service).
    """


    def _run_semgrep(self, target: Path) -> List[Dict[str, any]]:
        """Execute Semgrep on the target directory and return raw findings.

        If the ``semgrep`` binary is not available, an empty list is returned.
        """
        # Check semgrep availability
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=False)
        except FileNotFoundError:
            return []
        cmd = ["semgrep", "--config=auto", "--json", str(target)]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except subprocess.SubprocessError:
            return []
        if result.returncode not in (0, 1):
            return []
        try:
            data = json.loads(result.stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []



    def __init__(self, target_path: str, patterns: dict | None = None, min_severity: Severity = Severity.LOW, enable_llm: bool = False, run_jve: bool = True, include_false_positives: bool = False):
        self.target_path = target_path
        self.patterns = patterns if patterns is not None else {}
        self.min_severity = min_severity
        self.enable_llm = enable_llm
        self.run_jve = run_jve
        self.include_false_positives = include_false_positives
    def scan_path(self) -> List[Finding]:
        # Use instance attributes
        target_path = self.target_path
        min_severity = self.min_severity
        enable_llm = self.enable_llm
        run_jve = self.run_jve
        include_false_positives = self.include_false_positives

        """Scan a file or directory and return a list of :class:`Finding`.

        Parameters
        ----------
        target_path: str
            Path to a file or a directory tree.
        min_severity: Severity, default ``Severity.MEDIUM``
            Findings with a lower severity are filtered out.
        enable_llm: bool, default ``False``
            Whether to invoke the LLM provider for additional semantic
            analysis.
        run_jve: bool, default ``True``
            Run the Joint Verification Engine (adversarial check) on each
            finding.
        include_false_positives: bool, default ``False``
            If ``True`` keep findings that the JVE marks as
            ``DISPROVED_FALSE_POSITIVE``; otherwise they are omitted.
        """
        # ------------------------------------------------------------
        # 1️⃣ Discover target files
        # ------------------------------------------------------------
        target_files: List[str] = []
        if os.path.isfile(target_path):
            target_files.append(target_path)
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                # Skip common noise directories
                if any(part in root for part in [".git", "node_modules", "venv", "__pycache__", "dist", "build"]):
                    continue
                for file in files:
                    full_path = os.path.join(root, file)
                    if UniversalParser.detect_language(full_path):
                        target_files.append(full_path)
        else:
            console.print(f"[bold red]Error:[/bold red] Path not found: {target_path}")
            return []

        console.print(f"[cyan]Scanning [bold]{len(target_files)}[/bold] source files...[/cyan]")

        # ------------------------------------------------------------
        # 2️⃣ Fast deterministic pattern scan
        # ------------------------------------------------------------
        all_findings: List[Finding] = []
        finding_counter = 1
        llm = LLMProvider() if enable_llm else None

        # Run Semgrep (if available) and collect its findings
        semgrep_results = self._run_semgrep(Path(target_path))
        for sg in semgrep_results:
            # Extract basic fields from Semgrep result structure
            sg_path = sg.get("path", "")
            start_line = sg.get("start", {}).get("line", 0)
            end_line = sg.get("end", {}).get("line", start_line)
            severity_str = sg.get("severity", "info")
            severity = SEMGREP_TO_SEVERITY.get(severity_str, Severity.INFO)
            title = sg.get("message", "Semgrep finding")
            description = sg.get("extra", {}).get("metadata", {}).get("description", title)
            cwe = sg.get("extra", {}).get("metadata", {}).get("cwe")
            code_snippet = sg.get("extra", {}).get("lines", "").strip()
            finding = Finding(
                id=f"SGR-{finding_counter:03d}",
                file_path=sg_path,
                start_line=start_line,
                end_line=end_line,
                title=title,
                description=description,
                severity=severity,
                category=Category.SECURITY,
                cwe=cwe,
                code_snippet=code_snippet,
                suggested_fix=FixPatch(summary="", diff=""),
            )
            all_findings.append(finding)
            finding_counter += 1

        for file_path in target_files:
            lang = UniversalParser.detect_language(file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                lines = content.splitlines()
            except Exception:
                continue

            # Pattern scan (custom patterns + static RULES)
            for idx, line in enumerate(lines):
                line_no = idx + 1
                # Custom user-provided patterns
                for pat_name, pat_cfg in self.patterns.items():
                    try:
                        regex = re.compile(pat_cfg["regex"])
                    except re.error:
                        continue
                    if regex.search(line):
                        finding = Finding(
                            id=f"PAT-{finding_counter:03d}",
                            file_path=file_path,
                            start_line=line_no,
                            end_line=line_no,
                            title=pat_name,
                            description=pat_cfg.get("description", ""),
                            severity=Severity[pat_cfg.get("severity", "LOW")],
                            category=Category[pat_cfg.get("category", "CODE_QUALITY")],
                            cwe=None,
                            pattern_name=pat_name,
                            code_snippet=line.strip(),
                            suggested_fix=FixPatch(summary="", diff=""),
                        )
                        all_findings.append(finding)
                        finding_counter += 1
                # Static RULES
                for rule in RULES:
                    if rule.matches(line, lang):
                        finding = Finding(
                            id=f"SEC-{finding_counter:03d}",
                            file_path=file_path,
                            start_line=line_no,
                            end_line=line_no,
                            title=rule.title,
                            description=rule.description,
                            severity=rule.severity,
                            category=rule.category,
                            cwe=rule.cwe,
                            code_snippet=line.strip(),
                            suggested_fix=FixPatch(summary=rule.fix_suggestion, diff=""),
                        )
                        all_findings.append(finding)
                        finding_counter += 1

            # Optional LLM pass
            if enable_llm and llm and llm.api_key:
                chunks = UniversalParser.parse_file(file_path)
                for chunk in chunks:
                    llm_findings = llm.analyze_chunk(chunk, finding_id_prefix=f"AI-{finding_counter}")
                    for lf in llm_findings:
                        all_findings.append(lf)
                        finding_counter += 1

            # Optional JVE pass
            if run_jve:
                verified_findings: List[Finding] = []
                for f in all_findings:
                    # Provide 20 lines of surrounding code context
                    start_ctx = max(0, f.start_line - 10)
                    end_ctx = min(len(lines), f.end_line + 10)
                    surrounding = "\n".join(lines[start_ctx:end_ctx])
                    v_finding = JointVerificationEngine.verify(f, surrounding)
                    verified_findings.append(v_finding)
                all_findings = verified_findings

        # ------------------------------------------------------------
        # 3️⃣ Filtering by severity and false‑positive policy
        # ------------------------------------------------------------
        min_val = SEVERITY_ORDER.get(min_severity, 2)
        filtered = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 0) >= min_val]

        if not include_false_positives:
            filtered = [f for f in filtered if not (f.jve and f.jve.verdict == VerificationVerdict.DISPROVED_FALSE_POSITIVE)]

        return filtered

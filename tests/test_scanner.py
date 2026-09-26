"""Expanded test suite for Sentinel Bug Engine.

Covers:
- CWE catalog lookups (catalog.py)
- Static pattern rule matching (static_patterns.py)
- Scanner: pattern detection, severity filtering, false path handling
- Finding model field validation
"""
import os
import tempfile
from pathlib import Path

import pytest

from src.models.finding import Category, Severity, Finding, FixPatch
from src.rules.catalog import get_cwe, CWE_CATALOG
from src.rules.static_patterns import RULES
from src.scanner import Scanner


# ---------------------------------------------------------------------------
# CWE Catalog
# ---------------------------------------------------------------------------

class TestCWECatalog:
    def test_known_cwe_lookup(self):
        cwe = get_cwe("CWE-89")
        assert cwe is not None
        assert cwe.cwe_id == "CWE-89"
        assert "SQL" in cwe.name

    def test_case_insensitive_lookup(self):
        assert get_cwe("cwe-89") == get_cwe("CWE-89")

    def test_unknown_cwe_returns_none(self):
        assert get_cwe("CWE-9999") is None

    def test_none_cwe_returns_none(self):
        assert get_cwe(None) is None

    def test_empty_string_returns_none(self):
        assert get_cwe("") is None

    def test_catalog_has_ten_entries(self):
        assert len(CWE_CATALOG) == 10

    def test_owasp_mapping_present(self):
        cwe = get_cwe("CWE-89")
        assert cwe.owasp_top10 == "A03:2021-Injection"

    def test_cwe_with_no_owasp_is_none(self):
        # CWE-362 (Race Condition) has no OWASP mapping
        cwe = get_cwe("CWE-362")
        assert cwe is not None
        assert cwe.owasp_top10 is None


# ---------------------------------------------------------------------------
# Static Pattern Rules
# ---------------------------------------------------------------------------

class TestStaticPatterns:
    def test_hardcoded_secret_detected(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-001")
        assert rule.matches('api_key = "AKIAIOSFODNN7EXAMPLE"', "*")

    def test_aws_access_key_detected(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-001")
        assert rule.matches('key = "AKIA1234567890ABCDEF"', "python")

    def test_safe_line_not_flagged(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-001")
        assert not rule.matches('api_key = os.environ["API_KEY"]', "python")

    def test_os_command_injection_detected(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-003")
        assert rule.matches("subprocess.run(cmd, shell=True)", "python")

    def test_language_filter_respected(self):
        # SQL rule only applies to python/js/etc, not to arbitrary langs
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-002")
        assert not rule.matches("SELECT * FROM users WHERE id = '" + "' +", "rust")

    def test_eval_detected(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-004")
        assert rule.matches("result = eval(user_input)", "python")

    def test_exec_detected(self):
        rule = next(r for r in RULES if r.rule_id == "RULE-SEC-004")
        assert rule.matches("exec(some_code)", "python")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TestScanner:
    def test_scanner_finds_pattern(self):
        """Original test — kept for regression."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "sample.py"
            file_path.write_text("# TODO: fix this issue\nprint('hello')\n")
            patterns = {
                "todo_finder": {
                    "regex": "TODO",
                    "description": "Detect TODO comments",
                    "severity": "LOW",
                    "category": "CODE_QUALITY",
                }
            }
            scanner = Scanner(target_path=tmp_dir, patterns=patterns)
            results = scanner.scan_path()
            assert any(f.file_path == str(file_path) for f in results)
            finding = next(f for f in results if f.file_path == str(file_path))
            assert finding.pattern_name == "todo_finder"
            assert finding.severity == "LOW"
            assert finding.category == Category.CODE_QUALITY

    def test_scanner_detects_hardcoded_secret(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "config.py"
            file_path.write_text('api_key = "AKIA1234567890ABCDEF"\n')
            scanner = Scanner(target_path=tmp_dir, min_severity=Severity.LOW, run_jve=False)
            results = scanner.scan_path()
            assert len(results) > 0
            titles = [f.title for f in results]
            assert any("Secret" in t or "Credentials" in t or "Key" in t for t in titles)

    def test_scanner_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            scanner = Scanner(target_path=tmp_dir)
            results = scanner.scan_path()
            assert results == []

    def test_scanner_nonexistent_path(self):
        scanner = Scanner(target_path="/nonexistent/path/xyz")
        results = scanner.scan_path()
        assert results == []

    def test_scanner_single_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "app.py"
            file_path.write_text("x = 1\n")
            scanner = Scanner(target_path=str(file_path))
            results = scanner.scan_path()
            # No findings expected for a clean file
            assert isinstance(results, list)

    def test_severity_filtering(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "vuln.py"
            file_path.write_text('api_key = "AKIA1234567890ABCDEF"\n')
            # Only CRITICAL should be returned
            scanner = Scanner(
                target_path=tmp_dir,
                min_severity=Severity.CRITICAL,
                run_jve=False,
            )
            results = scanner.scan_path()
            for f in results:
                assert f.severity in (Severity.CRITICAL,)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class TestFindingModel:
    def test_finding_creation(self):
        f = Finding(
            id="SEC-001",
            file_path="app.py",
            start_line=1,
            end_line=1,
            title="Test",
            description="A test finding",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            suggested_fix=FixPatch(summary="fix it", diff=""),
        )
        assert f.id == "SEC-001"
        assert f.severity == Severity.HIGH

    def test_finding_default_tags_empty(self):
        f = Finding(
            id="SEC-002",
            file_path="x.py",
            start_line=1,
            end_line=1,
            title="T",
            description="D",
            severity=Severity.LOW,
            category=Category.CODE_QUALITY,
        )
        assert f.tags == []
        assert f.tainted_flow == []

"""Deterministic multi-language static pattern matching rules for fast pre-filtering."""
import re
from typing import List, Dict, Any, Optional
from src.models.finding import Severity, Category
from src.rules.catalog import get_cwe

class PatternRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        category: Category,
        severity: Severity,
        cwe_id: str,
        patterns: List[re.Pattern],
        languages: List[str],
        description: str,
        fix_suggestion: str
    ):
        self.rule_id = rule_id
        self.title = title
        self.category = category
        self.severity = severity
        self.cwe = get_cwe(cwe_id)
        self.patterns = patterns
        self.languages = [lang.lower() for lang in languages]
        self.description = description
        self.fix_suggestion = fix_suggestion

    def matches(self, line: str, language: str) -> bool:
        if "*" not in self.languages and language.lower() not in self.languages:
            return False
        return any(p.search(line) for p in self.patterns)


RULES: List[PatternRule] = [
    PatternRule(
        rule_id="RULE-SEC-001",
        title="Hardcoded API Secret or Private Key",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        cwe_id="CWE-798",
        languages=["*"],
        patterns=[
            re.compile(r"""(?:api[_-]?key|secret|password|access_token|auth_token)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{16,}['"]""", re.IGNORECASE),
            re.compile(r"""-----BEGIN (?:RSA )?PRIVATE KEY-----"""),
            re.compile(r"""ghp_[A-Za-z0-9]{36}"""), # GitHub PAT
            re.compile(r"""AKIA[0-9A-Z]{16}"""), # AWS Access Key
        ],
        description="A potential hardcoded secret or token was detected in source code. Credentials must never be committed to source control.",
        fix_suggestion="Move credentials to environment variables or an enterprise secret manager (e.g. AWS Secrets Manager, HashiCorp Vault)."
    ),
    PatternRule(
        rule_id="RULE-SEC-002",
        title="SQL Query Concatenation / Potential SQLi",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        languages=["python", "javascript", "typescript", "java", "php", "go"],
        patterns=[
            re.compile(r"""(?:execute|query|rawQuery)\s*\(\s*f?['"].*?SELECT.*?WHERE.*?\+""", re.IGNORECASE),
            re.compile(r"""(?:execute|query)\s*\(\s*f['"].*?SELECT.*?\{.*?\}""", re.IGNORECASE),
            re.compile(r"""SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?=\s*['"]\s*\+""", re.IGNORECASE),
            re.compile(r"""db\.(?:query|execute)\s*\(\s*`SELECT.*?FROM.*?WHERE.*?\$\{.*?\}""", re.IGNORECASE),
        ],
        description="SQL query appears to be constructed using string concatenation or template interpolation instead of parameterized queries.",
        fix_suggestion="Use parameterized queries / prepared statements (e.g. `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`)."
    ),
    PatternRule(
        rule_id="RULE-SEC-003",
        title="Dangerous OS Command Execution",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        cwe_id="CWE-78",
        languages=["python", "javascript", "typescript", "go", "php"],
        patterns=[
            re.compile(r"""subprocess\.(?:Popen|call|run|check_output)\s*\(.*shell\s*=\s*True""", re.IGNORECASE),
            re.compile(r"""os\.system\s*\(""", re.IGNORECASE),
            re.compile(r"""child_process\.exec\s*\(""", re.IGNORECASE),
            re.compile(r"""system\s*\(\s*\$_(?:GET|POST|REQUEST)""", re.IGNORECASE),
        ],
        description="Direct invocation of system shell with potentially untrusted dynamic input can allow arbitrary command injection.",
        fix_suggestion="Pass command arguments as an array/list with `shell=False` or sanitize inputs using strict whitelist validation."
    ),
    PatternRule(
        rule_id="RULE-SEC-004",
        title="Unsafe Dynamic Code Evaluation (eval/Function)",
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        cwe_id="CWE-502",
        languages=["python", "javascript", "typescript", "php"],
        patterns=[
            re.compile(r"""\beval\s*\(""", re.IGNORECASE),
            re.compile(r"""\bexec\s*\(""", re.IGNORECASE),
            re.compile(r"""new\s+Function\s*\(""", re.IGNORECASE),
        ],
        description="Use of dynamic code evaluation functions allows direct execution of arbitrary code strings if supplied by untrusted sources.",
        fix_suggestion="Refactor logic to use safe parsers (e.g. `ast.literal_eval`, `JSON.parse`) or structured lookups instead of runtime execution."
    ),
    PatternRule(
        rule_id="RULE-SEC-005",
        title="Path Traversal Risk via Unvalidated File Path",
        category=Category.SECURITY,
        severity=Severity.MEDIUM,
        cwe_id="CWE-22",
        languages=["python", "javascript", "typescript", "go", "java"],
        patterns=[
            re.compile(r"""open\s*\(\s*(?:os\.path\.join|path\.join)?.*?(?:req\.|request\.|params|query)""", re.IGNORECASE),
            re.compile(r"""fs\.(?:readFile|createReadStream)\s*\(.*?(?:req\.|params|query)""", re.IGNORECASE),
        ],
        description="File path is directly influenced by external request parameters without canonicalization or directory containment checks.",
        fix_suggestion="Resolve the absolute canonical path using `os.path.realpath` / `path.resolve` and verify it starts with the intended base directory."
    ),
    PatternRule(
        rule_id="RULE-BUG-001",
        title="Resource Leak (Unclosed File or Stream)",
        category=Category.RESOURCE_LEAK,
        severity=Severity.MEDIUM,
        cwe_id="CWE-400",
        languages=["python", "java", "go"],
        patterns=[
            re.compile(r"""^\s*[a-zA-Z_0-9]+\s*=\s*open\s*\([^)]+\)(?!\s*as\s)"""),
        ],
        description="Resource is opened directly without a context manager or defer/finally block, risking descriptor exhaustion on exceptions.",
        fix_suggestion="Use a context manager (`with open(...) as f:`) in Python, `try-with-resources` in Java, or `defer f.Close()` in Go."
    ),
]

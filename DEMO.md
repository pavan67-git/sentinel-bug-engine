# 🛡️ Sentinel Bug Engine — Live Demo

> Real scan output against a deliberately vulnerable Flask web application.
> All vulnerabilities below were **automatically detected** by Sentinel's 4-tier analysis pipeline.

---

## 🎯 Scan Target

**File:** `tests/samples/vulnerable_flask_app.py`
A simulated real-world Flask application with intentionally introduced OWASP Top 10 vulnerabilities — similar to patterns found in CVE databases.

**Command used:**
```bash
python -m src.cli scan tests/samples/vulnerable_flask_app.py --min-severity LOW
```

---

## 📊 Results Summary

| Metric | Value |
|--------|-------|
| **Files Scanned** | 1 |
| **Total Findings** | 6 |
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 1 |
| **JVE False-Positive Filter** | ✅ Active |
| **SARIF 2.1.0 Export** | ✅ Generated |

---

## 🔍 Detailed Findings

### [SEC-001] 🔴 CRITICAL — Hardcoded API Secret or Private Key
| Field | Detail |
|-------|--------|
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Location** | `vulnerable_flask_app.py:18` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
AWS_ACCESS_KEY    = "AKIA1234567890ABCDEF"
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN      = "ghp_1234567890abcdefghijklmnopqrstuv12"
```

**Fix:** Move credentials to environment variables or a secrets manager:
```python
AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]
```

---

### [SEC-002] 🟠 HIGH — SQL Query Concatenation / Potential SQLi
| Field | Detail |
|-------|--------|
| **CWE** | CWE-89: SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Location** | `vulnerable_flask_app.py:38` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

**Fix:** Use parameterized queries:
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
```

---

### [SEC-003] 🟠 HIGH — Dangerous OS Command Execution
| Field | Detail |
|-------|--------|
| **CWE** | CWE-78: OS Command Injection |
| **OWASP** | A03:2021 – Injection |
| **Location** | `vulnerable_flask_app.py:48` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
```

**Fix:** Use argument lists with `shell=False`:
```python
subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
```

---

### [SEC-004] 🟠 HIGH — Dangerous OS Command Execution
| Field | Detail |
|-------|--------|
| **CWE** | CWE-78: OS Command Injection |
| **OWASP** | A03:2021 – Injection |
| **Location** | `vulnerable_flask_app.py:55` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
os.system("tar -czf backup.tar.gz " + folder)
```

**Fix:** Use `subprocess` with a list of arguments and validate `folder` against a safe path prefix.

---

### [SEC-005] 🔴 CRITICAL — Unsafe Dynamic Code Evaluation
| Field | Detail |
|-------|--------|
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **OWASP** | A03:2021 – Injection |
| **Location** | `vulnerable_flask_app.py:70` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
result = eval(expr)  # expr comes from request.args
```

**Fix:** Replace `eval` with a safe expression parser (e.g. `ast.literal_eval`, `simpleeval`):
```python
import ast
result = ast.literal_eval(expr)
```

---

### [SEC-006] 🟡 MEDIUM — Resource Leak (Unclosed File)
| Field | Detail |
|-------|--------|
| **CWE** | CWE-400: Uncontrolled Resource Consumption |
| **OWASP** | N/A |
| **Location** | `vulnerable_flask_app.py:80` |
| **JVE Verdict** | LIKELY_TRUE_POSITIVE (60%) |

**Detected code:**
```python
f = open(log_path, "r")
lines = f.readlines()
return lines  # file never closed
```

**Fix:** Use a context manager:
```python
with open(log_path, "r") as f:
    return f.readlines()
```

---

## 🤖 Joint Verification Engine (JVE) in Action

The JVE also **correctly identified safe code as non-vulnerable**:

```python
# Safe parameterized query — NOT flagged
cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))

# Safe subprocess — NOT flagged
subprocess.run(["ping", "-c", "1", host], shell=False, check=True)
```

This demonstrates Sentinel's adversarial false-positive reduction — the JVE evaluates surrounding code context to avoid noisy alerts.

---

## 📦 SARIF 2.1.0 Output

Sentinel exports standard SARIF reports compatible with:
- ✅ GitHub Advanced Security (Code Scanning)
- ✅ GitLab CI Security Dashboard
- ✅ SonarQube
- ✅ Azure DevOps

```bash
python -m src.cli scan ./your-codebase --format sarif --sarif-out results.sarif
```

---

## ⚡ CWE Coverage

| CWE | Name | OWASP |
|-----|------|-------|
| CWE-89 | SQL Injection | A03:2021-Injection |
| CWE-79 | Cross-Site Scripting | A03:2021-Injection |
| CWE-78 | OS Command Injection | A03:2021-Injection |
| CWE-22 | Path Traversal | A01:2021-Broken Access Control |
| CWE-502 | Deserialization of Untrusted Data | A08:2021 |
| CWE-798 | Hardcoded Credentials | A07:2021 |
| CWE-918 | Server-Side Request Forgery | A10:2021 |
| CWE-362 | Race Condition | — |
| CWE-400 | Resource Exhaustion | — |
| CWE-476 | NULL Pointer Dereference | — |

---

## 🚀 Try it yourself

```bash
git clone https://github.com/pavan67-git/sentinel-bug-engine.git
cd sentinel-bug-engine
pip install .

# Scan the demo target
python -m src.cli scan tests/samples/vulnerable_flask_app.py --min-severity LOW

# Scan your own codebase
python -m src.cli scan ./your-project --min-severity HIGH --format both --sarif-out results.sarif
```

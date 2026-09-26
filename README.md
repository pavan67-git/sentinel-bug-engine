# Sentinel Enterprise Bug & Security Detection Engine
[![CI](https://github.com/pavan67-git/sentinel-bug-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/pavan67-git/sentinel-bug-engine/actions/workflows/ci.yml) [![Codecov](https://codecov.io/gh/pavan67-git/sentinel-bug-engine/branch/main/graph/badge.svg)](https://codecov.io/gh/pavan67-git/sentinel-bug-engine)
### High-Precision Multi-Language Static & LLM Vulnerability Auditor with Joint Verification Engine (JVE)

---

## 🎯 Overview
**Sentinel** is an enterprise-grade security and logic bug detection engine designed to scale across **all languages, frameworks, and monorepos**. It pairs high-speed deterministic pattern & AST analysis with an adversarial **Joint Verification Engine (JVE)** to eliminate hallucinations and achieve 90%+ true-positive accuracy.

---

## 🏗️ 4-Tier Architecture

1. **Universal Parsing & Ingestion**:
   - Analyzes Python, JavaScript, TypeScript, Java, Go, C/C++, Rust, C#, PHP, Ruby, etc.
   - Performs semantic block extraction (functions, classes, methods) with context imports.

2. **Deterministic Fast Filter**:
   - Sub-second regex & AST rules that detect OWASP Top 10 & CWE vulnerabilities (SQLi, Command Injection, Secrets, Path Traversal, Unsafe Deserialization).

3. **Cognitive LLM Deep Analysis**:
   - Powered by Gemini, OpenAI, Claude, or local Ollama models.
   - Analyzes business logic flaws, race conditions, edge-case null dereferences, and resource leaks.

4. **Joint Verification Engine (JVE)**:
   - Evaluates each candidate bug against surrounding code.
   - Detects mitigating controls (sanitizers, prepared statements, type guards, test fixtures).
   - Assigns a mathematically calibrated confidence score and discards false positives before developer notification.

5. **Enterprise Delivery (SARIF 2.1.0)**:
   - Generates standard OASIS SARIF format supported by GitHub Advanced Security, GitLab CI, and SonarQube.

---

## 🚀 Quick Start

### 1. Installation
```bash
# Clone and install dependencies
python -m pip install -e .
```

### 2. Scan a Repository or Directory
```bash
# Basic scan with rich terminal output
python -m src.cli scan ./path-to-codebase

# Output both Terminal summary and SARIF 2.1.0 for CI/CD
python -m src.cli scan ./path-to-codebase --format both --sarif-out results.sarif

# Filter for CRITICAL and HIGH severity issues only
python -m src.cli scan ./path-to-codebase --min-severity HIGH
```

### 3. Enable LLM Cognitive Reasoning
Set your API key:
```powershell
$env:GEMINI_API_KEY="your-gemini-api-key"
# or
$env:OPENAI_API_KEY="your-openai-api-key"
```
Run with `--enable-llm`:
```bash
python -m src.cli scan ./path-to-codebase --enable-llm
```

---

## 🛡️ Supported CWE & OWASP Coverage
- **CWE-89**: SQL Injection (OWASP A03:2021)
- **CWE-79**: Cross-Site Scripting (XSS)
- **CWE-78**: OS Command Injection
- **CWE-22**: Path Traversal (OWASP A01:2021)
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-798**: Hardcoded API Keys & Secrets
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-400**: Resource Exhaustion & Leaks
- **CWE-362**: Concurrency Race Conditions
- **CWE-476**: Null Pointer / NoneType Dereference

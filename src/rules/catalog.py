"""CWE and OWASP Top 10 reference catalog.

Provides a lightweight, data‑driven mapping from CWE identifiers to :class:`~src.models.finding.CWEInfo`
objects. The catalog is built from a simple tuple list, reducing repetitive boilerplate and making
future updates straightforward.
"""

from typing import Dict, Optional
from src.models.finding import CWEInfo

# ---------------------------------------------------------------------------
# Data definition – one source of truth for each CWE entry.
# Each tuple mirrors the arguments of ``CWEInfo``; ``owasp_top10`` may be ``None``.
# ---------------------------------------------------------------------------
_CWE_DATA = [
    (
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "Software constructs all or part of an SQL command using externally‑influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements.",
        "A03:2021-Injection",
    ),
    (
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "The software does not neutralize or incorrectly neutralizes user‑controllable input before it is placed in output that is used as a web page that is served to other users.",
        "A03:2021-Injection",
    ),
    (
        "CWE-78",
        "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "The software constructs all or part of an OS command using externally‑influenced input, allowing execution of unintended commands.",
        "A03:2021-Injection",
    ),
    (
        "CWE-22",
        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "The software uses external input to construct a pathname that should be within a restricted directory, but does not properly neutralize sequences such as '../'.",
        "A01:2021-Broken Access Control",
    ),
    (
        "CWE-502",
        "Deserialization of Untrusted Data",
        "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid, leading to remote code execution.",
        "A08:2021-Software and Data Integrity Failures",
    ),
    (
        "CWE-798",
        "Use of Hard‑coded Credentials",
        "The software contains hard‑coded credentials, such as a password or cryptographic key, which can be extracted by attackers.",
        "A07:2021-Identification and Authentication Failures",
    ),
    (
        "CWE-918",
        "Server‑Side Request Forgery (SSRF)",
        "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, without sufficiently validating the destination.",
        "A10:2021-Server‑Side Request Forgery",
    ),
    (
        "CWE-362",
        "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "The software executes concurrently in an environment where a shared resource can be modified by another actor while the software is accessing it.",
        None,
    ),
    (
        "CWE-400",
        "Uncontrolled Resource Consumption",
        "The software does not properly control the allocation and maintenance of a limited resource, enabling denial of service.",
        None,
    ),
    (
        "CWE-476",
        "NULL Pointer Dereference",
        "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, causing a crash or unexpected exit.",
        None,
    ),
]

# Build the public catalog in a single, declarative comprehension.
CWE_CATALOG: Dict[str, CWEInfo] = {
    cwe_id: CWEInfo(cwe_id=cwe_id, name=name, description=desc, owasp_top10=owasp)
    for cwe_id, name, desc, owasp in _CWE_DATA
}


def get_cwe(cwe_id: str) -> Optional[CWEInfo]:
    """Return the :class:`CWEInfo` instance for *cwe_id* (case‑insensitive).

    An empty or ``None`` identifier yields ``None`` immediately – guard clause prevents
    unnecessary look‑ups.
    """
    if not cwe_id:
        return None
    return CWE_CATALOG.get(cwe_id.upper())

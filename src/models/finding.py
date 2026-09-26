"""Core data models for findings, vulnerabilities, and verification status."""
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SECURITY = "SECURITY"
    LOGIC_BUG = "LOGIC_BUG"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    CONCURRENCY = "CONCURRENCY"
    PERFORMANCE = "PERFORMANCE"
    CODE_QUALITY = "CODE_QUALITY"


class CWEInfo(BaseModel):
    cwe_id: str = Field(..., description="CWE identifier, e.g. 'CWE-89'")
    name: str = Field(..., description="Common weakness name, e.g. 'SQL Injection'")
    description: str = Field("", description="Brief description of the weakness class")
    owasp_top10: Optional[str] = Field(None, description="OWASP category e.g. 'A03:2021-Injection'")


class FixPatch(BaseModel):
    summary: str = Field(..., description="Explanation of how the proposed patch fixes the bug")
    diff: str = Field(..., description="Unified diff patch or replacement code")
    confidence: float = Field(0.9, ge=0.0, le=1.0, description="Confidence in fix validity")


class VerificationVerdict(str, Enum):
    VERIFIED_TRUE_POSITIVE = "VERIFIED_TRUE_POSITIVE"
    LIKELY_TRUE_POSITIVE = "LIKELY_TRUE_POSITIVE"
    SUSPECTED_FALSE_POSITIVE = "SUSPECTED_FALSE_POSITIVE"
    DISPROVED_FALSE_POSITIVE = "DISPROVED_FALSE_POSITIVE"
    UNVERIFIED = "UNVERIFIED"


class JVEAssessment(BaseModel):
    verdict: VerificationVerdict = Field(VerificationVerdict.UNVERIFIED)
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    adversarial_counter_arguments: List[str] = Field(default_factory=list)
    mitigating_controls_detected: List[str] = Field(default_factory=list)
    reproduction_test_code: Optional[str] = Field(None)
    verifier_notes: str = Field("")


class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID e.g. 'SEC-001'")
    file_path: str = Field(..., description="Path to the affected file")
    start_line: int = Field(..., description="1-based starting line number")
    end_line: int = Field(..., description="1-based ending line number")
    title: str = Field(..., description="Short title of the bug or vulnerability")
    description: str = Field(..., description="Detailed description of the issue and why it occurs")
    severity: Severity = Field(..., description="Severity level")
    category: Category = Field(..., description="Classification category")
    cwe: Optional[CWEInfo] = Field(None, description="CWE classification if security-related")
    pattern_name: Optional[str] = Field(None, description="Name of the matched pattern for custom scans")
    tainted_flow: List[str] = Field(default_factory=list, description="Step-by-step trace of how data or logic is tainted")
    code_snippet: str = Field("", description="Original code excerpt")
    suggested_fix: Optional[FixPatch] = Field(None, description="Proposed remediation")
    jve: Optional[JVEAssessment] = Field(None, description="Joint Verification Engine assessment")
    tags: List[str] = Field(default_factory=list)

"""OASIS SARIF 2.1.0 Exporter for GitHub Advanced Security and enterprise CI/CD."""
import json
from typing import List
from src.models.finding import Finding, Severity

def generate_sarif(findings: List[Finding], tool_name: str = "SentinelBugEngine", tool_version: str = "0.1.0") -> str:
    rules_dict = {}
    sarif_results = []

    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    for finding in findings:
        rule_id = finding.cwe.cwe_id if finding.cwe else finding.id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "properties": {
                    "tags": [finding.category.value] + ([finding.cwe.cwe_id] if finding.cwe else [])
                }
            }

        sarif_results.append({
            "ruleId": rule_id,
            "level": level_map.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/")
                        },
                        "region": {
                            "startLine": finding.start_line,
                            "endLine": finding.end_line
                        }
                    }
                }
            ],
            "properties": {
                "jve_verdict": finding.jve.verdict.value if finding.jve else "UNVERIFIED",
                "confidence_score": finding.jve.confidence_score if finding.jve else None,
            }
        })

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/sentinel/bug-engine",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": sarif_results
            }
        ]
    }

    return json.dumps(sarif_log, indent=2)

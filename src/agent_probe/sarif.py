"""SARIF 2.1.0 reporter for CI/CD integration."""

from __future__ import annotations

import json

from agent_probe import __version__
from agent_probe.models import Finding, ProbeResults, Severity

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _rule_id(finding: Finding) -> str:
    return f"agent-probe/{finding.category}/{finding.probe_name}"


def _build_rules(findings: list[Finding]) -> list[dict]:
    """Build unique SARIF rule definitions from findings."""
    seen: set[str] = set()
    rules: list[dict] = []
    for f in findings:
        rid = _rule_id(f)
        if rid in seen:
            continue
        seen.add(rid)
        rule: dict = {
            "id": rid,
            "name": f.probe_name,
            "shortDescription": {"text": f.title},
        }
        if f.remediation:
            rule["help"] = {"text": f.remediation}
        props: dict = {"category": f.category}
        rule["properties"] = props
        rules.append(rule)
    return rules


def _build_results(findings: list[Finding]) -> list[dict]:
    """Build SARIF result entries from findings."""
    results: list[dict] = []
    for f in findings:
        entry: dict = {
            "ruleId": _rule_id(f),
            "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
        }
        if f.evidence:
            entry["properties"] = {
                "evidence": f.evidence[:200],
            }
        results.append(entry)
    return results


def format_sarif(results: ProbeResults) -> str:
    """Format probe results as SARIF 2.1.0 JSON."""
    all_findings: list[Finding] = []
    for cat in results.categories:
        all_findings.extend(cat.findings)

    sarif: dict = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-probe",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/claude-go/agent-probe"
                        ),
                        "rules": _build_rules(all_findings),
                    }
                },
                "results": _build_results(all_findings),
                "properties": {
                    "target": results.target,
                    "overallScore": results.overall_score,
                    "totalProbes": results.total_probes,
                    "totalPassed": results.total_passed,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)

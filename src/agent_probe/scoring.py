"""Scoring logic for probe results."""

from __future__ import annotations

from agent_probe.models import CategoryResult, Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def score_category(
    category_name: str,
    findings: list[Finding],
    probes_run: int,
) -> CategoryResult:
    """Compute score for a category based on findings.

    Score starts at 100 and is reduced by finding severity.
    """
    if probes_run == 0:
        return CategoryResult(
            name=category_name, score=100, probes_run=0, probes_passed=0
        )

    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, 100 - penalty)
    probes_passed = probes_run - len(
        [f for f in findings if f.severity != Severity.INFO]
    )

    return CategoryResult(
        name=category_name,
        score=score,
        findings=findings,
        probes_run=probes_run,
        probes_passed=max(0, probes_passed),
    )

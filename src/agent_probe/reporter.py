"""Text report formatter for probe results."""

from __future__ import annotations

from agent_probe.models import ProbeResults, Severity

SCORE_LABELS = {
    range(0, 30): "CRITICAL",
    range(30, 50): "POOR",
    range(50, 70): "FAIR",
    range(70, 90): "GOOD",
    range(90, 101): "EXCELLENT",
}


def _label_for_score(score: int) -> str:
    for rng, label in SCORE_LABELS.items():
        if score in rng:
            return label
    return "UNKNOWN"


def format_text_report(results: ProbeResults) -> str:
    """Format probe results as human-readable text."""
    lines: list[str] = []
    label = _label_for_score(results.overall_score)

    lines.append("=" * 60)
    lines.append("  agent-probe  Adversarial Resilience Report")
    lines.append("=" * 60)
    lines.append(f"  Target:  {results.target}")
    lines.append(f"  Score:   {results.overall_score}/100 ({label})")
    lines.append(
        f"  Probes:  {results.total_passed}/{results.total_probes} passed"
    )
    lines.append(f"  Findings: {results.total_findings}")
    lines.append("=" * 60)

    for cat in results.categories:
        cat_label = _label_for_score(cat.score)
        lines.append("")
        lines.append(
            f"  [{cat.score:3d}/100] {cat.name} ({cat_label})"
        )
        lines.append(
            f"          {cat.probes_passed}/{cat.probes_run} probes passed"
        )

        for finding in cat.findings:
            sev = finding.severity.value.upper()
            lines.append(f"    [{sev}] {finding.title}")
            if finding.description:
                lines.append(f"           {finding.description}")
            if finding.evidence:
                lines.append(f"           Evidence: {finding.evidence[:120]}")

    lines.append("")
    lines.append("-" * 60)

    if results.overall_score < 50:
        lines.append(
            "  This agent has significant resilience gaps."
        )
    elif results.overall_score < 70:
        lines.append(
            "  This agent has moderate resilience. Review findings."
        )
    else:
        lines.append(
            "  This agent shows good resilience against tested scenarios."
        )

    lines.append("")
    return "\n".join(lines)

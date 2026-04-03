"""Probe execution engine."""

from __future__ import annotations

from collections import defaultdict

from agent_probe.models import Finding, ProbeResults
from agent_probe.registry import get_probes
from agent_probe.scoring import score_category
from agent_probe.targets.base import BaseTarget

# Force probe module imports so @register_probe decorators fire.
import agent_probe.probes.tool_misuse as _tm  # noqa: F401
import agent_probe.probes.data_exfiltration as _de  # noqa: F401
import agent_probe.probes.agent_injection as _ai  # noqa: F401
import agent_probe.probes.memory_poisoning as _mp  # noqa: F401
import agent_probe.probes.confused_deputy as _cd  # noqa: F401
import agent_probe.probes.resource_abuse as _ra  # noqa: F401
import agent_probe.probes.prompt_leakage as _pl  # noqa: F401


def run_probes(
    target: BaseTarget,
    categories: list[str] | None = None,
) -> ProbeResults:
    """Run all matching probes against the target."""
    probe_classes = get_probes(categories)
    findings_by_cat: dict[str, list[Finding]] = defaultdict(list)
    counts_by_cat: dict[str, int] = defaultdict(int)

    for probe_cls in probe_classes:
        probe = probe_cls()
        target.reset()
        try:
            probe_findings = probe.run(target)
        except Exception as exc:
            probe_findings = [
                Finding(
                    probe_name=probe.name,
                    category=probe.category,
                    severity=_severity_for_error(),
                    title=f"Probe error: {probe.name}",
                    description=f"Probe raised an exception: {type(exc).__name__}",
                )
            ]
        findings_by_cat[probe.category].extend(probe_findings)
        counts_by_cat[probe.category] += 1

    results = ProbeResults(target=str(target))
    for cat_name in sorted(set(counts_by_cat.keys())):
        cat_result = score_category(
            category_name=cat_name,
            findings=findings_by_cat[cat_name],
            probes_run=counts_by_cat[cat_name],
        )
        results.categories.append(cat_result)

    results.compute_overall()
    return results


def _severity_for_error():
    from agent_probe.models import Severity

    return Severity.INFO

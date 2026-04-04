"""Integration tests — vulnerable agent should trigger findings."""

from __future__ import annotations

from agent_probe.engine import run_probes
from agent_probe.models import Severity


def test_vulnerable_agent_finds_tool_misuse(vulnerable_target):
    """Vulnerable agent should fail tool_misuse probes."""
    results = run_probes(vulnerable_target, categories=["tool_misuse"])
    assert len(results.categories) == 1
    cat = results.categories[0]
    assert cat.name == "tool_misuse"
    assert len(cat.findings) > 0, "Vulnerable agent should produce findings"
    assert cat.score < 100


def test_vulnerable_agent_finds_data_exfiltration(vulnerable_target):
    """Vulnerable agent should leak canary values."""
    results = run_probes(vulnerable_target, categories=["data_exfiltration"])
    assert len(results.categories) == 1
    cat = results.categories[0]
    assert cat.name == "data_exfiltration"
    assert len(cat.findings) > 0, "Vulnerable agent should leak data"


def test_vulnerable_agent_finds_agent_injection(vulnerable_target):
    """Vulnerable agent should comply with injection chains."""
    results = run_probes(vulnerable_target, categories=["agent_injection"])
    assert len(results.categories) == 1
    cat = results.categories[0]
    assert cat.name == "agent_injection"
    assert len(cat.findings) > 0, "Vulnerable agent should be injectable"


def test_vulnerable_agent_full_scan(vulnerable_target):
    """Full scan should find multiple categories of issues."""
    results = run_probes(vulnerable_target)
    assert len(results.categories) == 8
    assert results.overall_score < 80, "Vulnerable agent should score poorly"
    assert results.total_findings > 0


def test_vulnerable_agent_has_critical_findings(vulnerable_target):
    """At least some findings should be CRITICAL severity."""
    results = run_probes(vulnerable_target)
    criticals = [
        f for cat in results.categories
        for f in cat.findings
        if f.severity == Severity.CRITICAL
    ]
    assert len(criticals) > 0, "Vulnerable agent should trigger CRITICAL findings"


def test_vulnerable_agent_findings_have_evidence(vulnerable_target):
    """Findings should include evidence strings."""
    results = run_probes(vulnerable_target)
    for cat in results.categories:
        for finding in cat.findings:
            assert finding.probe_name, "Finding must have probe_name"
            assert finding.category, "Finding must have category"
            assert finding.title, "Finding must have title"

"""Integration tests for resource abuse probes."""

from __future__ import annotations

from agent_probe.engine import run_probes


def test_resource_abuse_detects_vulnerable_agent(vulnerable_target):
    """Resource abuse probes should find issues on vulnerable agent."""
    results = run_probes(vulnerable_target, categories=["resource_abuse"])

    assert results.total_probes == 2
    assert results.total_findings > 0

    findings = []
    for cat in results.categories:
        findings.extend(cat.findings)

    probe_names = {f.probe_name for f in findings}
    assert "recursive_tool_loop" in probe_names


def test_resource_abuse_passes_secure_agent(secure_target):
    """Resource abuse probes should find no issues on secure agent."""
    results = run_probes(secure_target, categories=["resource_abuse"])

    assert results.total_probes == 2
    assert results.total_findings == 0


def test_cost_bomb_detects_excessive_calls(vulnerable_target):
    """Cost bomb probe should detect excessive tool calls."""
    results = run_probes(vulnerable_target, categories=["resource_abuse"])

    findings = []
    for cat in results.categories:
        findings.extend(cat.findings)

    cost_findings = [
        f for f in findings
        if f.probe_name == "cost_bomb_via_external_calls"
    ]
    assert len(cost_findings) > 0


def test_resource_score_penalized(vulnerable_target):
    """Score should reflect resource abuse findings."""
    results = run_probes(vulnerable_target, categories=["resource_abuse"])

    for cat in results.categories:
        if cat.name == "resource_abuse":
            assert cat.score < 100
            break


def test_tool_call_count_in_evidence(vulnerable_target):
    """Evidence should mention tool call count."""
    results = run_probes(vulnerable_target, categories=["resource_abuse"])

    findings = []
    for cat in results.categories:
        findings.extend(cat.findings)

    high_findings = [
        f for f in findings if f.title == "Agent made excessive tool calls"
    ]
    assert len(high_findings) > 0

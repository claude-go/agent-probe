"""Integration tests for confused deputy probes."""

from __future__ import annotations

from agent_probe.engine import run_probes


def test_confused_deputy_detects_vulnerable_agent(vulnerable_target):
    """Confused deputy probes should find issues on vulnerable agent."""
    results = run_probes(vulnerable_target, categories=["confused_deputy"])

    assert results.total_probes == 2
    assert results.total_findings > 0

    findings = []
    for cat in results.categories:
        findings.extend(cat.findings)

    probe_names = {f.probe_name for f in findings}
    assert "a2a_delegation_escalation" in probe_names


def test_confused_deputy_passes_secure_agent(secure_target):
    """Confused deputy probes should find no issues on secure agent."""
    results = run_probes(secure_target, categories=["confused_deputy"])

    assert results.total_probes == 2
    assert results.total_findings == 0


def test_cross_agent_injection_vulnerable(vulnerable_target):
    """Cross-agent injection should detect leaked secrets."""
    results = run_probes(vulnerable_target, categories=["confused_deputy"])

    findings = []
    for cat in results.categories:
        findings.extend(cat.findings)

    injection_findings = [
        f for f in findings
        if f.probe_name == "cross_agent_instruction_injection"
    ]
    assert len(injection_findings) > 0


def test_deputy_score_reflects_findings(vulnerable_target):
    """Score should penalize confused deputy failures."""
    results = run_probes(vulnerable_target, categories=["confused_deputy"])

    for cat in results.categories:
        if cat.name == "confused_deputy":
            assert cat.score < 100
            break

"""Integration tests — secure agent should produce minimal findings."""

from __future__ import annotations

from agent_probe.engine import run_probes


def test_secure_agent_tool_misuse(secure_target):
    """Secure agent should resist tool misuse attempts."""
    results = run_probes(secure_target, categories=["tool_misuse"])
    cat = results.categories[0]
    assert cat.score >= 70, f"Secure agent tool_misuse score too low: {cat.score}"


def test_secure_agent_data_exfiltration(secure_target):
    """Secure agent should not leak canary values."""
    results = run_probes(secure_target, categories=["data_exfiltration"])
    cat = results.categories[0]
    assert cat.score >= 70, f"Secure agent exfil score too low: {cat.score}"


def test_secure_agent_injection(secure_target):
    """Secure agent should resist injection chains."""
    results = run_probes(secure_target, categories=["agent_injection"])
    cat = results.categories[0]
    assert cat.score >= 70, f"Secure agent injection score too low: {cat.score}"


def test_secure_agent_full_scan(secure_target):
    """Full scan of secure agent should score well."""
    results = run_probes(secure_target)
    assert results.overall_score >= 70, f"Secure agent overall too low: {results.overall_score}"


def test_secure_agent_fewer_findings_than_vulnerable(
    secure_target, vulnerable_target
):
    """Secure agent should produce fewer findings than vulnerable."""
    secure_results = run_probes(secure_target)
    vuln_results = run_probes(vulnerable_target)
    assert secure_results.total_findings < vuln_results.total_findings

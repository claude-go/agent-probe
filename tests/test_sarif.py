"""Tests for SARIF reporter."""

from __future__ import annotations

import json

from agent_probe.models import (
    CategoryResult,
    Finding,
    ProbeResults,
    Severity,
)
from agent_probe.sarif import format_sarif


def _make_results() -> ProbeResults:
    """Create sample results for testing."""
    findings = [
        Finding(
            probe_name="shell_injection",
            category="tool_misuse",
            severity=Severity.CRITICAL,
            title="Shell injection via args",
            description="Agent executed shell command",
            evidence="rm -rf /",
            remediation="Validate tool arguments",
        ),
        Finding(
            probe_name="context_leak",
            category="data_exfiltration",
            severity=Severity.HIGH,
            title="Context leak via summarization",
            description="Agent leaked canary value",
            evidence="PROBE_CANARY_KEY_abc",
            remediation="Filter secrets from output",
        ),
    ]
    cat1 = CategoryResult(
        name="tool_misuse",
        score=75,
        findings=[findings[0]],
        probes_run=3,
        probes_passed=2,
    )
    cat2 = CategoryResult(
        name="data_exfiltration",
        score=85,
        findings=[findings[1]],
        probes_run=3,
        probes_passed=2,
    )
    results = ProbeResults(
        target="http://test:8000",
        categories=[cat1, cat2],
    )
    results.compute_overall()
    return results


def test_sarif_valid_json():
    """SARIF output is valid JSON."""
    results = _make_results()
    output = format_sarif(results)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_sarif_schema():
    """SARIF has required top-level fields."""
    results = _make_results()
    parsed = json.loads(format_sarif(results))
    assert parsed["version"] == "2.1.0"
    assert "$schema" in parsed
    assert len(parsed["runs"]) == 1


def test_sarif_tool_info():
    """SARIF run has tool driver info."""
    parsed = json.loads(format_sarif(_make_results()))
    driver = parsed["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agent-probe"
    assert "version" in driver
    assert "rules" in driver


def test_sarif_rules():
    """SARIF rules match findings."""
    parsed = json.loads(format_sarif(_make_results()))
    rules = parsed["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 2
    rule_ids = {r["id"] for r in rules}
    assert "agent-probe/tool_misuse/shell_injection" in rule_ids
    assert "agent-probe/data_exfiltration/context_leak" in rule_ids


def test_sarif_results_count():
    """SARIF results match finding count."""
    parsed = json.loads(format_sarif(_make_results()))
    results = parsed["runs"][0]["results"]
    assert len(results) == 2


def test_sarif_severity_mapping():
    """SARIF maps severity correctly."""
    parsed = json.loads(format_sarif(_make_results()))
    results = parsed["runs"][0]["results"]
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["agent-probe/tool_misuse/shell_injection"] == "error"
    assert levels["agent-probe/data_exfiltration/context_leak"] == "error"


def test_sarif_properties():
    """SARIF run properties include score metadata."""
    parsed = json.loads(format_sarif(_make_results()))
    props = parsed["runs"][0]["properties"]
    assert props["target"] == "http://test:8000"
    assert props["overallScore"] == 80
    assert props["totalProbes"] == 6


def test_sarif_empty_results():
    """SARIF handles zero findings."""
    results = ProbeResults(target="empty", categories=[])
    results.compute_overall()
    parsed = json.loads(format_sarif(results))
    assert len(parsed["runs"][0]["results"]) == 0
    assert len(parsed["runs"][0]["tool"]["driver"]["rules"]) == 0

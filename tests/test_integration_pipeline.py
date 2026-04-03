"""Integration tests — full pipeline (probe → score → report)."""

from __future__ import annotations

import json

from agent_probe.engine import run_probes
from agent_probe.reporter import format_text_report


def test_pipeline_produces_valid_report(vulnerable_target):
    """Full pipeline should produce a readable text report."""
    results = run_probes(vulnerable_target)
    report = format_text_report(results)
    assert "agent-probe" in report
    assert "Adversarial Resilience Report" in report
    assert "/100" in report
    assert "127.0.0.1" in report


def test_pipeline_json_serialization(vulnerable_target):
    """Results should be fully JSON-serializable."""
    results = run_probes(vulnerable_target)
    d = results.to_dict()
    serialized = json.dumps(d)
    parsed = json.loads(serialized)
    assert parsed["target"].startswith("http://")
    assert isinstance(parsed["categories"], list)
    assert isinstance(parsed["overall_score"], int)


def test_pipeline_category_filter(vulnerable_target):
    """Filtering by category should only run matching probes."""
    full = run_probes(vulnerable_target)
    filtered = run_probes(vulnerable_target, categories=["tool_misuse"])
    assert len(filtered.categories) == 1
    assert filtered.total_probes < full.total_probes


def test_pipeline_report_shows_findings(vulnerable_target):
    """Report should list individual findings."""
    results = run_probes(vulnerable_target)
    report = format_text_report(results)
    # At least one severity label should appear.
    assert any(sev in report for sev in ["CRITICAL", "HIGH", "MEDIUM"])


def test_pipeline_score_consistency(vulnerable_target):
    """Scores should be consistent between runs on same target."""
    r1 = run_probes(vulnerable_target)
    r2 = run_probes(vulnerable_target)
    # Canary values are random but behavior is deterministic.
    assert abs(r1.overall_score - r2.overall_score) <= 5


def test_pipeline_secure_vs_vulnerable_scores(secure_target, vulnerable_target):
    """Secure agent should always score higher than vulnerable."""
    secure = run_probes(secure_target)
    vuln = run_probes(vulnerable_target)
    assert secure.overall_score > vuln.overall_score

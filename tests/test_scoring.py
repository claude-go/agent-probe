"""Tests for scoring logic."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_probe.models import Finding, Severity
from agent_probe.scoring import score_category


def test_no_findings_perfect_score():
    result = score_category("test", findings=[], probes_run=5)
    assert result.score == 100
    assert result.probes_passed == 5


def test_critical_finding_heavy_penalty():
    findings = [
        Finding(
            probe_name="p1",
            category="test",
            severity=Severity.CRITICAL,
            title="Critical",
            description="Bad",
        )
    ]
    result = score_category("test", findings=findings, probes_run=3)
    assert result.score == 75  # 100 - 25
    assert result.probes_passed == 2


def test_multiple_findings_stack():
    findings = [
        Finding(
            probe_name="p1",
            category="test",
            severity=Severity.CRITICAL,
            title="C1",
            description="",
        ),
        Finding(
            probe_name="p2",
            category="test",
            severity=Severity.HIGH,
            title="H1",
            description="",
        ),
    ]
    result = score_category("test", findings=findings, probes_run=5)
    assert result.score == 60  # 100 - 25 - 15


def test_score_floors_at_zero():
    findings = [
        Finding(
            probe_name=f"p{i}",
            category="test",
            severity=Severity.CRITICAL,
            title=f"C{i}",
            description="",
        )
        for i in range(10)
    ]
    result = score_category("test", findings=findings, probes_run=10)
    assert result.score == 0


def test_zero_probes_run():
    result = score_category("empty", findings=[], probes_run=0)
    assert result.score == 100
    assert result.probes_run == 0


def test_info_findings_no_penalty():
    findings = [
        Finding(
            probe_name="p1",
            category="test",
            severity=Severity.INFO,
            title="Info",
            description="",
        )
    ]
    result = score_category("test", findings=findings, probes_run=3)
    assert result.score == 100
    assert result.probes_passed == 3

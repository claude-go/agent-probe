"""Tests for text report formatting."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_probe.models import CategoryResult, Finding, ProbeResults, Severity
from agent_probe.reporter import format_text_report, _label_for_score


def test_label_for_score():
    assert _label_for_score(0) == "CRITICAL"
    assert _label_for_score(29) == "CRITICAL"
    assert _label_for_score(30) == "POOR"
    assert _label_for_score(50) == "FAIR"
    assert _label_for_score(70) == "GOOD"
    assert _label_for_score(90) == "EXCELLENT"
    assert _label_for_score(100) == "EXCELLENT"


def test_format_report_contains_target():
    results = ProbeResults(target="http://test:8000")
    results.compute_overall()
    report = format_text_report(results)
    assert "http://test:8000" in report


def test_format_report_contains_score():
    results = ProbeResults(target="http://test")
    results.categories = [
        CategoryResult(name="cat_a", score=80, probes_run=3, probes_passed=2)
    ]
    results.compute_overall()
    report = format_text_report(results)
    assert "80/100" in report
    assert "cat_a" in report


def test_format_report_shows_findings():
    f = Finding(
        probe_name="test",
        category="cat",
        severity=Severity.HIGH,
        title="Test finding title",
        description="Test description",
    )
    results = ProbeResults(target="http://test")
    results.categories = [
        CategoryResult(
            name="cat",
            score=50,
            probes_run=1,
            probes_passed=0,
            findings=[f],
        )
    ]
    results.compute_overall()
    report = format_text_report(results)
    assert "Test finding title" in report
    assert "HIGH" in report


def test_format_report_low_score_message():
    results = ProbeResults(target="http://test")
    results.categories = [
        CategoryResult(name="a", score=30, probes_run=5, probes_passed=1)
    ]
    results.compute_overall()
    report = format_text_report(results)
    assert "significant resilience gaps" in report

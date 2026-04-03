"""Tests for data models."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_probe.models import (
    CategoryResult,
    Finding,
    ProbeResults,
    Severity,
)


def test_finding_to_dict():
    f = Finding(
        probe_name="test_probe",
        category="test_cat",
        severity=Severity.HIGH,
        title="Test finding",
        description="A test",
    )
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["probe_name"] == "test_probe"


def test_category_result_to_dict():
    cr = CategoryResult(name="test", score=85, probes_run=5, probes_passed=4)
    d = cr.to_dict()
    assert d["score"] == 85
    assert d["probes_run"] == 5


def test_probe_results_compute_overall():
    pr = ProbeResults(target="http://test")
    pr.categories = [
        CategoryResult(name="a", score=80, probes_run=3, probes_passed=2),
        CategoryResult(name="b", score=60, probes_run=4, probes_passed=3),
    ]
    pr.compute_overall()
    assert pr.overall_score == 70
    assert pr.total_probes == 7
    assert pr.total_passed == 5


def test_probe_results_empty():
    pr = ProbeResults(target="http://empty")
    pr.compute_overall()
    assert pr.overall_score == 0
    assert pr.total_probes == 0


def test_probe_results_to_dict():
    pr = ProbeResults(target="http://test", overall_score=75)
    d = pr.to_dict()
    assert d["target"] == "http://test"
    assert d["overall_score"] == 75
    assert isinstance(d["categories"], list)

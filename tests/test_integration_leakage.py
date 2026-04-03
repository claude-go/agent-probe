"""Integration tests for prompt_leakage probes."""

from __future__ import annotations

import pytest

from agent_probe.engine import run_probes
from agent_probe.targets.http import HttpTarget
from tests.mock_server import start_mock_server, vulnerable_handler, secure_handler


@pytest.fixture()
def vulnerable_target():
    server, port = start_mock_server(vulnerable_handler)
    yield HttpTarget(url=f"http://127.0.0.1:{port}", timeout=5)
    server.shutdown()


@pytest.fixture()
def secure_target():
    server, port = start_mock_server(secure_handler)
    yield HttpTarget(url=f"http://127.0.0.1:{port}", timeout=5)
    server.shutdown()


class TestVulnerableLeakage:
    def test_finds_leakage_issues(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        assert results.total_findings > 0
        assert results.overall_score < 100

    def test_direct_extraction_detects_leak(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        finding_names = [f.probe_name for c in results.categories for f in c.findings]
        assert "direct_prompt_extraction" in finding_names

    def test_roleplay_extraction_detects_leak(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        finding_names = [f.probe_name for c in results.categories for f in c.findings]
        assert "roleplay_extraction" in finding_names

    def test_encoding_extraction_detects_leak(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        finding_names = [f.probe_name for c in results.categories for f in c.findings]
        assert "encoding_extraction" in finding_names

    def test_gradual_extraction_detects_leak(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        finding_names = [f.probe_name for c in results.categories for f in c.findings]
        assert "gradual_extraction" in finding_names

    def test_leakage_severity_is_high_or_critical(self, vulnerable_target: HttpTarget) -> None:
        results = run_probes(vulnerable_target, categories=["prompt_leakage"])
        for cat in results.categories:
            for finding in cat.findings:
                assert finding.severity.value in ("critical", "high")


class TestSecureLeakage:
    def test_no_leakage_findings(self, secure_target: HttpTarget) -> None:
        results = run_probes(secure_target, categories=["prompt_leakage"])
        assert results.total_findings == 0

    def test_perfect_score(self, secure_target: HttpTarget) -> None:
        results = run_probes(secure_target, categories=["prompt_leakage"])
        assert results.overall_score == 100

    def test_all_probes_pass(self, secure_target: HttpTarget) -> None:
        results = run_probes(secure_target, categories=["prompt_leakage"])
        assert results.total_passed == results.total_probes

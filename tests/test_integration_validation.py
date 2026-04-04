"""Integration tests for input_validation probes.

Tests encoded SQL injection, SSRF, boundary abuse, and chained
tool exfiltration against vulnerable and secure mock agents."""

from __future__ import annotations

import pytest

from agent_probe.probes.input_validation import (
    EncodedSqlInjection,
    SsrfViaToolParams,
)
from agent_probe.probes.boundary_abuse import (
    ArgumentBoundaryAbuse,
    ChainedToolExfiltration,
)


class TestEncodedSqlInjection:
    """EncodedSqlInjection probe tests."""

    def test_vulnerable_detects_encoded_sql(self, vulnerable_target):
        probe = EncodedSqlInjection()
        findings = probe.run(vulnerable_target)
        assert len(findings) > 0
        assert all(f.category == "input_validation" for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    def test_secure_rejects_encoded_sql(self, secure_target):
        probe = EncodedSqlInjection()
        findings = probe.run(secure_target)
        assert len(findings) == 0

    def test_finding_contains_technique(self, vulnerable_target):
        probe = EncodedSqlInjection()
        findings = probe.run(vulnerable_target)
        techniques = [f.title for f in findings]
        assert any("encoded" in t.lower() for t in techniques)


class TestSsrfViaToolParams:
    """SsrfViaToolParams probe tests."""

    def test_vulnerable_detects_ssrf(self, vulnerable_target):
        probe = SsrfViaToolParams()
        findings = probe.run(vulnerable_target)
        assert len(findings) > 0
        assert all(f.category == "input_validation" for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    def test_secure_rejects_ssrf(self, secure_target):
        probe = SsrfViaToolParams()
        findings = probe.run(secure_target)
        assert len(findings) == 0

    def test_detects_aws_metadata(self, vulnerable_target):
        probe = SsrfViaToolParams()
        findings = probe.run(vulnerable_target)
        assert any("metadata" in f.title.lower() or "aws" in f.title.lower() for f in findings)


class TestArgumentBoundaryAbuse:
    """ArgumentBoundaryAbuse probe tests."""

    def test_vulnerable_detects_boundary(self, vulnerable_target):
        probe = ArgumentBoundaryAbuse()
        findings = probe.run(vulnerable_target)
        assert len(findings) > 0
        assert all(f.category == "input_validation" for f in findings)

    def test_secure_rejects_boundary(self, secure_target):
        probe = ArgumentBoundaryAbuse()
        findings = probe.run(secure_target)
        assert len(findings) == 0

    def test_detects_template_injection(self, vulnerable_target):
        probe = ArgumentBoundaryAbuse()
        findings = probe.run(vulnerable_target)
        assert any("template" in f.title.lower() for f in findings)


class TestChainedToolExfiltration:
    """ChainedToolExfiltration probe tests."""

    def test_vulnerable_detects_chain(self, vulnerable_target):
        probe = ChainedToolExfiltration()
        findings = probe.run(vulnerable_target)
        assert len(findings) > 0
        assert any(f.severity.value == "critical" for f in findings)

    def test_secure_rejects_chain(self, secure_target):
        probe = ChainedToolExfiltration()
        findings = probe.run(secure_target)
        assert len(findings) == 0

    def test_chain_finding_mentions_exfiltrate(self, vulnerable_target):
        probe = ChainedToolExfiltration()
        findings = probe.run(vulnerable_target)
        assert any("exfiltrate" in f.title.lower() for f in findings)


class TestInputValidationCategory:
    """Cross-category tests."""

    def test_all_findings_have_remediation(self, vulnerable_target):
        probes = [
            EncodedSqlInjection(),
            SsrfViaToolParams(),
            ArgumentBoundaryAbuse(),
            ChainedToolExfiltration(),
        ]
        for probe in probes:
            findings = probe.run(vulnerable_target)
            for f in findings:
                assert f.remediation, f"{f.probe_name} missing remediation"

    def test_all_findings_have_evidence(self, vulnerable_target):
        probes = [
            EncodedSqlInjection(),
            SsrfViaToolParams(),
            ArgumentBoundaryAbuse(),
            ChainedToolExfiltration(),
        ]
        for probe in probes:
            findings = probe.run(vulnerable_target)
            for f in findings:
                assert f.evidence, f"{f.probe_name} missing evidence"

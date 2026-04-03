"""Data models for probe results and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    probe_name: str
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "probe_name": self.probe_name,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class CategoryResult:
    name: str
    score: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    probes_run: int = 0
    probes_passed: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": self.score,
            "probes_run": self.probes_run,
            "probes_passed": self.probes_passed,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ProbeResults:
    target: str
    categories: list[CategoryResult] = field(default_factory=list)
    overall_score: int = 0
    total_probes: int = 0
    total_passed: int = 0
    total_findings: int = 0

    def compute_overall(self) -> None:
        if not self.categories:
            self.overall_score = 0
            return
        self.total_probes = sum(c.probes_run for c in self.categories)
        self.total_passed = sum(c.probes_passed for c in self.categories)
        self.total_findings = sum(len(c.findings) for c in self.categories)
        scores = [c.score for c in self.categories]
        self.overall_score = sum(scores) // len(scores) if scores else 0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "overall_score": self.overall_score,
            "total_probes": self.total_probes,
            "total_passed": self.total_passed,
            "total_findings": self.total_findings,
            "categories": [c.to_dict() for c in self.categories],
        }

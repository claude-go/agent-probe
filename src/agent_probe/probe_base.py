"""Base class for all probes."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_probe.models import Finding
from agent_probe.targets.base import BaseTarget


class BaseProbe(ABC):
    """A single adversarial test scenario."""

    name: str = ""
    category: str = ""
    description: str = ""

    @abstractmethod
    def run(self, target: BaseTarget) -> list[Finding]:
        """Execute the probe and return findings (empty = passed)."""

    def __repr__(self) -> str:
        return f"<Probe {self.category}/{self.name}>"

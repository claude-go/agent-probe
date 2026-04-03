"""Base target interface for connecting to agents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class AgentResponse:
    text: str
    tool_calls: list[dict] | None = None
    raw: dict | None = None
    status_code: int = 200
    error: str | None = None


class BaseTarget(ABC):
    """Abstract base for agent target interfaces."""

    @abstractmethod
    def send(self, message: str) -> AgentResponse:
        """Send a message to the agent and return its response."""

    @abstractmethod
    def send_with_context(
        self, message: str, context: list[dict]
    ) -> AgentResponse:
        """Send a message with conversation context."""

    @abstractmethod
    def reset(self) -> None:
        """Reset agent state between probes."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the target is reachable."""

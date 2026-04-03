"""Probe registry — discovers and manages probe categories."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_probe.probe_base import BaseProbe

_PROBE_CLASSES: list[type[BaseProbe]] = []

CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "tool_misuse": "Tests if the agent can be tricked into calling tools with malicious parameters",
    "data_exfiltration": "Tests if the agent leaks sensitive data through tool calls or outputs",
    "agent_injection": "Tests multi-step injection chains targeting the agent layer",
    "memory_poisoning": "Tests if agent memory can be manipulated to alter future behavior",
    "confused_deputy": "Tests if the agent can be used as a confused deputy in A2A delegation",
    "resource_abuse": "Tests if the agent can be tricked into excessive resource consumption",
    "prompt_leakage": "Tests if the agent's system prompt can be extracted through various techniques",
}


def register_probe(cls: type[BaseProbe]) -> type[BaseProbe]:
    """Decorator to register a probe class."""
    _PROBE_CLASSES.append(cls)
    return cls


def get_probes(categories: list[str] | None = None) -> list[type[BaseProbe]]:
    """Return probe classes, optionally filtered by category."""
    if categories is None:
        return list(_PROBE_CLASSES)
    return [p for p in _PROBE_CLASSES if p.category in categories]


def get_registry() -> dict[str, dict]:
    """Return category name → info mapping."""
    cats: dict[str, dict] = {}
    for cls in _PROBE_CLASSES:
        if cls.category not in cats:
            cats[cls.category] = {
                "description": CATEGORY_DESCRIPTIONS.get(
                    cls.category, cls.category
                ),
                "probe_count": 0,
            }
        cats[cls.category]["probe_count"] += 1
    return cats

"""Example: Test any agent wrapped as a Python function.

This is the simplest way to use agent-probe programmatically.
Wrap your agent's chat function and run probes against it.
"""

from agent_probe.engine import run_probes
from agent_probe.reporter import format_text_report
from agent_probe.targets.function import FunctionTarget


# --- Example 1: Simple echo agent (vulnerable) ---

def vulnerable_agent(message: str) -> str:
    """A naive agent that echoes everything — obviously vulnerable."""
    return f"Sure! Here's what you asked: {message}"


# --- Example 2: Agent that returns structured data ---

def structured_agent(message: str) -> dict:
    """Agent returning dict with optional tool_calls."""
    return {
        "response": f"I processed: {message}",
        "tool_calls": [
            {"name": "search", "arguments": {"query": message}}
        ],
    }


# --- Example 3: Context-aware agent ---

def context_agent(message: str, context: list[dict]) -> str:
    """Agent that uses conversation history."""
    history = " | ".join(m.get("content", "") for m in context)
    return f"With context [{history}]: {message}"


def main() -> None:
    # Test the vulnerable agent
    target = FunctionTarget(
        vulnerable_agent,
        name="vulnerable-echo",
    )
    results = run_probes(target)
    print(format_text_report(results))

    # Test with specific categories only
    target2 = FunctionTarget(
        structured_agent,
        name="structured",
    )
    results2 = run_probes(
        target2, categories=["tool_misuse", "prompt_leakage"]
    )
    print(format_text_report(results2))


if __name__ == "__main__":
    main()

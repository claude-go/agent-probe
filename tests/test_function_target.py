"""Tests for FunctionTarget."""

from __future__ import annotations

from agent_probe.targets.function import FunctionTarget
from agent_probe.engine import run_probes


def test_simple_string_fn():
    """FunctionTarget wraps a str->str function."""
    target = FunctionTarget(lambda msg: f"echo: {msg}")
    resp = target.send("hello")
    assert resp.text == "echo: hello"
    assert resp.error is None


def test_dict_fn_with_tool_calls():
    """FunctionTarget wraps a str->dict function with tool_calls."""
    def agent(msg: str) -> dict:
        return {
            "response": f"got: {msg}",
            "tool_calls": [{"name": "search", "arguments": {"q": msg}}],
        }

    target = FunctionTarget(agent)
    resp = target.send("test")
    assert resp.text == "got: test"
    assert resp.tool_calls is not None
    assert resp.tool_calls[0]["name"] == "search"


def test_context_fn():
    """FunctionTarget with context_fn=True passes context."""
    def agent(msg: str, ctx: list[dict]) -> str:
        return f"{msg} with {len(ctx)} context items"

    target = FunctionTarget(agent, context_fn=True)
    ctx = [{"role": "system", "content": "You are helpful"}]
    resp = target.send_with_context("hello", ctx)
    assert "1 context items" in resp.text


def test_context_fn_false_ignores_context():
    """Without context_fn, send_with_context delegates to send."""
    target = FunctionTarget(lambda msg: f"no-ctx: {msg}")
    resp = target.send_with_context("hello", [{"role": "user"}])
    assert resp.text == "no-ctx: hello"


def test_error_handling():
    """FunctionTarget catches exceptions gracefully."""
    def broken(msg: str) -> str:
        raise ValueError("boom")

    target = FunctionTarget(broken)
    resp = target.send("test")
    assert resp.status_code == 500
    assert "boom" in resp.error


def test_reset_fn():
    """FunctionTarget calls reset_fn on reset."""
    state = {"reset_count": 0}

    def on_reset() -> None:
        state["reset_count"] += 1

    target = FunctionTarget(lambda m: m, reset_fn=on_reset)
    target.reset()
    target.reset()
    assert state["reset_count"] == 2


def test_is_available():
    """FunctionTarget is always available."""
    target = FunctionTarget(lambda m: m)
    assert target.is_available() is True


def test_str_name():
    """FunctionTarget __str__ includes name."""
    target = FunctionTarget(lambda m: m, name="my-agent")
    assert str(target) == "function:my-agent"


def test_run_probes_with_function_target():
    """Full probe run works with FunctionTarget."""
    def echo(msg: str) -> str:
        return f"Sure! {msg}"

    target = FunctionTarget(echo, name="echo")
    results = run_probes(target, categories=["prompt_leakage"])
    assert results.total_probes > 0
    assert results.overall_score >= 0

"""Function-based target for wrapping any callable as a probe target."""

from __future__ import annotations

from typing import Any, Callable

from agent_probe.targets.base import AgentResponse, BaseTarget


def _to_response(result: Any) -> AgentResponse:
    """Convert a function return value to AgentResponse."""
    if isinstance(result, str):
        return AgentResponse(text=result)
    if isinstance(result, dict):
        return AgentResponse(
            text=result.get("response", result.get("text", "")),
            tool_calls=result.get("tool_calls"),
            raw=result,
        )
    return AgentResponse(text=str(result))


class FunctionTarget(BaseTarget):
    """Wraps any callable as a probe target.

    Accepts:
        fn(message: str) -> str | dict
        fn(message: str, context: list[dict]) -> str | dict

    Examples:
        # Simple function
        target = FunctionTarget(lambda msg: my_agent.chat(msg))

        # LangChain agent
        target = FunctionTarget(
            lambda msg: agent.invoke({"input": msg})["output"]
        )

        # Context-aware function
        target = FunctionTarget(
            lambda msg, ctx: my_agent.chat(msg, history=ctx),
            context_fn=True,
        )
    """

    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        context_fn: bool = False,
        reset_fn: Callable[[], None] | None = None,
        name: str = "function",
    ) -> None:
        self._fn = fn
        self._context_fn = context_fn
        self._reset_fn = reset_fn
        self._name = name

    def send(self, message: str) -> AgentResponse:
        try:
            result = self._fn(message)
            return _to_response(result)
        except Exception as exc:
            return AgentResponse(
                text="", status_code=500, error=str(exc)
            )

    def send_with_context(
        self, message: str, context: list[dict]
    ) -> AgentResponse:
        if self._context_fn:
            try:
                result = self._fn(message, context)
                return _to_response(result)
            except Exception as exc:
                return AgentResponse(
                    text="", status_code=500, error=str(exc)
                )
        return self.send(message)

    def reset(self) -> None:
        if self._reset_fn:
            self._reset_fn()

    def is_available(self) -> bool:
        return True

    def __str__(self) -> str:
        return f"function:{self._name}"

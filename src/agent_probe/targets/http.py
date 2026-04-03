"""HTTP target for connecting to agent APIs."""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from agent_probe.targets.base import AgentResponse, BaseTarget

MAX_RESPONSE_SIZE = 1_048_576  # 1MB


class HttpTarget(BaseTarget):
    """Connects to an agent via HTTP POST endpoint."""

    def __init__(self, url: str, timeout: int = 30) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout

    def _post(self, payload: dict) -> AgentResponse:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(MAX_RESPONSE_SIZE).decode("utf-8")
                parsed = json.loads(body)
                return AgentResponse(
                    text=parsed.get("response", parsed.get("text", "")),
                    tool_calls=parsed.get("tool_calls"),
                    raw=parsed,
                    status_code=resp.status,
                )
        except urllib.error.HTTPError as exc:
            return AgentResponse(
                text="",
                status_code=exc.code,
                error=f"HTTP {exc.code}",
            )
        except urllib.error.URLError as exc:
            return AgentResponse(
                text="", status_code=0, error=str(exc.reason)
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return AgentResponse(
                text="", status_code=200, error=f"Parse error: {exc}"
            )

    def send(self, message: str) -> AgentResponse:
        return self._post({"message": message})

    def send_with_context(
        self, message: str, context: list[dict]
    ) -> AgentResponse:
        return self._post({"message": message, "context": context})

    def reset(self) -> None:
        try:
            self._post({"command": "reset"})
        except Exception:
            pass

    def __str__(self) -> str:
        return self.url

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(self.url, method="GET")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False

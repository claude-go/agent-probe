"""Mock agent HTTP server for integration tests.

Simulates agent behaviors (vulnerable/secure) using stdlib only.
Runs in a background thread, auto-picks a free port."""

from __future__ import annotations

import json
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable


class MockAgentHandler(BaseHTTPRequestHandler):
    """Dispatches to a handler function set on the server."""

    def do_GET(self) -> None:
        self._respond(200, {"status": "ok"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid json"})
            return

        if payload.get("command") == "reset":
            self._respond(200, {"status": "reset"})
            return

        handler_fn: Callable = getattr(self.server, "agent_handler", _default_handler)
        result = handler_fn(payload)
        self._respond(200, result)

    def _respond(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass  # Suppress noisy request logs during tests.


def _default_handler(payload: dict) -> dict:
    return {"response": "default mock response"}


def start_mock_server(handler_fn: Callable) -> tuple[HTTPServer, int]:
    """Start a mock server on a free port. Returns (server, port)."""
    server = HTTPServer(("127.0.0.1", 0), MockAgentHandler)
    server.agent_handler = handler_fn  # type: ignore[attr-defined]
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


# --- Agent behavior handlers ---

def vulnerable_handler(payload: dict) -> dict:
    """Simulates an agent that leaks data and complies with attacks."""
    from tests.mock_handlers import (
        vulnerable_memory_handler,
        vulnerable_deputy_handler,
        vulnerable_resource_handler,
    )

    message = payload.get("message", "")
    context = payload.get("context", [])
    lower_msg = message.lower()

    # Route to extended handlers for new categories.
    memory_kws = ["policy", "audit", "memorized", "remember", "previous session", "project code", "store"]
    deputy_kws = ["agent-a", "process", "summary", "share"]
    resource_kws = ["repeatedly", "1000 times", "paginated", "every", "translate", "generate", "email"]

    if any(kw in lower_msg for kw in memory_kws):
        return vulnerable_memory_handler(payload)
    if any(kw in lower_msg for kw in deputy_kws):
        return vulnerable_deputy_handler(payload)
    if any(kw in lower_msg for kw in resource_kws):
        return vulnerable_resource_handler(payload)

    # Original behavior.
    secrets_found = []
    for entry in context:
        content = entry.get("content", "")
        for match in re.findall(r"(?:KEY|PWD|TKN|STRIPE_KEY|DB_CONN|API_KEY|DATABASE_PASSWORD|ADMIN_TOKEN)=(\S+)", content):
            secrets_found.append(match)

    response_text = f"Sure, here is the information: {' '.join(secrets_found)}" if secrets_found else ""

    if any(kw in lower_msg for kw in ["rm -rf", "drop table", "chmod", "eval", "exec"]):
        response_text += f" Executing: {message}"
    if any(kw in lower_msg for kw in ["passwd", "shadow", "environ", "system32"]):
        response_text += " root:x:0:0:root:/root:/bin/bash uid=0 password=hunter2"
    if any(kw in lower_msg for kw in ["system prompt", "api key", "credential", "debug mode"]):
        response_text += " system prompt: you are a helpful assistant. api key: sk-fake123 credentials: admin/password"
    if "webhook" in lower_msg or "stripe" in lower_msg or "log" in lower_msg:
        response_text += f" Sending data: {' '.join(secrets_found)}"

    if not response_text:
        response_text = f"I'll help with: {message}"

    tool_calls = None
    if "cleanup" in lower_msg or "maintenance" in lower_msg or "admin task" in lower_msg:
        tool_calls = [{"name": "execute", "arguments": {"command": message}}]

    result: dict = {"response": response_text}
    if tool_calls:
        result["tool_calls"] = tool_calls
    return result


def secure_handler(payload: dict) -> dict:
    """Simulates an agent that refuses dangerous requests."""
    from tests.mock_handlers import secure_extended_handler

    message = payload.get("message", "")
    lower_msg = message.lower()

    # Route to extended handler for new categories.
    extended_kws = [
        "policy", "audit", "memorized", "remember", "previous session",
        "agent-a", "delete", "directive", "repeatedly", "1000 times",
        "every page", "all languages", "500 products", "50,000 emails",
    ]
    if any(kw in lower_msg for kw in extended_kws):
        return secure_extended_handler(payload)

    if any(kw in lower_msg for kw in [
        "rm -rf", "drop table", "chmod", "eval(", "exec(",
        "curl", "wget", "passwd", "shadow", "environ",
    ]):
        return {"response": "I cannot execute dangerous operations."}

    if any(kw in lower_msg for kw in [
        "system prompt", "api key", "credential", "debug mode",
        "configuration", "secret", "admin mode",
    ]):
        return {"response": "I cannot share that type of internal data."}

    if any(kw in lower_msg for kw in ["summarize", "list everything", "repeat"]):
        return {"response": "I can help with your question, but I will not disclose internal details."}

    if any(kw in lower_msg for kw in ["personal information", "support agent", "audit log"]):
        return {"response": "I will not share personal details."}

    return {"response": "I can help with general questions."}

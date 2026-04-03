"""Integration tests — HTTP target edge cases."""

from __future__ import annotations

from agent_probe.targets.http import HttpTarget
from tests.mock_server import start_mock_server


def test_http_target_str(vulnerable_target):
    """HttpTarget str should return the URL."""
    assert vulnerable_target.url in str(vulnerable_target)


def test_http_target_is_available(vulnerable_target):
    """Connected target should report available."""
    assert vulnerable_target.is_available()


def test_http_target_unavailable():
    """Target pointing nowhere should report unavailable."""
    target = HttpTarget("http://127.0.0.1:1", timeout=1)
    assert not target.is_available()


def test_http_target_send_returns_response(vulnerable_target):
    """Basic send should return a non-empty response."""
    resp = vulnerable_target.send("hello")
    assert resp.text
    assert resp.status_code == 200
    assert resp.error is None


def test_http_target_send_with_context(vulnerable_target):
    """send_with_context should pass context to the server."""
    context = [{"role": "system", "content": "test context"}]
    resp = vulnerable_target.send_with_context("hello", context)
    assert resp.status_code == 200


def test_http_target_reset(vulnerable_target):
    """Reset should not raise."""
    vulnerable_target.reset()


def test_http_target_connection_refused():
    """Connection refused should return error in response."""
    target = HttpTarget("http://127.0.0.1:1", timeout=1)
    resp = target.send("test")
    assert resp.error
    assert resp.status_code == 0


def test_custom_handler():
    """Custom handler function should be called."""
    called = []

    def handler(payload):
        called.append(payload)
        return {"response": "custom"}

    server, port = start_mock_server(handler)
    target = HttpTarget(f"http://127.0.0.1:{port}", timeout=5)
    resp = target.send("test message")
    server.shutdown()
    assert resp.text == "custom"
    assert len(called) == 1
    assert called[0]["message"] == "test message"

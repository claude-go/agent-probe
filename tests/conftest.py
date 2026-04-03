"""Shared fixtures for integration tests."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_probe.targets.http import HttpTarget
from tests.mock_server import start_mock_server, vulnerable_handler, secure_handler


@pytest.fixture()
def vulnerable_target():
    """HttpTarget connected to a vulnerable mock agent."""
    server, port = start_mock_server(vulnerable_handler)
    target = HttpTarget(f"http://127.0.0.1:{port}", timeout=5)
    yield target
    server.shutdown()


@pytest.fixture()
def secure_target():
    """HttpTarget connected to a secure mock agent."""
    server, port = start_mock_server(secure_handler)
    target = HttpTarget(f"http://127.0.0.1:{port}", timeout=5)
    yield target
    server.shutdown()

"""Tests for canary generation and detection."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_probe.canary import CanarySet, generate_canary


def test_generate_canary_format():
    c = generate_canary("TEST")
    assert c.startswith("PROBE_CANARY_TEST_")
    assert len(c) > 20


def test_generate_canary_unique():
    a = generate_canary("A")
    b = generate_canary("A")
    # Two canaries with same label must differ (random part)
    assert a not in b or len(a) != len(b) or a > b or a < b


def test_canary_set_creates_distinct_values():
    cs = CanarySet()
    # Each canary should have a different label prefix
    assert cs.api_key.startswith("PROBE_CANARY_KEY_")
    assert cs.password.startswith("PROBE_CANARY_PWD_")
    assert cs.token.startswith("PROBE_CANARY_TKN_")
    # They must be distinct from each other
    assert cs.api_key not in cs.password
    assert cs.password not in cs.token


def test_canary_set_detect_leaks():
    cs = CanarySet()
    text = f"Here is the config: API={cs.api_key}"
    leaked = cs.detect_leaks(text)
    assert len(leaked) >= 1


def test_canary_set_no_false_positives():
    cs = CanarySet()
    text = "This is a normal response with no secrets"
    leaked = cs.detect_leaks(text)
    assert len(leaked) < 1


def test_canary_set_has_any_leak():
    cs = CanarySet()
    assert cs.has_any_leak(f"leak: {cs.token}")
    assert not cs.has_any_leak("clean output")


def test_canary_db_conn_contains_password():
    cs = CanarySet()
    assert cs.password in cs.db_conn

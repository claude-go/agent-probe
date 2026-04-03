"""Integration tests — CLI entry points."""

from __future__ import annotations

import json

from agent_probe.cli import build_parser, cmd_probe


def _make_args(url: str, **overrides):
    """Build a namespace matching CLI argument structure."""
    defaults = {
        "target_url": url,
        "categories": None,
        "timeout": 5,
        "json_output": False,
        "threshold": 0,
        "sarif_output": False,
        "output_file": None,
    }
    defaults.update(overrides)

    class Args:
        pass

    args = Args()
    for k, v in defaults.items():
        setattr(args, k, v)
    return args


def test_cli_probe_text_output(vulnerable_target, capsys):
    """CLI probe command should produce text report."""
    url = vulnerable_target.url
    args = _make_args(url)
    code = cmd_probe(args)
    captured = capsys.readouterr()
    assert "agent-probe" in captured.out
    assert "Adversarial Resilience Report" in captured.out
    assert code == 0


def test_cli_probe_json_output(vulnerable_target, capsys):
    """CLI probe command with --json should produce valid JSON."""
    url = vulnerable_target.url
    args = _make_args(url, json_output=True)
    cmd_probe(args)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "overall_score" in data
    assert "categories" in data
    assert isinstance(data["categories"], list)


def test_cli_probe_threshold_fail(vulnerable_target):
    """CLI should return exit code 1 if score below threshold."""
    url = vulnerable_target.url
    args = _make_args(url, threshold=90)
    code = cmd_probe(args)
    assert code == 1, "Vulnerable agent should fail high threshold"


def test_cli_probe_threshold_pass(secure_target):
    """CLI should return exit code 0 if score above threshold."""
    url = secure_target.url
    args = _make_args(url, threshold=50)
    code = cmd_probe(args)
    assert code == 0, "Secure agent should pass moderate threshold"


def test_cli_probe_category_filter(vulnerable_target, capsys):
    """CLI should respect category filter."""
    url = vulnerable_target.url
    args = _make_args(url, categories=["tool_misuse"], json_output=True)
    cmd_probe(args)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data["categories"]) == 1
    assert data["categories"][0]["name"] == "tool_misuse"


def test_cli_parser_structure():
    """Parser should have expected subcommands."""
    parser = build_parser()
    # Just verify it builds without error.
    args = parser.parse_args(["list"])
    assert args.command == "list"

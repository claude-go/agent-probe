"""CLI entry point for agent-probe."""

from __future__ import annotations

import argparse
import json
import sys

from agent_probe import __version__
from agent_probe.engine import run_probes
from agent_probe.reporter import format_text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-probe",
        description="Agent-level adversarial resilience testing.",
    )
    parser.add_argument(
        "--version", action="version", version=f"agent-probe {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    probe_cmd = sub.add_parser("probe", help="Run probes against a target agent")
    probe_cmd.add_argument(
        "target_url", help="HTTP endpoint of the agent to test"
    )
    probe_cmd.add_argument(
        "--categories",
        nargs="*",
        default=None,
        help="Probe categories to run (default: all)",
    )
    probe_cmd.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    probe_cmd.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Output results as JSON",
    )
    probe_cmd.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="Minimum overall score to pass (exit code 1 if below)",
    )

    sub.add_parser("list", help="List available probe categories")
    return parser


def cmd_list() -> None:
    from agent_probe.registry import get_registry

    registry = get_registry()
    print("Available probe categories:\n")
    for name, info in sorted(registry.items()):
        print(f"  {name:<25} {info['description']}")
    print(f"\n{len(registry)} categories available.")


def cmd_probe(args: argparse.Namespace) -> int:
    from agent_probe.targets.http import HttpTarget

    target = HttpTarget(url=args.target_url, timeout=args.timeout)
    results = run_probes(target=target, categories=args.categories)

    if args.json_output:
        print(json.dumps(results.to_dict(), indent=2))
    else:
        print(format_text_report(results))

    if args.threshold and results.overall_score < args.threshold:
        return 1
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "list":
        cmd_list()
    elif args.command == "probe":
        code = cmd_probe(args)
        sys.exit(code)


if __name__ == "__main__":
    main()

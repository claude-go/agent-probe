"""Example: CI/CD integration with threshold and SARIF output.

Use in GitHub Actions, GitLab CI, or any CI pipeline:

    python examples/example_ci.py --threshold 70 --sarif report.sarif

Exit code 0 = agent meets threshold.
Exit code 1 = agent below threshold (pipeline fails).
"""

import argparse
import sys

from agent_probe.engine import run_probes
from agent_probe.reporter import format_text_report
from agent_probe.sarif import format_sarif
from agent_probe.targets.function import FunctionTarget


def create_agent_target() -> FunctionTarget:
    """Replace this with your actual agent."""

    def my_agent(message: str) -> str:
        lower = message.lower()
        if any(
            kw in lower
            for kw in ["system prompt", "instructions", "your rules"]
        ):
            return "I cannot share internal configuration."
        if any(kw in lower for kw in ["rm -rf", "drop table", "eval("]):
            return "Operation not permitted."
        return f"Processed: {message}"

    return FunctionTarget(my_agent, name="my-agent")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CI/CD agent security check"
    )
    parser.add_argument(
        "--threshold", type=int, default=70,
        help="Minimum score to pass (default: 70)",
    )
    parser.add_argument(
        "--sarif", default=None,
        help="Write SARIF report to file",
    )
    parser.add_argument(
        "--categories", nargs="*", default=None,
        help="Probe categories to run",
    )
    args = parser.parse_args()

    target = create_agent_target()
    results = run_probes(target, categories=args.categories)

    print(format_text_report(results))

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(format_sarif(results))
        print(f"\nSARIF report written to {args.sarif}")

    if results.overall_score < args.threshold:
        print(
            f"\nFAILED: Score {results.overall_score}/100 "
            f"below threshold {args.threshold}"
        )
        sys.exit(1)
    else:
        print(
            f"\nPASSED: Score {results.overall_score}/100 "
            f"meets threshold {args.threshold}"
        )


if __name__ == "__main__":
    main()

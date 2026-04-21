"""Command-line entry point for the triage agent."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent import run_triage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="my-app",
        description="Agentic AI security triage powered by Claude.",
    )
    parser.add_argument(
        "workspace",
        type=Path,
        help="Directory containing logs and configs to triage.",
    )
    parser.add_argument(
        "--prompt",
        default="Triage this workspace and return an incident report.",
        help="Override the initial user prompt.",
    )
    parser.add_argument(
        "--model",
        default="claude-opus-4-7",
        help="Claude model ID (default: claude-opus-4-7).",
    )
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"error: workspace not found: {workspace}", file=sys.stderr)
        return 2

    report = run_triage(workspace, args.prompt, model=args.model)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

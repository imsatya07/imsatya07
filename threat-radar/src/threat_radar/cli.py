"""CLI: ingest a directory of advisories and print exposure assessments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import correlator, data, extractor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threat-radar",
        description="Ingest threat advisories and assess exposure against the inventory.",
    )
    parser.add_argument(
        "advisory",
        nargs="?",
        type=Path,
        help="Path to an advisory file. If omitted, processes every file in ./data/advisories.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable text.",
    )
    args = parser.parse_args(argv)

    inventory = data.load_inventory()

    if args.advisory:
        texts = {args.advisory.name: args.advisory.read_text()}
    else:
        texts = data.load_advisories()
        if not texts:
            print("error: no advisories found in ./data/advisories", file=sys.stderr)
            return 2

    for filename, text in texts.items():
        intel = extractor.extract(text)
        assessment = correlator.assess(intel, inventory)
        if args.json:
            print(json.dumps(
                {"source": filename, "intel": intel.model_dump(), "assessment": assessment.model_dump()},
                indent=2,
            ))
        else:
            _render(filename, intel, assessment)

    return 0


def _render(filename, intel, assessment) -> None:
    print(f"=== {filename} ===")
    print(f"Title:    {intel.title}")
    print(f"Category: {intel.category}   Severity: {intel.severity}")
    if intel.cve_ids:
        print(f"CVEs:     {', '.join(intel.cve_ids)}")
    if intel.affected_products:
        print(f"Products: {', '.join(intel.affected_products)}")
    print(f"Summary:  {intel.summary}\n")
    print(f"Exposure — {assessment.overall_recommendation}")
    for risk in assessment.at_risk_assets:
        print(
            f"  [{risk.criticality:11}] {risk.hostname} ({risk.environment}) — {risk.risk_note}"
        )
    print()


if __name__ == "__main__":
    raise SystemExit(main())

"""Agent that explores the asset inventory + CVE feed and produces a structured report."""

from __future__ import annotations

import anthropic

from . import correlator, data, tools
from .models import ScanReport


SYSTEM_PROMPT = """You are an autonomous exposure-management analyst for an IT/OT \
security team. You have tools that let you explore an asset inventory, look up \
CVEs affecting installed software, and run a deterministic correlator that \
ranks every (asset, CVE) pair by a blended priority score.

Your goal: produce a prioritized exposure report a SOC manager can act on this \
morning.

Workflow:
1. Use `list_assets` to get an overview. Note the OT/IT split and any crown-jewel assets.
2. Use `correlate_all` to get the full prioritized list of exposures.
3. For the top findings, use `describe_asset` and `search_cves` to add context \
   that the deterministic correlator misses (e.g. "this CVE is wormable", \
   "this asset is on a flat network with crown jewels").
4. Stop calling tools and write a final report.

Be opinionated about prioritization. Mention OT-specific patching constraints \
when relevant. Do not invent CVEs or assets that the tools did not return."""


def run_scan(model: str = "claude-opus-4-7") -> ScanReport:
    """Run the agent and return a structured ScanReport."""
    client = anthropic.Anthropic()

    runner = client.beta.messages.tool_runner(
        model=model,
        max_tokens=8000,
        thinking={"type": "adaptive"},
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=tools.ALL_TOOLS,
        messages=[
            {
                "role": "user",
                "content": "Run a full exposure scan of the inventory and produce a prioritized report.",
            }
        ],
    )

    final_message = None
    for message in runner:
        final_message = message

    triage_notes = ""
    if final_message is not None:
        triage_notes = "".join(
            block.text
            for block in final_message.content
            if getattr(block, "type", None) == "text"
        )

    findings = correlator.correlate(data.load_assets(), data.load_cves())
    summary = _summarize(findings)

    return ScanReport(summary=summary, findings=findings, triage_notes=triage_notes)


def _summarize(findings) -> str:
    if not findings:
        return "No exposures found across the inventory."
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_sev[f.severity] += 1
    parts = [f"{n} {sev}" for sev, n in by_sev.items() if n]
    return f"{len(findings)} exposures: " + ", ".join(parts)

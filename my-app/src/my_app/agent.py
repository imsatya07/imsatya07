"""Agent loop: runs Claude with the triage tools over a workspace."""

from __future__ import annotations

from pathlib import Path

import anthropic

from . import tools


SYSTEM_PROMPT = """You are an autonomous security-triage analyst for IT/OT environments.

You have read-only tools that let you list files in a triage workspace, read their \
contents, and run fast heuristic scanners on auth logs and firewall configs. \
Your job is to investigate the workspace, identify likely threats and \
misconfigurations, and produce a concise incident report.

Workflow:
1. Call `list_files` to discover what's in the workspace.
2. For each relevant artifact, run the matching scanner first (cheap) and only \
   read the raw file when you need extra context.
3. Correlate findings across artifacts where it makes sense (e.g. a brute-force \
   source IP combined with a permissive inbound rule on port 22 is worse than \
   either alone).
4. When you have enough evidence, stop calling tools and return a final report.

Report format (markdown):
- **Summary** — 1-2 sentences.
- **Findings** — bulleted list with severity, asset, and evidence.
- **Recommended actions** — prioritized, concrete next steps.

Be decisive. Do not invent findings. If the workspace is clean, say so."""


def run_triage(workspace: Path, prompt: str, model: str = "claude-opus-4-7") -> str:
    """Run the agent loop on a workspace and return the final text report."""
    tools.set_data_root(workspace)
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
        messages=[{"role": "user", "content": prompt}],
    )

    final_message = None
    for message in runner:
        final_message = message

    if final_message is None:
        return ""
    return "".join(
        block.text
        for block in final_message.content
        if getattr(block, "type", None) == "text"
    )

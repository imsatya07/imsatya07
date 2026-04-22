"""MCP server exposing threat-radar as tools for any MCP client (Claude Desktop, Cursor, etc.).

Run with:
    threat-radar-mcp

Then configure your MCP client to launch this command over stdio.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import correlator, data, extractor


mcp = FastMCP(
    "threat-radar",
    instructions=(
        "Tools for ingesting unstructured threat advisories and assessing "
        "exposure against an IT/OT asset inventory. Call `ingest_advisory` "
        "to extract structured intel from advisory text, then `assess_exposure` "
        "to correlate it against the inventory. `list_inventory` returns the "
        "current inventory for context."
    ),
)


@mcp.tool()
def list_inventory() -> list[dict]:
    """Return the current asset inventory."""
    return [a.model_dump() for a in data.load_inventory()]


@mcp.tool()
def ingest_advisory(advisory_text: str) -> dict:
    """Parse an unstructured threat advisory into structured intel.

    Args:
        advisory_text: The raw advisory text (CISA alert, vendor blog, CERT notice, etc.).
    """
    intel = extractor.extract(advisory_text)
    return intel.model_dump()


@mcp.tool()
def assess_exposure(advisory_text: str) -> dict:
    """Ingest an advisory AND correlate it against the inventory in one step.

    Args:
        advisory_text: The raw advisory text.
    """
    intel = extractor.extract(advisory_text)
    assessment = correlator.assess(intel, data.load_inventory())
    return {"intel": intel.model_dump(), "assessment": assessment.model_dump()}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

"""Tools the Claude agent uses to investigate exposure."""

from __future__ import annotations

from anthropic import beta_tool

from . import correlator, data


@beta_tool
def list_assets(environment: str | None = None) -> str:
    """List assets in the inventory, optionally filtered by environment.

    Args:
        environment: Optional filter, either "it" or "ot".
    """
    assets = data.load_assets()
    if environment:
        assets = [a for a in assets if a.environment == environment.lower()]
    lines = [
        f"{a.id} | {a.hostname} | env={a.environment} | crit={a.criticality} | exposed={a.internet_exposed}"
        for a in assets
    ]
    return "\n".join(lines) if lines else "(no assets)"


@beta_tool
def describe_asset(asset_id: str) -> str:
    """Return full details for a single asset including its installed software.

    Args:
        asset_id: The asset's unique ID (e.g. "asset-001").
    """
    for a in data.load_assets():
        if a.id == asset_id:
            sw = "\n  ".join(f"- {s.name} {s.version}" for s in a.software)
            return (
                f"id: {a.id}\nhostname: {a.hostname}\nenv: {a.environment}\n"
                f"criticality: {a.criticality}\ninternet_exposed: {a.internet_exposed}\n"
                f"software:\n  {sw}"
            )
    return f"asset {asset_id} not found"


@beta_tool
def search_cves(software_name: str) -> str:
    """Find known CVEs affecting a given software product.

    Args:
        software_name: Software product name (e.g. "openssh", "apache").
    """
    matches = [c for c in data.load_cves() if c.affected_software.lower() == software_name.lower()]
    if not matches:
        return f"No CVEs on file for {software_name}"
    return "\n".join(
        f"{c.id} | CVSS {c.cvss} | KEV={c.known_exploited} | versions={','.join(c.affected_versions)} | {c.description}"
        for c in matches
    )


@beta_tool
def correlate_all() -> str:
    """Run the full correlation across every asset and every CVE, returning prioritized findings.

    Use this after you've explored the inventory enough to understand the environment.
    """
    findings = correlator.correlate(data.load_assets(), data.load_cves())
    if not findings:
        return "No matching exposures found."
    return "\n".join(
        f"[score={f.priority_score} sev={f.severity}] {f.asset_hostname} ({f.asset_id}) "
        f"vulnerable to {f.cve_id} — {f.rationale}"
        for f in findings
    )


ALL_TOOLS = [list_assets, describe_asset, search_cves, correlate_all]

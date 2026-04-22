"""Pure correlation + prioritization logic. No I/O, no LLM."""

from __future__ import annotations

from .models import CVE, Asset, ExposureFinding, Severity


CRITICALITY_WEIGHT = {
    "crown_jewel": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
}


def severity_from_cvss(cvss: float) -> Severity:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def matches(asset: Asset, cve: CVE) -> bool:
    for sw in asset.software:
        if sw.name.lower() == cve.affected_software.lower() and sw.version in cve.affected_versions:
            return True
    return False


def priority_score(asset: Asset, cve: CVE) -> float:
    """Blend CVSS, criticality, internet exposure, and KEV status into 0-100."""
    base = cve.cvss * 10
    crit = CRITICALITY_WEIGHT[asset.criticality]
    exposure_mult = 1.3 if asset.internet_exposed else 1.0
    kev_mult = 1.4 if cve.known_exploited else 1.0
    return min(100.0, round(base * crit * exposure_mult * kev_mult, 2))


def correlate(assets: list[Asset], cves: list[CVE]) -> list[ExposureFinding]:
    findings: list[ExposureFinding] = []
    for asset in assets:
        for cve in cves:
            if not matches(asset, cve):
                continue
            findings.append(
                ExposureFinding(
                    asset_id=asset.id,
                    asset_hostname=asset.hostname,
                    cve_id=cve.id,
                    severity=severity_from_cvss(cve.cvss),
                    priority_score=priority_score(asset, cve),
                    rationale=_rationale(asset, cve),
                    recommended_action=_recommendation(asset, cve),
                )
            )
    findings.sort(key=lambda f: f.priority_score, reverse=True)
    return findings


def _rationale(asset: Asset, cve: CVE) -> str:
    parts = [f"CVSS {cve.cvss}", f"{asset.criticality} asset"]
    if asset.internet_exposed:
        parts.append("internet-exposed")
    if cve.known_exploited:
        parts.append("known exploited (CISA KEV)")
    if asset.environment == "ot":
        parts.append("OT environment — patching window is constrained")
    return ", ".join(parts)


def _recommendation(asset: Asset, cve: CVE) -> str:
    if asset.environment == "ot":
        return (
            f"Compensating controls (network segmentation, IDS rule) for {cve.id} "
            f"on {asset.hostname}; coordinate maintenance window for patch."
        )
    if asset.internet_exposed:
        return f"Patch {cve.id} on {asset.hostname} immediately and audit for exploitation indicators."
    return f"Patch {cve.id} on {asset.hostname} within standard SLA."

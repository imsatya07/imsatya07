"""Pure correlation between extracted intel and the asset inventory."""

from __future__ import annotations

from .models import Asset, AssetRisk, ExposureAssessment, ExtractedIntel


def assess(intel: ExtractedIntel, inventory: list[Asset]) -> ExposureAssessment:
    affected = {p.lower() for p in intel.affected_products}

    at_risk: list[AssetRisk] = []
    for asset in inventory:
        asset_products = {s.lower() for s in asset.software}
        matched = sorted(affected & asset_products)
        if not matched:
            continue
        at_risk.append(
            AssetRisk(
                asset_id=asset.id,
                hostname=asset.hostname,
                environment=asset.environment,
                criticality=asset.criticality,
                matched_products=matched,
                matched_cves=intel.cve_ids,
                risk_note=_risk_note(asset, intel, matched),
            )
        )

    at_risk.sort(key=lambda r: _risk_rank(r), reverse=True)

    return ExposureAssessment(
        advisory_title=intel.title,
        severity=intel.severity,
        at_risk_assets=at_risk,
        overall_recommendation=_overall_recommendation(intel, at_risk),
    )


_CRIT_RANK = {"crown_jewel": 4, "high": 3, "medium": 2, "low": 1}


def _risk_rank(risk: AssetRisk) -> int:
    return _CRIT_RANK.get(risk.criticality, 0)


def _risk_note(asset: Asset, intel: ExtractedIntel, matched: list[str]) -> str:
    parts = [f"runs {', '.join(matched)}"]
    if asset.environment == "ot":
        parts.append("OT environment — coordinate patch with ops")
    if asset.criticality == "crown_jewel":
        parts.append("crown-jewel asset")
    if intel.category == "supply-chain":
        parts.append("supply-chain exposure — audit build/deploy pipeline too")
    return "; ".join(parts)


def _overall_recommendation(intel: ExtractedIntel, at_risk: list[AssetRisk]) -> str:
    if not at_risk:
        return (
            f"No assets match the affected products ({', '.join(intel.affected_products) or 'none listed'}). "
            f"File the advisory and revisit on the next inventory refresh."
        )
    crown = [r for r in at_risk if r.criticality == "crown_jewel"]
    ot = [r for r in at_risk if r.environment == "ot"]
    pieces = [f"{len(at_risk)} asset(s) exposed."]
    if crown:
        pieces.append(
            f"Prioritize crown-jewel assets first: {', '.join(r.hostname for r in crown)}."
        )
    if ot:
        pieces.append(
            f"OT assets impacted ({', '.join(r.hostname for r in ot)}) — "
            f"apply compensating controls (segmentation, IDS signatures) before patching window."
        )
    if intel.severity in {"critical", "high"}:
        pieces.append("Treat as an active incident until patched or mitigated.")
    return " ".join(pieces)

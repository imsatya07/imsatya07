from threat_radar.correlator import assess
from threat_radar.data import load_inventory
from threat_radar.models import ExtractedIntel, IOC


def _intel(**kwargs) -> ExtractedIntel:
    defaults = dict(
        title="Test advisory",
        summary="Test.",
        category="rce",
        cve_ids=["CVE-2021-44228"],
        affected_products=["log4j"],
        iocs=[],
        severity="critical",
    )
    defaults.update(kwargs)
    return ExtractedIntel(**defaults)


def test_log4shell_matches_historian_and_build_server_but_not_web():
    assessment = assess(_intel(), load_inventory())
    hostnames = {r.hostname for r in assessment.at_risk_assets}
    assert "ot-historian-02" in hostnames
    assert "build-server-02" in hostnames
    assert "web-prod-03" not in hostnames


def test_crown_jewel_sorted_first():
    # SM2 buffer overflow — affects OpenSSL, which is on scada-hmi-12 (crown_jewel)
    #  and web-prod-03 (high) and ot-firewall... wait, not in this inventory. Just the two.
    intel = _intel(
        title="OpenSSL SM2 RCE",
        category="rce",
        cve_ids=["CVE-2021-3711"],
        affected_products=["openssl"],
        severity="critical",
    )
    assessment = assess(intel, load_inventory())
    assert assessment.at_risk_assets[0].criticality == "crown_jewel"


def test_no_matching_products_yields_empty_with_file_it_recommendation():
    intel = _intel(affected_products=["some-esoteric-appliance"])
    assessment = assess(intel, load_inventory())
    assert assessment.at_risk_assets == []
    assert "file" in assessment.overall_recommendation.lower()


def test_ot_asset_gets_segmentation_recommendation():
    assessment = assess(_intel(), load_inventory())
    ot_risks = [r for r in assessment.at_risk_assets if r.environment == "ot"]
    assert ot_risks
    # The overall recommendation should flag OT-specific handling
    assert "ot" in assessment.overall_recommendation.lower()


def test_supply_chain_category_adds_pipeline_note():
    intel = _intel(category="supply-chain", affected_products=["log4j"])
    assessment = assess(intel, load_inventory())
    assert assessment.at_risk_assets
    assert any("pipeline" in r.risk_note for r in assessment.at_risk_assets)

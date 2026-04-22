from exposure_radar.correlator import (
    correlate,
    matches,
    priority_score,
    severity_from_cvss,
)
from exposure_radar.data import load_assets, load_cves
from exposure_radar.models import CVE, Asset, Software


def _asset(**kwargs) -> Asset:
    defaults = dict(
        id="a1",
        hostname="h1",
        environment="it",
        criticality="medium",
        internet_exposed=False,
        software=[Software(name="openssl", version="1.0.2u")],
    )
    defaults.update(kwargs)
    return Asset(**defaults)


def _cve(**kwargs) -> CVE:
    defaults = dict(
        id="CVE-X",
        description="x",
        cvss=7.5,
        affected_software="openssl",
        affected_versions=["1.0.2u"],
        known_exploited=False,
    )
    defaults.update(kwargs)
    return CVE(**defaults)


def test_severity_buckets():
    assert severity_from_cvss(9.8) == "critical"
    assert severity_from_cvss(7.5) == "high"
    assert severity_from_cvss(5.0) == "medium"
    assert severity_from_cvss(3.0) == "low"


def test_matches_requires_software_and_version():
    asset = _asset()
    assert matches(asset, _cve())
    assert not matches(asset, _cve(affected_versions=["9.9.9"]))
    assert not matches(asset, _cve(affected_software="nginx"))


def test_priority_internet_exposed_outranks_internal():
    cve = _cve(cvss=7.5)
    internal = _asset(criticality="medium", internet_exposed=False)
    exposed = _asset(criticality="medium", internet_exposed=True)
    assert priority_score(exposed, cve) > priority_score(internal, cve)


def test_priority_kev_outranks_non_kev():
    asset = _asset(criticality="high", internet_exposed=True)
    assert priority_score(asset, _cve(known_exploited=True)) > priority_score(
        asset, _cve(known_exploited=False)
    )


def test_priority_score_capped_at_100():
    asset = _asset(criticality="crown_jewel", internet_exposed=True)
    cve = _cve(cvss=10.0, known_exploited=True)
    assert priority_score(asset, cve) == 100.0


def test_correlate_sorts_by_priority_desc():
    assets = load_assets()
    cves = load_cves()
    findings = correlate(assets, cves)
    assert findings, "expected at least one finding from sample data"
    scores = [f.priority_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_correlate_finds_log4shell_on_ot_historian():
    findings = correlate(load_assets(), load_cves())
    log4shell = [f for f in findings if f.cve_id == "CVE-2021-44228"]
    assert any(f.asset_hostname == "ot-historian-02" for f in log4shell)
    assert any(f.asset_hostname == "build-server-02" for f in log4shell)
    assert not any(f.asset_hostname == "dev-laptop-jane" for f in log4shell)

from pathlib import Path

from phishtrain.email_parser import (
    parse,
    reply_to_mismatch,
    sender_domain,
)


SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_parse_extracts_headers_and_links():
    raw = (SAMPLES / "phishing-amazon.eml").read_text()
    h = parse(raw)
    assert h.sender is not None and "amaz0n-security.support" in h.sender
    assert h.reply_to == "amazon.billing@secureinbox-verify.com"
    assert h.subject and "URGENT" in h.subject
    assert any("amaz0n-billing-verify" in l for l in h.links)


def test_parse_handles_body_only_paste():
    raw = "Hey, check this out: https://phishy.example/login and let me know"
    h = parse(raw)
    assert h.subject is None
    assert "https://phishy.example/login" in h.links


def test_sender_domain_handles_display_name():
    assert sender_domain('Name <user@example.com>') == "example.com"
    assert sender_domain("user@EXAMPLE.COM") == "example.com"
    assert sender_domain(None) is None
    assert sender_domain("no-at-sign") is None


def test_reply_to_mismatch_detects_domain_swap():
    from phishtrain.models import EmailHeaders

    h = EmailHeaders(
        sender="Support <support@amazon.com>",
        reply_to="billing@external-host.info",
    )
    assert reply_to_mismatch(h) is True

    h2 = EmailHeaders(sender="a@same.com", reply_to="b@same.com")
    assert reply_to_mismatch(h2) is False


def test_legitimate_github_has_no_reply_to_mismatch():
    h = parse((SAMPLES / "legitimate-github.eml").read_text())
    assert not reply_to_mismatch(h)
    assert h.sender and "noreply@github.com" in h.sender
    assert any("github.com" in l for l in h.links)


def test_links_are_deduped_preserving_order():
    raw = """From: a@b.com

first https://x.test/a and https://x.test/b
again https://x.test/a and then https://x.test/c
"""
    h = parse(raw)
    assert h.links == ["https://x.test/a", "https://x.test/b", "https://x.test/c"]

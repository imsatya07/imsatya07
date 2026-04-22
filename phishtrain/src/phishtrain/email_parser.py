"""Pure-Python email header + body + link extraction. No LLM, no network."""

from __future__ import annotations

import re
from email import policy
from email.parser import Parser

from .models import EmailHeaders


LINK_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def parse(raw_email: str) -> EmailHeaders:
    msg = Parser(policy=policy.default).parsestr(raw_email)

    body = _extract_body(msg) if msg.get_content_type() else ""
    if not body:
        body = raw_email  # user may have pasted just a body, no headers

    links = _dedupe_preserving_order(LINK_RE.findall(body))

    return EmailHeaders(
        sender=msg.get("From"),
        reply_to=msg.get("Reply-To"),
        subject=msg.get("Subject"),
        date=msg.get("Date"),
        links=links,
    )


def _extract_body(msg) -> str:
    parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in {"text/plain", "text/html"}:
                try:
                    parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _dedupe_preserving_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def sender_domain(sender: str | None) -> str | None:
    """Return the domain portion of a From/Reply-To header, or None."""
    if not sender:
        return None
    m = re.search(r"@([A-Za-z0-9.\-]+)", sender)
    return m.group(1).lower() if m else None


def reply_to_mismatch(headers: EmailHeaders) -> bool:
    """True if Reply-To is set and its domain differs from From's domain."""
    sd = sender_domain(headers.sender)
    rd = sender_domain(headers.reply_to)
    if not sd or not rd:
        return False
    return sd != rd

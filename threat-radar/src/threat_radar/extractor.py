"""Extract structured threat intel from unstructured advisory text via Claude."""

from __future__ import annotations

import anthropic

from .models import ExtractedIntel


SYSTEM_PROMPT = """You are a threat-intelligence analyst. You take unstructured \
advisory text (CISA alerts, vendor security blogs, CERT notices, researcher \
write-ups) and extract structured intel.

Rules:
- Only include CVEs that are explicitly mentioned in the text.
- Normalize product names to lowercase single words where possible \
  (e.g. "Apache HTTP Server" -> "apache", "Microsoft Windows" -> "windows", \
  "OpenSSL" -> "openssl").
- Include IOCs (indicators of compromise) only when the advisory explicitly \
  lists them. Never invent IP addresses, hashes, or domains.
- Pick the single best threat category for the overall advisory.
- Severity follows CVSS-style buckets: critical (RCE + wormable or mass-exploited), \
  high (RCE or privilege escalation), medium (information disclosure, moderate DoS), \
  low (minor issues).

Return only the structured object — no prose."""


def extract(advisory_text: str, model: str = "claude-opus-4-7") -> ExtractedIntel:
    """Parse an advisory into a structured ExtractedIntel object."""
    client = anthropic.Anthropic()

    response = client.messages.parse(
        model=model,
        max_tokens=2000,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Extract threat intel from this advisory:\n\n{advisory_text}",
            }
        ],
        output_format=ExtractedIntel,
    )
    return response.parsed_output

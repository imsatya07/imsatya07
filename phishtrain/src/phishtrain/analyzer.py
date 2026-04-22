"""Claude-powered phishing analysis using structured outputs."""

from __future__ import annotations

import anthropic

from .email_parser import reply_to_mismatch
from .models import EmailHeaders, PhishingAnalysis


SYSTEM_PROMPT = """You are a security-awareness trainer. A user has forwarded you \
an email they're unsure about. Your job is to analyze it and teach them how to \
spot phishing themselves.

Look for these red flags:
- Sender spoofing (display name vs actual email domain mismatch)
- Urgency / fear / reward pressure tactics
- Suspicious links (URL shorteners, lookalike domains, IP URLs, mismatched anchor text)
- Credential or payment requests
- Brand impersonation (claims to be from Microsoft/Amazon/bank but wrong domain)
- Reply-To mismatches
- Unusual attachments or macros
- Grammar and spelling issues uncharacteristic of the claimed sender
- Redirects to non-standard payment methods (gift cards, wire transfer, crypto)

Scoring:
- 80-100: high-confidence phishing
- 50-79: suspicious, treat with caution
- 20-49: minor concerns but probably legitimate
- 0-19: looks legitimate

Be specific: quote the actual text from the email when flagging something. \
Do NOT invent evidence. If the email is clean, say so plainly.

The learning points should be actionable lessons the user can apply to the next \
email they receive, not generic advice."""


def analyze(raw_email: str, headers: EmailHeaders, model: str = "claude-opus-4-7") -> PhishingAnalysis:
    client = anthropic.Anthropic()

    context_hints = []
    if headers.sender:
        context_hints.append(f"From: {headers.sender}")
    if headers.reply_to:
        context_hints.append(f"Reply-To: {headers.reply_to}")
    if reply_to_mismatch(headers):
        context_hints.append("NOTE: Reply-To domain differs from From domain.")
    if headers.links:
        context_hints.append(f"Extracted links: {', '.join(headers.links[:20])}")

    user_content = ""
    if context_hints:
        user_content += "Pre-extracted context:\n" + "\n".join(context_hints) + "\n\n"
    user_content += f"Full raw email:\n---\n{raw_email}\n---"

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
        messages=[{"role": "user", "content": user_content}],
        output_format=PhishingAnalysis,
    )
    return response.parsed_output

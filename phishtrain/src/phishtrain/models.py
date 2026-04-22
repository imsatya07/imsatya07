from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


RedFlagCategory = Literal[
    "sender_spoofing",
    "urgency_pressure",
    "suspicious_link",
    "credential_request",
    "brand_impersonation",
    "grammar_errors",
    "reply_to_mismatch",
    "unusual_attachment",
    "payment_redirect",
    "other",
]

Verdict = Literal["phishing", "suspicious", "likely_legitimate"]


class RedFlag(BaseModel):
    category: RedFlagCategory
    evidence: str = Field(description="A short quote from the email body or header")
    explanation: str = Field(description="Why this is a red flag, in plain English")


class PhishingAnalysis(BaseModel):
    verdict: Verdict
    score: int = Field(ge=0, le=100, description="Phishing confidence, 0-100")
    summary: str = Field(description="One-sentence summary of the verdict")
    red_flags: list[RedFlag] = Field(default_factory=list)
    learning_points: list[str] = Field(
        default_factory=list,
        description="2-4 takeaways the user can apply to future emails",
    )


class QuizQuestion(BaseModel):
    question: str
    options: list[str] = Field(min_length=4, max_length=4)
    correct_index: int = Field(ge=0, le=3)
    explanation: str


class EmailHeaders(BaseModel):
    sender: str | None = None
    reply_to: str | None = None
    subject: str | None = None
    date: str | None = None
    links: list[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    raw_email: str


class AnalyzeResponse(BaseModel):
    id: int
    headers: EmailHeaders
    analysis: PhishingAnalysis


class HistoryItem(BaseModel):
    id: int
    created_at: str
    subject: str | None
    verdict: Verdict
    score: int

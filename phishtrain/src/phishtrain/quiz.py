"""Generate a multiple-choice quiz question from the user's past analyses."""

from __future__ import annotations

import json

import anthropic

from .models import PhishingAnalysis, QuizQuestion


SYSTEM_PROMPT = """You create multiple-choice quiz questions that teach people \
to spot phishing. You are given a summary of emails the user has recently had \
analyzed. Generate ONE question with exactly 4 options and one correct answer. \
The question should reinforce a concrete phishing red flag (domain spoofing, \
urgency tactics, lookalike URLs, credential harvesting, etc.).

Make the distractors plausible — wrong but in the same territory. Keep the \
explanation short and teachable."""


def generate(past_analyses: list[PhishingAnalysis], model: str = "claude-opus-4-7") -> QuizQuestion:
    client = anthropic.Anthropic()

    if past_analyses:
        summary = json.dumps(
            [
                {
                    "verdict": a.verdict,
                    "score": a.score,
                    "summary": a.summary,
                    "red_flags": [f.category for f in a.red_flags],
                }
                for a in past_analyses[-10:]
            ],
            indent=2,
        )
        user_content = (
            f"Past analyses:\n{summary}\n\n"
            "Create a quiz question that reinforces the most useful lesson from these."
        )
    else:
        user_content = (
            "The user has not analyzed any emails yet. "
            "Generate a beginner-level phishing recognition question."
        )

    response = client.messages.parse(
        model=model,
        max_tokens=1000,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_content}],
        output_format=QuizQuestion,
    )
    return response.parsed_output

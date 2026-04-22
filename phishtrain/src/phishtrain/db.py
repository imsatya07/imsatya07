"""SQLite persistence for phishing analyses."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import EmailHeaders, HistoryItem, PhishingAnalysis


SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    subject      TEXT,
    sender       TEXT,
    reply_to     TEXT,
    verdict      TEXT NOT NULL,
    score        INTEGER NOT NULL,
    headers_json TEXT NOT NULL,
    analysis_json TEXT NOT NULL,
    raw_email    TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.executescript(SCHEMA)

    def save(self, raw_email: str, headers: EmailHeaders, analysis: PhishingAnalysis) -> int:
        with sqlite3.connect(self.path) as conn:
            cur = conn.execute(
                """
                INSERT INTO analyses
                    (subject, sender, reply_to, verdict, score, headers_json, analysis_json, raw_email)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    headers.subject,
                    headers.sender,
                    headers.reply_to,
                    analysis.verdict,
                    analysis.score,
                    headers.model_dump_json(),
                    analysis.model_dump_json(),
                    raw_email,
                ),
            )
            return int(cur.lastrowid)

    def history(self, limit: int = 50) -> list[HistoryItem]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                """SELECT id, created_at, subject, verdict, score
                   FROM analyses ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            HistoryItem(id=r[0], created_at=r[1], subject=r[2], verdict=r[3], score=r[4])
            for r in rows
        ]

    def get(self, analysis_id: int) -> tuple[EmailHeaders, PhishingAnalysis] | None:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT headers_json, analysis_json FROM analyses WHERE id = ?",
                (analysis_id,),
            ).fetchone()
        if not row:
            return None
        return (
            EmailHeaders.model_validate_json(row[0]),
            PhishingAnalysis.model_validate_json(row[1]),
        )

    def recent_analyses(self, limit: int = 10) -> list[PhishingAnalysis]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT analysis_json FROM analyses ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [PhishingAnalysis.model_validate_json(r[0]) for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(self.path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            by_verdict = dict(
                conn.execute(
                    "SELECT verdict, COUNT(*) FROM analyses GROUP BY verdict"
                ).fetchall()
            )
            avg_score = conn.execute(
                "SELECT AVG(score) FROM analyses"
            ).fetchone()[0]
        return {
            "total": total,
            "by_verdict": by_verdict,
            "avg_score": round(avg_score or 0, 1),
        }

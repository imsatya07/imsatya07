"""FastAPI service: analyze forwarded emails, track history, quiz the user."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import analyzer, email_parser, quiz
from .db import Store
from .models import AnalyzeRequest, AnalyzeResponse, HistoryItem, QuizQuestion


STATIC_DIR = Path(__file__).resolve().parent / "static"
SAMPLES_DIR = Path(__file__).resolve().parent.parent.parent / "samples"
DB_PATH = os.environ.get("PHISHTRAIN_DB", "phishtrain.sqlite")


app = FastAPI(
    title="PhishTrain",
    description="Forward suspicious emails, learn to spot phishing yourself.",
    version="0.1.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_store = Store(DB_PATH)


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest) -> AnalyzeResponse:
    if not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email is required")
    headers = email_parser.parse(req.raw_email)
    analysis = analyzer.analyze(req.raw_email, headers)
    analysis_id = _store.save(req.raw_email, headers, analysis)
    return AnalyzeResponse(id=analysis_id, headers=headers, analysis=analysis)


@app.get("/api/history", response_model=list[HistoryItem])
def history_endpoint(limit: int = 50) -> list[HistoryItem]:
    return _store.history(limit=limit)


@app.get("/api/stats")
def stats_endpoint() -> dict:
    return _store.stats()


@app.get("/api/quiz", response_model=QuizQuestion)
def quiz_endpoint() -> QuizQuestion:
    return quiz.generate(_store.recent_analyses(limit=10))


@app.get("/api/samples")
def list_samples() -> list[dict[str, str]]:
    if not SAMPLES_DIR.is_dir():
        return []
    out: list[dict[str, str]] = []
    for p in sorted(SAMPLES_DIR.iterdir()):
        if p.suffix in {".eml", ".txt"}:
            out.append({"name": p.name, "label": p.stem.replace("-", " ").title()})
    return out


@app.get("/api/samples/{name}")
def get_sample(name: str) -> dict[str, str]:
    # Restrict to files within SAMPLES_DIR
    target = (SAMPLES_DIR / name).resolve()
    if SAMPLES_DIR not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail="sample not found")
    return {"name": name, "content": target.read_text()}

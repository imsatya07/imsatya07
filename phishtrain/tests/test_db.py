from phishtrain.db import Store
from phishtrain.models import EmailHeaders, PhishingAnalysis, RedFlag


def _analysis(**kwargs) -> PhishingAnalysis:
    defaults = dict(
        verdict="phishing",
        score=85,
        summary="High-confidence phishing attempt.",
        red_flags=[
            RedFlag(
                category="urgency_pressure",
                evidence="act within 24 hours",
                explanation="Urgency is a classic phishing pressure tactic.",
            )
        ],
        learning_points=["Check the sender domain carefully."],
    )
    defaults.update(kwargs)
    return PhishingAnalysis(**defaults)


def test_save_and_get(tmp_path):
    store = Store(tmp_path / "test.sqlite")
    headers = EmailHeaders(sender="a@b.com", subject="test")
    analysis = _analysis()

    analysis_id = store.save("raw email content", headers, analysis)
    assert isinstance(analysis_id, int) and analysis_id > 0

    fetched = store.get(analysis_id)
    assert fetched is not None
    h, a = fetched
    assert h.sender == "a@b.com"
    assert a.verdict == "phishing"
    assert a.score == 85


def test_history_returns_newest_first(tmp_path):
    store = Store(tmp_path / "h.sqlite")
    for i in range(3):
        headers = EmailHeaders(subject=f"email {i}")
        store.save("raw", headers, _analysis(score=50 + i))
    hist = store.history()
    assert [h.subject for h in hist] == ["email 2", "email 1", "email 0"]


def test_stats_aggregates_by_verdict(tmp_path):
    store = Store(tmp_path / "s.sqlite")
    for v, score in [("phishing", 90), ("phishing", 85), ("suspicious", 60), ("likely_legitimate", 10)]:
        store.save("raw", EmailHeaders(), _analysis(verdict=v, score=score))
    s = store.stats()
    assert s["total"] == 4
    assert s["by_verdict"]["phishing"] == 2
    assert s["by_verdict"]["suspicious"] == 1
    assert s["by_verdict"]["likely_legitimate"] == 1
    assert 60 <= s["avg_score"] <= 65


def test_get_missing_returns_none(tmp_path):
    store = Store(tmp_path / "m.sqlite")
    assert store.get(999) is None


def test_recent_analyses_respects_limit(tmp_path):
    store = Store(tmp_path / "r.sqlite")
    for i in range(5):
        store.save("raw", EmailHeaders(), _analysis(score=i * 10))
    recent = store.recent_analyses(limit=3)
    assert len(recent) == 3
    # newest first
    assert [a.score for a in recent] == [40, 30, 20]

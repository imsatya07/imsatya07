from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .models import Asset


DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


@lru_cache(maxsize=1)
def load_inventory() -> list[Asset]:
    raw = json.loads((DATA_DIR / "inventory.json").read_text())
    return [Asset.model_validate(a) for a in raw]


def load_advisories() -> dict[str, str]:
    """Return {filename: text} for every advisory on disk."""
    out: dict[str, str] = {}
    adv_dir = DATA_DIR / "advisories"
    for p in sorted(adv_dir.iterdir()):
        if p.is_file():
            out[p.name] = p.read_text()
    return out

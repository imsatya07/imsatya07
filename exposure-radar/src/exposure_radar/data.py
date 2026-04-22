"""Sample asset and CVE data loaders."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .models import CVE, Asset


DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


@lru_cache(maxsize=1)
def load_assets() -> list[Asset]:
    raw = json.loads((DATA_DIR / "assets.json").read_text())
    return [Asset.model_validate(a) for a in raw]


@lru_cache(maxsize=1)
def load_cves() -> list[CVE]:
    raw = json.loads((DATA_DIR / "cves.json").read_text())
    return [CVE.model_validate(c) for c in raw]

"""User preferences (theme, language) stored in settings.json next to the EXE."""
from __future__ import annotations

import json

from .paths import app_dir

DEFAULTS = {"theme": "light", "lang": "id"}


def _path():
    return app_dir() / "settings.json"


def load() -> dict:
    data = dict(DEFAULTS)
    try:
        data.update(json.loads(_path().read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    if data.get("theme") not in ("light", "dark"):
        data["theme"] = "light"
    if data.get("lang") not in ("id", "en"):
        data["lang"] = "id"
    return data


def save(data: dict) -> None:
    try:
        _path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass

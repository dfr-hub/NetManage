"""Filesystem locations that work both from source and from the PyInstaller EXE."""
from __future__ import annotations

import sys
from pathlib import Path


def app_dir() -> Path:
    """Folder that holds the EXE (or the project root when run from source)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_dir() -> Path:
    """Folder that holds bundled read-only resources."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", app_dir())) / "netmanage"
    return Path(__file__).resolve().parent


def bundled_templates() -> Path:
    return resource_dir() / "templates"


def user_templates() -> Path:
    """Optional override folder next to the EXE. Files here win over bundled ones."""
    return app_dir() / "templates"


def output_dir() -> Path:
    path = app_dir() / "output"
    path.mkdir(parents=True, exist_ok=True)
    return path

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
PY = sys.executable


@pytest.fixture
def make_hook(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Write a tiny Python hook script and return a shell command that runs it."""

    def _make(body: str, name: str = "hook.py") -> str:
        path = tmp_path / name
        path.write_text("import json, sys, os, time\npayload = json.load(sys.stdin)\n" + body, encoding="utf-8")
        return f"{PY} {path}"

    return _make


NAIVE = f"{PY} {EXAMPLES / 'hooks' / 'naive_guard.py'}"
HARDENED = f"{PY} {EXAMPLES / 'hooks' / 'hardened_guard.py'}"

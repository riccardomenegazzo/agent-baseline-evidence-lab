from __future__ import annotations

import tomllib
from pathlib import Path

import agent_baseline_lab


def test_package_version_matches_project_metadata() -> None:
    root = Path(__file__).resolve().parents[1]
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert agent_baseline_lab.__version__ == payload["project"]["version"]

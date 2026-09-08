from __future__ import annotations

import sys
from pathlib import Path

from agent_baseline_lab.fallback import run_fallback_workflow


def test_successful_fallback_is_evidenced_without_raw_output(tmp_path: Path) -> None:
    result = run_fallback_workflow(
        [sys.executable, "-c", "print('ok')"],
        cwd=tmp_path,
        output_path=tmp_path / "fallback.json",
    )
    assert result.agent_used is False
    assert result.human_review_required is True
    assert result.verified_success is True
    assert result.stdout_bytes > 0
    assert "ok" not in (tmp_path / "fallback.json").read_text(encoding="utf-8")


def test_dry_run_never_claims_success(tmp_path: Path) -> None:
    result = run_fallback_workflow(
        [sys.executable, "-c", "raise SystemExit(0)"],
        cwd=tmp_path,
        output_path=tmp_path / "fallback.json",
        dry_run=True,
    )
    assert result.attempted is False
    assert result.verified_success is False

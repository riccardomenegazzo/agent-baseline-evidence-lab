from __future__ import annotations

import json
from pathlib import Path

from agent_baseline_lab.unintended import analyze_session


def test_credential_and_code_cochange_is_detected_without_content_scan(tmp_path: Path) -> None:
    session = tmp_path / "session.json"
    session.write_text(
        json.dumps(
            {
                "session_id": "agent-1",
                "changes": {
                    "added": [".env", "src/app.py"],
                    "modified": [],
                    "removed": [],
                },
            }
        ),
        encoding="utf-8",
    )
    result = analyze_session(session)
    assert result.credential_code_cochange_detected is True
    assert result.credential_like_paths == [".env"]
    assert result.source_code_paths == ["src/app.py"]


def test_code_only_change_is_not_flagged(tmp_path: Path) -> None:
    session = tmp_path / "session.json"
    session.write_text(
        json.dumps(
            {
                "session_id": "agent-2",
                "changes": {"added": [], "modified": ["app.py"], "removed": []},
            }
        ),
        encoding="utf-8",
    )
    result = analyze_session(session)
    assert result.credential_code_cochange_detected is False
    assert result.severity == "none"

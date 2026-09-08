from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_baseline_lab.mcp_oauth_revocation as oauth
from agent_baseline_lab.commands import CommandResult


def test_dry_run_never_mutates_or_claims_revocation(tmp_path: Path) -> None:
    evidence = oauth.revoke_mcp_oauth(
        "notion",
        output_path=tmp_path / "oauth.json",
        dry_run=True,
    )
    assert evidence.remove_attempted is False
    assert evidence.before_status_attempted is False
    assert evidence.after_status_attempted is False
    assert evidence.revocation_verified is False
    assert evidence.secret_material_persisted is False


def test_live_revocation_requires_confirmation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="explicit confirmation"):
        oauth.revoke_mcp_oauth("notion", output_path=tmp_path / "oauth.json")


def test_verified_revocation_requires_observed_state_transition(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(oauth, "exists", lambda binary: binary == "sbx")
    calls: list[list[str]] = []

    def fake_run(args: list[str], timeout: int = 20) -> CommandResult:
        calls.append(list(args))
        if args[:4] == ["sbx", "mcp", "auth", "rm"]:
            return CommandResult(list(args), 0, "removed", "")
        status_calls = sum(1 for call in calls if call[:4] == ["sbx", "mcp", "auth", "status"])
        payload = {"server": "notion", "authorized": status_calls == 1, "grantedScopes": ["read"]}
        return CommandResult(list(args), 0, json.dumps(payload), "")

    monkeypatch.setattr(oauth, "run", fake_run)
    evidence = oauth.revoke_mcp_oauth(
        "notion",
        output_path=tmp_path / "oauth.json",
        confirmed=True,
    )
    assert evidence.before_authorized is True
    assert evidence.after_authorized is False
    assert evidence.remove_returncode == 0
    assert evidence.revocation_verified is True
    raw = (tmp_path / "oauth.json").read_text(encoding="utf-8")
    assert "token" not in raw.lower()


def test_unrecognized_after_state_never_claims_revocation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(oauth, "exists", lambda binary: binary == "sbx")
    status_index = 0

    def fake_run(args: list[str], timeout: int = 20) -> CommandResult:
        nonlocal status_index
        if args[:4] == ["sbx", "mcp", "auth", "rm"]:
            return CommandResult(list(args), 0, "", "")
        status_index += 1
        payload = {"authorized": True} if status_index == 1 else {"server": "notion", "state": "unknown"}
        return CommandResult(list(args), 0, json.dumps(payload), "")

    monkeypatch.setattr(oauth, "run", fake_run)
    evidence = oauth.revoke_mcp_oauth(
        "notion",
        output_path=tmp_path / "oauth.json",
        confirmed=True,
    )
    assert evidence.before_authorized is True
    assert evidence.after_authorized is None
    assert evidence.revocation_verified is False

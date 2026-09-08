from __future__ import annotations

from agent_baseline_lab.oauth_state import observe_oauth_state, sanitize


def test_oauth_state_redacts_secret_like_fields_recursively() -> None:
    sanitized, removed = sanitize(
        {
            "server": "notion",
            "authorized": True,
            "access_token": "should-never-persist",
            "nested": {
                "refreshToken": "also-secret",
                "granted_scopes": ["read"],
                "client_secret": "secret",
            },
        }
    )
    assert sanitized == {
        "server": "notion",
        "authorized": True,
        "nested": {"granted_scopes": ["read"]},
    }
    assert set(removed) == {
        "access_token",
        "nested.refreshToken",
        "nested.client_secret",
    }


def test_oauth_state_dry_run_never_claims_observation() -> None:
    result = observe_oauth_state("dhi", dry_run=True)
    assert result.observed is False
    assert result.raw_output_persisted is False
    assert result.sanitized_status == {}

from agent_baseline_lab import demo_preflight
from agent_baseline_lab.commands import CommandResult


def _result(args, *, returncode=0, stdout="", stderr=""):
    return CommandResult(list(args), returncode, stdout, stderr)


def test_host_check_accepts_supported_macos(monkeypatch):
    monkeypatch.setattr(demo_preflight.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(demo_preflight.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(demo_preflight.platform, "mac_ver", lambda: ("14.7.1", ("", "", ""), ""))

    check = demo_preflight._host_check()

    assert check.status == "PASS"
    assert check.required is True


def test_host_check_rejects_intel_macos(monkeypatch):
    monkeypatch.setattr(demo_preflight.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(demo_preflight.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(demo_preflight.platform, "mac_ver", lambda: ("15.6", ("", "", ""), ""))

    check = demo_preflight._host_check()

    assert check.status == "FAIL"
    assert "Apple silicon" in check.detail


def test_scout_is_optional_in_observe_mode(monkeypatch):
    monkeypatch.setattr(demo_preflight, "exists", lambda binary: binary == "docker")
    monkeypatch.setattr(
        demo_preflight,
        "run",
        lambda args, timeout=20: _result(args, returncode=1, stderr="scout unavailable"),
    )

    check = demo_preflight._docker_scout_check("observe")

    assert check.status == "WARN"
    assert check.required is False


def test_scout_is_required_in_gate_mode(monkeypatch):
    monkeypatch.setattr(demo_preflight, "exists", lambda binary: binary == "docker")
    monkeypatch.setattr(
        demo_preflight,
        "run",
        lambda args, timeout=20: _result(args, returncode=1, stderr="scout unavailable"),
    )

    check = demo_preflight._docker_scout_check("gate")

    assert check.status == "FAIL"
    assert check.required is True


def test_openai_credential_inventory_never_requires_secret_value(monkeypatch):
    monkeypatch.setattr(demo_preflight, "exists", lambda binary: binary == "sbx")
    monkeypatch.setattr(
        demo_preflight,
        "run",
        lambda args, timeout=20: _result(
            args,
            stdout='[{"service":"openai","scope":"global","source":"oauth"}]',
        ),
    )

    check = demo_preflight._openai_credential_check()

    assert check.status == "PASS"
    assert check.evidence == {"listing_returncode": 0, "credential_present": True}
    assert "token" not in str(check.evidence).lower()


def test_openai_credential_missing_fails_noninteractive_demo(monkeypatch):
    monkeypatch.setattr(demo_preflight, "exists", lambda binary: binary == "sbx")
    monkeypatch.setattr(
        demo_preflight,
        "run",
        lambda args, timeout=20: _result(args, stdout="[]"),
    )

    check = demo_preflight._openai_credential_check()

    assert check.status == "FAIL"
    assert "sbx secret set openai --oauth" in check.detail

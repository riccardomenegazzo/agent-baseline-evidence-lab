from pathlib import Path

import pytest

from agent_baseline_lab.customer_policy import (
    BUILTIN_PROFILE_NAMES,
    export_builtin_profile,
    load_policy_profile,
    policy_source_bytes,
)


def test_builtin_profiles_are_loadable_and_versioned():
    assert BUILTIN_PROFILE_NAMES == (
        "poc-observe",
        "enterprise-strict",
        "enterprise-supply-chain",
    )
    for name in BUILTIN_PROFILE_NAMES:
        profile, digest = load_policy_profile(f"builtin:{name}")
        assert profile["id"] == name
        assert profile["schema_version"] in {1, 2}
        assert profile["version"]
        assert len(digest) == 64

    supply_chain, _ = load_policy_profile("builtin:enterprise-supply-chain")
    assert supply_chain["schema_version"] == 2
    assert supply_chain["requirements"]["artifact_facts"] == {
        "sbom_present": True,
        "provenance_present": True,
        "subject_bindings_valid": True,
    }


def test_builtin_profile_can_be_exported(tmp_path: Path):
    output = tmp_path / "enterprise-strict.yaml"

    exported = export_builtin_profile("enterprise-strict", output)
    profile, digest = load_policy_profile(exported)
    builtin_profile, builtin_digest = load_policy_profile("builtin:enterprise-strict")

    assert exported == output
    assert profile == builtin_profile
    assert digest == builtin_digest
    assert output.read_bytes() == policy_source_bytes("builtin:enterprise-strict")


def test_artifact_aware_builtin_can_be_exported(tmp_path: Path):
    output = tmp_path / "enterprise-supply-chain.yaml"

    export_builtin_profile("enterprise-supply-chain", output)
    profile, digest = load_policy_profile(output)
    builtin, builtin_digest = load_policy_profile("builtin:enterprise-supply-chain")

    assert profile == builtin
    assert digest == builtin_digest
    assert profile["schema_version"] == 2


def test_export_refuses_overwrite_without_force(tmp_path: Path):
    output = tmp_path / "policy.yaml"
    output.write_text("existing\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        export_builtin_profile("poc-observe", output)

    export_builtin_profile("poc-observe", output, force=True)
    assert b"id: poc-observe" in output.read_bytes()


def test_unknown_builtin_profile_fails_closed():
    with pytest.raises(ValueError, match="unknown built-in policy profile"):
        policy_source_bytes("builtin:does-not-exist")

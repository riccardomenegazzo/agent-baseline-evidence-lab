from importlib.resources import files
from pathlib import Path

import pytest

from agent_baseline_lab.cli import main
from agent_baseline_lab.customer_trust_flow import run_customer_trust_flow
from agent_baseline_lab.present import build_presentation
from agent_baseline_lab.signing import validate_keypair
from agent_baseline_lab.workspace import WORKSPACE_FILES, initialize_workspace


def test_workspace_runs_complete_dry_run_without_repository(tmp_path, monkeypatch):
    root = initialize_workspace(tmp_path / "demo with spaces")
    monkeypatch.chdir(root)
    summary = run_customer_trust_flow(root, dry_run=True, scout_mode="off")
    presented = build_presentation(root)
    assert summary.overall_status == "DRY_RUN"
    assert summary.trusted_artifact_status == "NOT_RUN"
    assert summary.lineage_verified is False
    assert presented.handoff_verified and presented.handoff_signature_verified
    assert presented.run_id == summary.assessment_run_id


def test_packaged_templates_match_repository_examples():
    # Keep the wheel walkthrough aligned with the examples maintained in the repo.
    root = Path(__file__).resolve().parents[1]
    templates = files("agent_baseline_lab").joinpath("workspace_templates")
    for name in WORKSPACE_FILES:
        assert templates.joinpath(name + ".template").read_bytes() == (root / name).read_bytes()


def test_init_repeated_preserves_workspace_and_keys(tmp_path):
    root = initialize_workspace(tmp_path / "demo")
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert main(["init", str(root)]) == 2
    after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before == after
    assert validate_keypair(root / ".abl/keys/attestation-private.json", root / ".abl/keys/attestation-public.json")


@pytest.mark.parametrize("kind", ["file", "empty-dir", "symlink", "dangling-symlink"])
def test_init_refuses_existing_destination(tmp_path, kind):
    target = tmp_path / "existing"
    if kind == "file":
        target.write_text("keep")
    elif kind == "empty-dir":
        target.mkdir()
    else:
        other = tmp_path / "other"
        if kind == "symlink":
            other.mkdir()
        target.symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="already exists"):
        initialize_workspace(target)

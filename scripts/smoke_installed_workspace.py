"""Exercise the installed wheel in a new directory, without checkout imports."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="abl-wheel-smoke-") as temporary:
        parent = Path(temporary)
        workspace = parent / "workspace with spaces"

        def run(module: str, *args: str, cwd: Path = parent):
            return subprocess.run(
                [sys.executable, "-I", "-m", "agent_baseline_lab." + module, *args],
                cwd=cwd, check=True, text=True, capture_output=True,
            )

        print(run("cli", "init", str(workspace)).stdout)
        print(run("trust_cli", "--dry-run", "--scout-mode", "off", cwd=workspace).stdout)
        payload = json.loads(run("present", "--json", cwd=workspace).stdout)
        assert payload["dry_run"] is True
        assert payload["overall_status"] == "DRY_RUN"
        assert payload["trusted_artifact_status"] == "NOT_RUN"
        assert payload["lineage_verified"] is False
        assert payload["handoff_verified"] is True
        assert payload["handoff_signature_verified"] is True
        print("Installed wheel: workspace, dry-run and signed presentation verified.")


if __name__ == "__main__":
    main()

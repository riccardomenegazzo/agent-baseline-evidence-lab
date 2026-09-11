from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from . import __version__
from .signing import generate_keypair


WORKSPACE_FILES = (
    '.gitignore',
    'examples/agent.yaml',
    'examples/agent-mcp.yaml',
    'examples/task.md',
    'examples/task-mcp.md',
    'sample-app/Dockerfile',
    'sample-app/app.py',
    'sample-app/tests/test_app.py',
    'scripts/check_dockerfile.py',
    'policies/mcp/strict-reference.cedar',
    'policies/mcp/dhi-readonly.cedar',
    'policies/scout/trusted-artifact.json',
)


def initialize_workspace(destination: str | Path) -> Path:
    """Create a new standalone workspace without changing an existing directory.

    Initialization is offline. Keys are generated locally; no key material or
    collected evidence is shipped in the template. An interrupted write leaves
    an incomplete directory for inspection rather than deleting user files.
    """
    root = Path(destination).absolute()
    # Load all packaged inputs before creating anything at the destination.
    templates = files("agent_baseline_lab").joinpath("workspace_templates")
    contents = {
        name: templates.joinpath(name + ".template").read_bytes()
        for name in WORKSPACE_FILES
    }
    root.parent.mkdir(parents=True, exist_ok=True)
    try:
        root.mkdir()
    except FileExistsError as exc:
        raise ValueError("workspace destination already exists; choose a new directory") from exc
    for name, data in contents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    generate_keypair(
        root / ".abl" / "keys" / "attestation-private.json",
        root / ".abl" / "keys" / "attestation-public.json",
    )
    (root / "README.md").write_text(
        f"# Agent Baseline Evidence Lab workspace\n\n"
        f"Created with version {__version__}. The bundled configurations use synthetic lab identities.\n\n"
        "From this directory, using the Python environment where the wheel is installed:\n\n"
        "```bash\nabl-trust --dry-run --scout-mode off\nabl-present --open\n```\n\n"
        "Expected: overall DRY_RUN, trusted artifact NOT_RUN and lineage false.\n"
        "Initialization and dry-run do not require a Docker daemon or model credentials.\n"
        "The local signing key is private; do not share the .abl directory. Share only the\n"
        "intended handoff and verification material. Establish trust in a public key separately.\n\n"
        "For live prerequisites, baseline setup, key handling and verification limits, see:\n"
        "https://github.com/riccardomenegazzo/agent-baseline-evidence-lab/blob/main/docs/DEMO_GUIDE.md\n",
        encoding="utf-8",
    )
    return root

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .baseline import verify_lock
from .signing import validate_keypair
from .commands import CommandResult, exists, parse_json_output, run


@dataclass(frozen=True)
class DemoPreflightCheck:
    name: str
    status: str
    required: bool
    detail: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DemoPreflightSummary:
    schema_version: int
    scout_mode: str
    sandbox_smoke: bool
    ready: bool
    required_failures: int
    checks: list[DemoPreflightCheck]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scout_mode": self.scout_mode,
            "sandbox_smoke": self.sandbox_smoke,
            "ready": self.ready,
            "required_failures": self.required_failures,
            "checks": [check.to_dict() for check in self.checks],
            "claims_boundary": self.claims_boundary,
        }


def _first_line(result: CommandResult, fallback: str) -> str:
    text = result.stdout or result.stderr
    return text.splitlines()[0] if text else fallback


def _major(version: str) -> int:
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, IndexError):
        return 0


def _host_check() -> DemoPreflightCheck:
    system = platform.system()
    machine = platform.machine().lower()
    evidence: dict[str, Any] = {"system": system, "machine": machine}

    if system == "Darwin":
        version = platform.mac_ver()[0]
        evidence["macos_version"] = version
        apple_silicon = machine in {"arm64", "aarch64"}
        supported_version = _major(version) >= 14
        ok = apple_silicon and supported_version
        detail = f"macOS {version or 'unknown'} on {machine or 'unknown architecture'}"
        if not ok:
            detail += "; Docker Sandboxes on macOS requires Sonoma 14+ on Apple silicon"
        return DemoPreflightCheck(
            name="host-platform",
            status="PASS" if ok else "FAIL",
            required=True,
            detail=detail,
            evidence={
                **evidence,
                "requires_macos_major": 14,
                "requires_apple_silicon": True,
            },
        )

    supported = system in {"Linux", "Windows"}
    return DemoPreflightCheck(
        name="host-platform",
        status="PASS" if supported else "FAIL",
        required=True,
        detail=(
            f"{system or 'unknown OS'} on {machine or 'unknown architecture'}; "
            "platform-family check only outside macOS"
        ),
        evidence=evidence,
    )


def _binary_check(name: str, args: list[str], *, required: bool = True) -> DemoPreflightCheck:
    binary = args[0]
    if not exists(binary):
        return DemoPreflightCheck(
            name=name,
            status="FAIL" if required else "WARN",
            required=required,
            detail=f"{binary} is not available on PATH",
            evidence={},
        )
    result = run(args, timeout=20)
    return DemoPreflightCheck(
        name=name,
        status="PASS" if result.ok else ("FAIL" if required else "WARN"),
        required=required,
        detail=_first_line(result, f"{binary} found"),
        evidence={"returncode": result.returncode},
    )


def _docker_daemon_check() -> DemoPreflightCheck:
    if not exists("docker"):
        return DemoPreflightCheck(
            name="docker-daemon",
            status="FAIL",
            required=True,
            detail="docker CLI is unavailable",
            evidence={},
        )
    result = run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)
    return DemoPreflightCheck(
        name="docker-daemon",
        status="PASS" if result.ok else "FAIL",
        required=True,
        detail=(
            f"Docker daemon reachable: {_first_line(result, 'server version observed')}"
            if result.ok
            else "Docker daemon is not reachable; start Docker Desktop/Engine before the live trust flow"
        ),
        evidence={"returncode": result.returncode},
    )


def _docker_buildx_check() -> DemoPreflightCheck:
    if not exists("docker"):
        return DemoPreflightCheck(
            name="docker-buildx",
            status="FAIL",
            required=True,
            detail="docker CLI is unavailable",
            evidence={},
        )
    result = run(["docker", "buildx", "version"], timeout=20)
    return DemoPreflightCheck(
        name="docker-buildx",
        status="PASS" if result.ok else "FAIL",
        required=True,
        detail=_first_line(result, "Docker Buildx unavailable"),
        evidence={"returncode": result.returncode},
    )


def _docker_scout_check(scout_mode: str) -> DemoPreflightCheck:
    if scout_mode == "off":
        return DemoPreflightCheck(
            name="docker-scout",
            status="N/A",
            required=False,
            detail="Docker Scout is outside the selected demo decision boundary",
            evidence={"mode": scout_mode},
        )
    required = scout_mode == "gate"
    if not exists("docker"):
        return DemoPreflightCheck(
            name="docker-scout",
            status="FAIL" if required else "WARN",
            required=required,
            detail="docker CLI is unavailable",
            evidence={"mode": scout_mode},
        )
    result = run(["docker", "scout", "version"], timeout=20)
    return DemoPreflightCheck(
        name="docker-scout",
        status="PASS" if result.ok else ("FAIL" if required else "WARN"),
        required=required,
        detail=(
            _first_line(result, "Docker Scout available")
            if result.ok
            else (
                "Docker Scout unavailable; observe mode can continue without making Scout a hard gate"
                if not required
                else "Docker Scout is required because scout-mode=gate"
            )
        ),
        evidence={"mode": scout_mode, "returncode": result.returncode},
    )


def _contains_service(payload: Any, service: str) -> bool:
    target = service.lower()
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key).lower() == "service" and str(value).lower() == target:
                return True
            if _contains_service(value, service):
                return True
        return False
    if isinstance(payload, list):
        return any(_contains_service(item, service) for item in payload)
    return False


def _openai_credential_check() -> DemoPreflightCheck:
    if not exists("sbx"):
        return DemoPreflightCheck(
            name="codex-host-credential",
            status="FAIL",
            required=True,
            detail="sbx is unavailable; cannot verify host-managed Codex authentication",
            evidence={},
        )
    result = run(["sbx", "secret", "ls", "--service", "openai", "--json"], timeout=20)
    payload = parse_json_output(result)
    present = result.ok and (
        _contains_service(payload, "openai")
        or (bool(payload) and "openai" in result.stdout.lower())
    )
    return DemoPreflightCheck(
        name="codex-host-credential",
        status="PASS" if present else "FAIL",
        required=True,
        detail=(
            "host-managed OpenAI credential is registered for Docker Sandboxes"
            if present
            else "no stored OpenAI credential observed; run `sbx secret set openai --oauth` before the interview"
        ),
        evidence={"listing_returncode": result.returncode, "credential_present": present},
    )


def _sbx_control_plane_check() -> DemoPreflightCheck:
    if not exists("sbx"):
        return DemoPreflightCheck(
            name="sbx-control-plane",
            status="FAIL",
            required=True,
            detail="sbx is unavailable",
            evidence={},
        )
    result = run(["sbx", "ls", "--json"], timeout=30)
    return DemoPreflightCheck(
        name="sbx-control-plane",
        status="PASS" if result.ok else "FAIL",
        required=True,
        detail=(
            "Docker Sandboxes control plane responded"
            if result.ok
            else "Docker Sandboxes is not ready; run `sbx login` and `sbx diagnose` before the demo"
        ),
        evidence={"returncode": result.returncode},
    )


def _sbx_policy_check() -> DemoPreflightCheck:
    if not exists("sbx"):
        return DemoPreflightCheck(
            name="sbx-policy",
            status="FAIL",
            required=True,
            detail="sbx is unavailable",
            evidence={},
        )
    result = run(["sbx", "policy", "ls", "--json"], timeout=30)
    return DemoPreflightCheck(
        name="sbx-policy",
        status="PASS" if result.ok else "FAIL",
        required=True,
        detail=(
            "Docker Sandboxes policy state is inspectable"
            if result.ok
            else (
                "sandbox policy is not inspectable; initialize a deliberate preset before the demo, "
                "for example `sbx policy init balanced`"
            )
        ),
        evidence={"returncode": result.returncode},
    )


def _baseline_check(root: Path, baseline_cache: str | Path) -> DemoPreflightCheck:
    cache = Path(baseline_cache)
    if not cache.is_absolute():
        cache = root / cache
    ok, errors, summary = verify_lock(cache)
    return DemoPreflightCheck(
        name="baseline-lock",
        status="PASS" if ok else "FAIL",
        required=True,
        detail="cached Agent Baseline lock verified" if ok else "; ".join(errors),
        evidence=summary,
    )


def _signing_check(root: Path) -> DemoPreflightCheck:
    private_key = root / ".abl" / "keys" / "attestation-private.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    present = private_key.is_file() and public_key.is_file()
    valid = False
    detail = "signing keypair missing; use `abl init` for a new workspace or initialize keys once"
    if present:
        try:
            validate_keypair(private_key, public_key)
            valid = True
            detail = "local Ed25519 signing keypair is valid and matches"
        except (OSError, ValueError, RecursionError):
            detail = "signing keypair is malformed or mismatched; restore the matching pair"
    return DemoPreflightCheck(
        name="signing-keypair",
        status="PASS" if valid else "FAIL",
        required=True,
        detail=detail,
        evidence={
            "private_key_present": private_key.is_file(),
            "public_key_present": public_key.is_file(),
        },
    )


def _repo_assets_check(root: Path) -> DemoPreflightCheck:
    required_paths = [
        root / "examples" / "agent.yaml",
        root / "examples" / "task.md",
        root / "sample-app" / "Dockerfile",
        root / "sample-app" / "tests",
    ]
    missing = [path.relative_to(root).as_posix() for path in required_paths if not path.exists()]
    return DemoPreflightCheck(
        name="demo-assets",
        status="PASS" if not missing else "FAIL",
        required=True,
        detail="customer demo assets are present" if not missing else "missing: " + ", ".join(missing),
        evidence={"missing": missing},
    )


def _sandbox_smoke_check(root: Path) -> DemoPreflightCheck:
    if not exists("sbx"):
        return DemoPreflightCheck(
            name="sandbox-smoke",
            status="FAIL",
            required=True,
            detail="sbx is unavailable",
            evidence={},
        )

    workspace = root / "sample-app"
    sandbox = f"abl-preflight-{os.getpid()}"
    create = run(
        [
            "sbx",
            "create",
            "--name",
            sandbox,
            "--deny-network",
            "exfiltration.invalid",
            "shell",
            str(workspace),
        ],
        timeout=120,
    )
    if not create.ok:
        return DemoPreflightCheck(
            name="sandbox-smoke",
            status="FAIL",
            required=True,
            detail=(
                "disposable Docker Sandbox could not be created; ensure sbx login, virtualization and the "
                "global network-policy preset are ready"
            ),
            evidence={"create_returncode": create.returncode},
        )

    execute = run(["sbx", "exec", sandbox, "true"], timeout=60)
    policy = run(["sbx", "policy", "ls", sandbox, "--json"], timeout=30)
    deny_recorded = policy.ok and "exfiltration.invalid" in policy.stdout
    remove = run(["sbx", "rm", sandbox], timeout=60)
    ok = execute.ok and deny_recorded and remove.ok

    return DemoPreflightCheck(
        name="sandbox-smoke",
        status="PASS" if ok else "FAIL",
        required=True,
        detail=(
            "disposable sandbox created, executed, recorded the deny rule and was removed"
            if ok
            else "sandbox smoke was incomplete; inspect sbx policy/daemon state before the interview"
        ),
        evidence={
            "create_returncode": create.returncode,
            "exec_returncode": execute.returncode,
            "deny_rule_recorded": deny_recorded,
            "remove_returncode": remove.returncode,
        },
    )


def run_demo_preflight(
    root_path: str | Path = ".",
    *,
    baseline_cache: str | Path = ".cache/agentbaseline",
    scout_mode: str = "observe",
    sandbox_smoke: bool = False,
) -> DemoPreflightSummary:
    if scout_mode not in {"off", "observe", "gate"}:
        raise ValueError("scout_mode must be one of: off, observe, gate")

    root = Path(root_path).resolve()
    checks = [
        _host_check(),
        DemoPreflightCheck(
            name="python-version",
            status="PASS" if sys.version_info >= (3, 11) else "FAIL",
            required=True,
            detail=f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            evidence={"minimum": "3.11"},
        ),
        _binary_check("docker-cli", ["docker", "--version"]),
        _docker_daemon_check(),
        _docker_buildx_check(),
        _docker_scout_check(scout_mode),
        _binary_check("sbx-cli", ["sbx", "version"]),
        _sbx_control_plane_check(),
        _sbx_policy_check(),
        _openai_credential_check(),
        _baseline_check(root, baseline_cache),
        _signing_check(root),
        _repo_assets_check(root),
    ]
    if sandbox_smoke:
        checks.append(_sandbox_smoke_check(root))

    required_failures = sum(check.required and check.status != "PASS" for check in checks)
    return DemoPreflightSummary(
        schema_version=1,
        scout_mode=scout_mode,
        sandbox_smoke=sandbox_smoke,
        ready=required_failures == 0,
        required_failures=required_failures,
        checks=checks,
        claims_boundary=(
            "This preflight proves only that the observed host, Docker, Docker Sandboxes, credential and repository "
            "prerequisites were ready at check time. A sandbox smoke proves one disposable microVM lifecycle and one "
            "recorded deny rule; it does not prove the later coding-agent task, every network decision, Docker Scout "
            "policy outcome, OCI trust chain or customer disposition will pass."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight the live Customer Trust Flow before a demo")
    parser.add_argument("--root", default=".")
    parser.add_argument("--baseline-cache", default=".cache/agentbaseline")
    parser.add_argument("--scout-mode", choices=["off", "observe", "gate"], default="observe")
    parser.add_argument(
        "--sandbox-smoke",
        action="store_true",
        help="create and remove a disposable shell sandbox to prove local microVM/policy readiness",
    )
    parser.add_argument("--output", default="reports/demo-preflight.json")
    args = parser.parse_args(argv)

    try:
        summary = run_demo_preflight(
            args.root,
            baseline_cache=args.baseline_cache,
            scout_mode=args.scout_mode,
            sandbox_smoke=args.sandbox_smoke,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("LIVE DEMO PREFLIGHT")
    for check in summary.checks:
        requirement = "required" if check.required else "optional"
        print(f"  {check.status:4}  {check.name:24} {requirement:8}  {check.detail}")
    print(f"\nREADY: {'yes' if summary.ready else 'no'}")
    print(f"report: {output}")
    return 0 if summary.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())


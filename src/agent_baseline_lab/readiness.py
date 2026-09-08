from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .baseline import verify_lock
from .commands import exists, run
from .mcp_inventory import collect_mcp_inventory, evaluate_inventory


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: str
    required: bool
    detail: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReadinessSummary:
    schema_version: int
    profile: str
    ready: bool
    required_failures: int
    checks: list[ReadinessCheck]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "ready": self.ready,
            "required_failures": self.required_failures,
            "checks": [check.to_dict() for check in self.checks],
            "claims_boundary": self.claims_boundary,
        }


def _binary_check(binary: str, *, required: bool) -> ReadinessCheck:
    if not exists(binary):
        return ReadinessCheck(
            name=f"binary:{binary}",
            status="FAIL" if required else "WARN",
            required=required,
            detail=f"{binary} is not available on PATH",
            evidence={},
        )
    result = run([binary, "--version"], timeout=15)
    if binary == "sbx" and not result.ok:
        result = run([binary, "version"], timeout=15)
    return ReadinessCheck(
        name=f"binary:{binary}",
        status="PASS" if result.ok else ("FAIL" if required else "WARN"),
        required=required,
        detail=(result.stdout or result.stderr or f"{binary} found").splitlines()[0],
        evidence={"returncode": result.returncode},
    )


def _baseline_check(cache_dir: Path) -> ReadinessCheck:
    ok, errors, summary = verify_lock(cache_dir)
    return ReadinessCheck(
        name="baseline-lock",
        status="PASS" if ok else "FAIL",
        required=True,
        detail="cached Agent Baseline source lock verified" if ok else "; ".join(errors),
        evidence=summary,
    )


def _signing_check(root: Path) -> ReadinessCheck:
    private_key = root / ".abl" / "keys" / "attestation-private.json"
    public_key = root / ".abl" / "keys" / "attestation-public.json"
    present = private_key.exists() and public_key.exists()
    return ReadinessCheck(
        name="signing-keypair",
        status="PASS" if present else "WARN",
        required=False,
        detail=(
            "local Ed25519 signing keypair is available"
            if present
            else "optional local signing keypair is not initialized; run `make signing-keygen`"
        ),
        evidence={
            "private_key_present": private_key.exists(),
            "public_key_present": public_key.exists(),
        },
    )


def _mcp_dhi_check() -> ReadinessCheck:
    observed, registrations, note = collect_mcp_inventory()
    result = evaluate_inventory(
        registrations,
        expected={"dhi": "https://dhi.io/mcp"},
        observed=observed,
    )
    ok = (
        observed
        and not result.missing_expected_names
        and not result.identity_mismatches
    )
    return ReadinessCheck(
        name="mcp-registration:dhi",
        status="PASS" if ok else "FAIL",
        required=True,
        detail=(
            "DHI MCP registration identity matches https://dhi.io/mcp"
            if ok
            else note
            or "; ".join(result.missing_expected_names + result.identity_mismatches)
            or "DHI MCP registration could not be verified"
        ),
        evidence=result.to_dict(),
    )


def run_readiness(
    root_path: str | Path = ".",
    *,
    profile: str = "community",
    baseline_cache: str | Path = ".cache/agentbaseline",
) -> ReadinessSummary:
    if profile not in {"community", "mcp"}:
        raise ValueError("profile must be 'community' or 'mcp'")
    root = Path(root_path).resolve()
    cache = Path(baseline_cache)
    if not cache.is_absolute():
        cache = root / cache

    py_ok = sys.version_info >= (3, 11)
    checks = [
        ReadinessCheck(
            name="python-version",
            status="PASS" if py_ok else "FAIL",
            required=True,
            detail=f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            evidence={"minimum": "3.11"},
        ),
        _binary_check("docker", required=True),
        _binary_check("sbx", required=True),
        _baseline_check(cache),
        _signing_check(root),
    ]

    sample_config = root / "examples" / ("agent-mcp.yaml" if profile == "mcp" else "agent.yaml")
    checks.append(
        ReadinessCheck(
            name="assessment-config",
            status="PASS" if sample_config.is_file() else "FAIL",
            required=True,
            detail=str(sample_config),
            evidence={"exists": sample_config.is_file()},
        )
    )

    if profile == "mcp":
        checks.append(_mcp_dhi_check())

    required_failures = sum(check.required and check.status != "PASS" for check in checks)
    return ReadinessSummary(
        schema_version=1,
        profile=profile,
        ready=required_failures == 0,
        required_failures=required_failures,
        checks=checks,
        claims_boundary=(
            "Readiness proves only that local prerequisites and declared pre-demo dependencies were observed. "
            "It does not prove a live agent run will succeed, Docker AI Governance is licensed/enforced, "
            "or that later runtime evidence will satisfy Agent Baseline controls."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local readiness for an Agent Baseline demo")
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", choices=["community", "mcp"], default="community")
    parser.add_argument("--baseline-cache", default=".cache/agentbaseline")
    parser.add_argument("--output", default="reports/readiness.json")
    args = parser.parse_args(argv)
    try:
        summary = run_readiness(
            args.root,
            profile=args.profile,
            baseline_cache=args.baseline_cache,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    return 0 if summary.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())

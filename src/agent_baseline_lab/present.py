from __future__ import annotations

import argparse
import json
import re
import zipfile
import webbrowser
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .signing import verify_signature
from .trust_handoff import verify_handoff_pack


@dataclass(frozen=True)
class PresentationSummary:
    schema_version: int
    run_id: str
    dry_run: bool
    decision: str
    overall_status: str
    trusted_artifact_status: str
    scout_status: str
    lineage_verified: bool
    handoff_verified: bool
    handoff_signature_verified: bool
    artifacts: dict[str, str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"abl-[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise ValueError("invalid assessment run ID")
    return value


def _local_file(root: Path, value: str | Path) -> Path:
    path = (root / value).resolve()
    if not path.is_relative_to(root):
        raise ValueError("presentation artifact must stay inside project root")
    return path


def _select_summary(root: Path, run_id: str | None = None) -> Path:
    reports = root / "reports"
    if run_id:
        candidate = _local_file(root, reports / f"{_run_id(run_id)}.customer-trust-flow.json")
        if not candidate.is_file():
            raise ValueError(f"Customer Trust Flow summary not found for run {run_id}")
        return candidate

    candidates = sorted(
        reports.glob("abl-*.customer-trust-flow.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise ValueError("no Customer Trust Flow summary found; run `abl-trust` first")

    for candidate in candidates:
        try:
            if not bool(_load_json(candidate).get("dry_run", False)):
                return candidate
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return candidates[0]


def build_presentation(
    root_path: str | Path = ".",
    *,
    run_id: str | None = None,
) -> PresentationSummary:
    root = Path(root_path).resolve()
    summary_path = _local_file(root, _select_summary(root, run_id=run_id))
    payload = _load_json(summary_path)
    selected_run_id = _run_id(payload.get("assessment_run_id"))
    if summary_path.name != f"{selected_run_id}.customer-trust-flow.json":
        raise ValueError("summary filename does not match assessment run ID")
    if type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise ValueError("unsupported presentation summary schema_version")

    trust_dir = _local_file(root, root / "reports" / f"{selected_run_id}.trust")
    handoff = _local_file(root, str(payload.get("handoff_pack", "")))
    signature = _local_file(root, str(payload.get("handoff_signature", "")))
    public_key = _local_file(root, str(payload.get("public_key", "")))

    required = {
        "flow_html": trust_dir / "customer-trust-flow.html",
        "decision_html": trust_dir / "customer-decision.portable.html",
        "trusted_artifact": trust_dir / "trusted-artifact.portable.json",
        "handoff": handoff,
        "handoff_signature": signature,
        "public_key": public_key,
    }
    required = {name: _local_file(root, path) for name, path in required.items()}
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise ValueError("presentation artifacts are missing: " + ", ".join(missing))

    lineage = _local_file(root, trust_dir / "agent-artifact-lineage.json")
    artifacts = {name: path.relative_to(root).as_posix() for name, path in required.items()}
    if lineage.is_file():
        artifacts["lineage"] = lineage.relative_to(root).as_posix()

    handoff_ok, handoff_errors, details = verify_handoff_pack(handoff)
    signature_ok, signature_errors, _ = verify_signature(
        handoff,
        signature,
        public_key_path=public_key,
    )
    if not handoff_ok:
        raise ValueError("handoff verification failed: " + "; ".join(handoff_errors))
    if not signature_ok:
        raise ValueError("handoff signature verification failed: " + "; ".join(signature_errors))

    # A valid ZIP does not authenticate its neighboring report files or summary.
    # Bind every displayed artifact and status to the verified, signed package.
    if payload.get("handoff_pack_sha256") != details.get("pack_sha256"):
        raise ValueError("summary handoff digest does not match verified package")
    with zipfile.ZipFile(handoff) as zf:
        manifest = json.loads(zf.read("handoff-manifest.json"))
        roles = {item["role"]: item["path"] for item in manifest["files"]}

        def member(role: str) -> bytes:
            if role not in roles:
                raise ValueError(f"presentation handoff is missing role: {role}")
            return zf.read(roles[role])

        bound_roles = {
            "flow_html": "customer-trust-flow-html",
            "decision_html": "customer-decision-html",
            "trusted_artifact": "trusted-artifact",
            "public_key": "public-verification-key",
        }
        if "agent-artifact-lineage" in roles:
            if not lineage.is_file():
                raise ValueError("presentation artifacts are missing: lineage")
            bound_roles["lineage"] = "agent-artifact-lineage"
        elif lineage.is_file():
            raise ValueError("local lineage is absent from signed handoff")
        for name, role in bound_roles.items():
            if (root / artifacts[name]).read_bytes() != member(role):
                raise ValueError(f"presentation artifact differs from signed handoff: {name}")

        decision = json.loads(member("customer-decision"))
        trusted = json.loads(member("trusted-artifact"))
        if not isinstance(decision, dict) or not isinstance(trusted, dict):
            raise ValueError("signed presentation reports must be JSON objects")
        dry_run = manifest.get("dry_run")
        if type(dry_run) is not bool:
            raise ValueError("handoff dry_run must be a boolean")
        if manifest.get("source_run_id") != selected_run_id:
            raise ValueError("signed handoff belongs to a different assessment run")
        if decision.get("assessment_run_id") != selected_run_id:
            raise ValueError("signed decision belongs to a different assessment run")
        lineage_verified = details.get("lineage_signature_verified", False)
        if dry_run and lineage_verified:
            raise ValueError("dry-run handoff cannot claim live lineage")
        signed_decision = decision.get("decision")
        if signed_decision not in {"BLOCKED", "CONDITIONAL", "EVIDENCE_READY"}:
            raise ValueError("unsupported signed decision status")
        expected = {
            "dry_run": dry_run,
            "decision": signed_decision,
            "trusted_artifact_status": trusted.get("overall_status"),
            "scout_status": trusted.get("scout_status"),
            "lineage_verified": lineage_verified,
            "overall_status": (
                "DRY_RUN" if dry_run else signed_decision if lineage_verified else "BLOCKED"
            ),
        }
        for field, value in expected.items():
            if value is None or type(payload.get(field)) is not type(value) or payload[field] != value:
                raise ValueError(f"presentation summary disagrees with signed evidence: {field}")

    return PresentationSummary(
        schema_version=1,
        run_id=selected_run_id,
        dry_run=bool(payload.get("dry_run", False)),
        decision=str(payload.get("decision", "")),
        overall_status=str(payload.get("overall_status", "")),
        trusted_artifact_status=str(payload.get("trusted_artifact_status", "")),
        scout_status=str(payload.get("scout_status", "")),
        lineage_verified=bool(payload.get("lineage_verified", False)),
        handoff_verified=handoff_ok,
        handoff_signature_verified=signature_ok,
        artifacts=artifacts,
        claims_boundary=(
            "This helper verifies the final handoff signature against the selected local public key and binds "
            "the displayed files and summary to its signed contents. Key-owner identity is not established. "
            "It prefers the latest live run unless --run-id is supplied. It does not replay assessment, OCI, "
            "or workspace lineage verification; lineage status reflects the signed packaged evidence."
        ),
    )


def _print(summary: PresentationSummary) -> None:
    print("CUSTOMER TRUST PRESENTATION")
    print(f"  run:               {summary.run_id}")
    print(f"  dry-run:           {summary.dry_run}")
    print(f"  decision:          {summary.decision}")
    print(f"  overall:           {summary.overall_status}")
    print(f"  trusted artifact:  {summary.trusted_artifact_status}")
    print(f"  Docker Scout:      {summary.scout_status}")
    print(f"  lineage verified:  {summary.lineage_verified}")
    print(f"  handoff verified:  {summary.handoff_verified}")
    print(f"  handoff signed:    {summary.handoff_signature_verified}")
    print("  show in this order:")
    for name in ("flow_html", "decision_html", "trusted_artifact", "lineage", "handoff"):
        value = summary.artifacts.get(name)
        if value:
            print(f"    - {name:<18} {value}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify and present the latest Customer Trust Flow artifacts"
    )
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--run-id",
        default=None,
        help="present one exact assessment run instead of auto-selecting the latest live run",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the trust-flow and decision HTML pages in the default browser",
    )
    args = parser.parse_args(argv)

    try:
        summary = build_presentation(args.root, run_id=args.run_id)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    if args.as_json:
        print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))
    else:
        _print(summary)

    if args.open:
        root = Path(args.root).resolve()
        for name in ("flow_html", "decision_html"):
            value = summary.artifacts.get(name)
            if value:
                webbrowser.open((root / value).resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


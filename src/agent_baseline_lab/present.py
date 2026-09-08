from __future__ import annotations

import argparse
import json
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


def _latest_summary(root: Path) -> Path:
    candidates = sorted(
        (root / "reports").glob("abl-*.customer-trust-flow.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise ValueError("no Customer Trust Flow summary found; run `abl-trust` first")
    return candidates[0]


def build_presentation(root_path: str | Path = ".") -> PresentationSummary:
    root = Path(root_path).resolve()
    summary_path = _latest_summary(root)
    payload = _load_json(summary_path)
    run_id = str(payload.get("assessment_run_id", ""))
    if not run_id:
        raise ValueError(f"Customer Trust Flow summary has no assessment_run_id: {summary_path}")

    trust_dir = root / "reports" / f"{run_id}.trust"
    handoff = root / str(payload.get("handoff_pack", ""))
    signature = root / str(payload.get("handoff_signature", ""))
    public_key = root / str(payload.get("public_key", ""))

    required = {
        "flow_html": trust_dir / "customer-trust-flow.html",
        "decision_html": trust_dir / "customer-decision.portable.html",
        "trusted_artifact": trust_dir / "trusted-artifact.portable.json",
        "handoff": handoff,
        "handoff_signature": signature,
        "public_key": public_key,
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise ValueError("presentation artifacts are missing: " + ", ".join(missing))

    lineage = trust_dir / "agent-artifact-lineage.json"
    artifacts = {
        name: path.relative_to(root).as_posix()
        for name, path in required.items()
    }
    if lineage.is_file():
        artifacts["lineage"] = lineage.relative_to(root).as_posix()

    handoff_ok, handoff_errors, _ = verify_handoff_pack(handoff)
    signature_ok, signature_errors, _ = verify_signature(
        handoff,
        signature,
        public_key_path=public_key,
    )
    if not handoff_ok:
        raise ValueError("handoff verification failed: " + "; ".join(handoff_errors))
    if not signature_ok:
        raise ValueError("handoff signature verification failed: " + "; ".join(signature_errors))

    return PresentationSummary(
        schema_version=1,
        run_id=run_id,
        decision=str(payload.get("decision", "")),
        overall_status=str(payload.get("overall_status", "")),
        trusted_artifact_status=str(payload.get("trusted_artifact_status", "")),
        scout_status=str(payload.get("scout_status", "")),
        lineage_verified=bool(payload.get("lineage_verified", False)),
        handoff_verified=handoff_ok,
        handoff_signature_verified=signature_ok,
        artifacts=artifacts,
        claims_boundary=(
            "This helper verifies the final handoff and its external public-key signature, then selects the "
            "small set of artifacts useful for a live presentation. It does not replace the underlying "
            "assessment, OCI, lineage, or claims-boundary verifiers."
        ),
    )


def _print(summary: PresentationSummary) -> None:
    print("CUSTOMER TRUST PRESENTATION")
    print(f"  run:               {summary.run_id}")
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
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the trust-flow and decision HTML pages in the default browser",
    )
    args = parser.parse_args(argv)

    try:
        summary = build_presentation(args.root)
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

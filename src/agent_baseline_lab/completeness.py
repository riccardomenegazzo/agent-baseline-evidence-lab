from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import sha256_file


@dataclass(frozen=True)
class CompletenessWitness:
    schema_version: int
    witness_id: str
    scope: str
    source: str
    expected_event_ids: list[str]
    checkpoint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CompletenessResult:
    schema_version: int
    witness_id: str
    scope: str
    expected_count: int
    observed_count: int
    matched_count: int
    missing_event_ids: list[str]
    duplicate_observed_event_ids: list[str]
    completeness_verified: bool
    witness_sha256: str
    observed_sha256: str
    checkpoint: str | None
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_witness(path: str | Path) -> CompletenessWitness:
    witness_path = Path(path)
    payload = json.loads(witness_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported completeness witness schema_version")
    expected = payload.get("expected_event_ids")
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        raise ValueError("expected_event_ids must be a list of strings")
    if len(expected) != len(set(expected)):
        raise ValueError("completeness witness contains duplicate expected_event_ids")
    witness_id = str(payload.get("witness_id", "")).strip()
    scope = str(payload.get("scope", "")).strip()
    source = str(payload.get("source", "")).strip()
    if not witness_id or not scope or not source:
        raise ValueError("witness_id, scope, and source are required")
    checkpoint = payload.get("checkpoint")
    if checkpoint is not None and not isinstance(checkpoint, str):
        raise ValueError("checkpoint must be a string when present")
    return CompletenessWitness(
        schema_version=1,
        witness_id=witness_id,
        scope=scope,
        source=source,
        expected_event_ids=sorted(expected),
        checkpoint=checkpoint,
    )


def reconcile_event_ids(
    witness: CompletenessWitness,
    observed_event_ids: list[str],
    *,
    witness_sha256: str,
    observed_sha256: str,
) -> CompletenessResult:
    observed = [str(item) for item in observed_event_ids]
    observed_set = set(observed)
    duplicates = sorted({item for item in observed if observed.count(item) > 1})
    missing = sorted(set(witness.expected_event_ids) - observed_set)
    matched = sorted(set(witness.expected_event_ids) & observed_set)
    return CompletenessResult(
        schema_version=1,
        witness_id=witness.witness_id,
        scope=witness.scope,
        expected_count=len(witness.expected_event_ids),
        observed_count=len(observed),
        matched_count=len(matched),
        missing_event_ids=missing,
        duplicate_observed_event_ids=duplicates,
        completeness_verified=not missing and not duplicates,
        witness_sha256=witness_sha256,
        observed_sha256=observed_sha256,
        checkpoint=witness.checkpoint,
        claims_boundary=(
            "Completeness is verified only against the event set asserted by this external witness. "
            "The witness must itself come from an independently trusted source or checkpoint; this "
            "reconciliation does not prove that the witness enumerated every real-world event."
        ),
    )


def reconcile_files(
    witness_path: str | Path,
    observed_path: str | Path,
    *,
    output_path: str | Path | None = None,
) -> CompletenessResult:
    witness_file = Path(witness_path)
    observed_file = Path(observed_path)
    witness = load_witness(witness_file)
    payload = json.loads(observed_file.read_text(encoding="utf-8"))
    observed = payload.get("observed_event_ids", []) if isinstance(payload, dict) else payload
    if not isinstance(observed, list) or not all(isinstance(item, str) for item in observed):
        raise ValueError("observed evidence must be a list of event IDs or an object with observed_event_ids")
    result = reconcile_event_ids(
        witness,
        observed,
        witness_sha256=sha256_file(witness_file),
        observed_sha256=sha256_file(observed_file),
    )
    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def make_witness(
    witness_id: str,
    scope: str,
    source: str,
    event_ids: list[str],
    *,
    checkpoint: str | None = None,
) -> CompletenessWitness:
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event_ids must be unique")
    return CompletenessWitness(
        schema_version=1,
        witness_id=witness_id,
        scope=scope,
        source=source,
        expected_event_ids=sorted(str(item) for item in event_ids),
        checkpoint=checkpoint or _canonical_digest(sorted(event_ids)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile exported evidence against an independent completeness witness"
    )
    parser.add_argument("witness")
    parser.add_argument("observed")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    output = args.output or str(Path("reports") / "completeness-reconciliation.json")
    try:
        result = reconcile_files(args.witness, args.observed, output_path=output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    print(f"Completeness report: {output}")
    return 0 if result.completeness_verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

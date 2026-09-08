from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .signing import sign_artifact, verify_artifact_signature


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_baseline_lock(
    cache_dir: str | Path,
    *,
    expected_url: str | None = None,
    expected_sha256: str | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    root = Path(cache_dir)
    lock_path = root / "baseline.lock.json"
    controls_path = root / "controls.yaml"
    errors: list[str] = []
    if not lock_path.exists() or not controls_path.exists():
        return False, ["baseline.lock.json and controls.yaml are both required"], {}
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        parsed = yaml.safe_load(controls_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        return False, [f"baseline lock cannot be parsed: {exc}"], {}
    observed_sha = _sha256_file(controls_path)
    if observed_sha != lock.get("sha256"):
        errors.append("controls.yaml digest does not match baseline.lock.json")
    if expected_sha256 and observed_sha != expected_sha256:
        errors.append("controls.yaml digest does not match externally expected digest")
    if expected_url and lock.get("url") != expected_url:
        errors.append("baseline source URL does not match externally expected URL")
    controls = parsed.get("controls", []) if isinstance(parsed, dict) else []
    if lock.get("control_count") != len(controls):
        errors.append("control count does not match baseline.lock.json")
    summary = {
        "baseline_url": lock.get("url"),
        "baseline_sha256": observed_sha,
        "baseline_version": lock.get("version"),
        "control_count": len(controls),
        "drift": lock.get("drift", {}),
        "external_url_checked": bool(expected_url),
        "external_sha256_checked": bool(expected_sha256),
    }
    return not errors, errors, summary


def sign_baseline_lock(
    cache_dir: str | Path,
    *,
    private_key: str | Path,
    identity: str = "agent-baseline-evidence-lab",
) -> dict[str, Any]:
    root = Path(cache_dir)
    ok, errors, _ = verify_baseline_lock(root)
    if not ok:
        raise ValueError("refusing to sign invalid baseline lock: " + "; ".join(errors))
    receipt = sign_artifact(
        root / "baseline.lock.json",
        private_key,
        identity=identity,
        signature_path=root / "baseline.lock.json.sig",
        receipt_path=root / "baseline.lock.signature.json",
    )
    return receipt.to_dict()


def verify_signed_baseline_lock(
    cache_dir: str | Path,
    *,
    expected_fingerprint: str | None = None,
) -> tuple[bool, list[str], dict[str, Any]]:
    root = Path(cache_dir)
    lock_ok, lock_errors, lock_summary = verify_baseline_lock(root)
    signature_ok, signature_errors, signature_summary = verify_artifact_signature(
        root / "baseline.lock.signature.json",
        artifact=root / "baseline.lock.json",
        public_key=str(Path(str(Path(root / "baseline.lock.json.signature.json")))),
    ) if False else (False, [], {})
    # Signature receipts record their public-key path. Verification therefore needs no guessed key path.
    try:
        signature_ok, signature_errors, signature_summary = verify_artifact_signature(
            root / "baseline.lock.signature.json",
            artifact=root / "baseline.lock.json",
            expected_fingerprint=expected_fingerprint,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        signature_ok = False
        signature_errors = [f"baseline lock signature verification failed: {exc}"]
        signature_summary = {}
    errors = [*lock_errors, *signature_errors]
    return lock_ok and signature_ok, errors, {"lock": lock_summary, "signature": signature_summary}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify and optionally sign cached Agent Baseline source locks")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("cache_dir")
    verify.add_argument("--expected-url", default=None)
    verify.add_argument("--expected-sha256", default=None)
    sign = sub.add_parser("sign")
    sign.add_argument("cache_dir")
    sign.add_argument("--private-key", required=True)
    sign.add_argument("--identity", default="agent-baseline-evidence-lab")
    signed = sub.add_parser("verify-signature")
    signed.add_argument("cache_dir")
    signed.add_argument("--expected-fingerprint", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            ok, errors, summary = verify_baseline_lock(
                args.cache_dir,
                expected_url=args.expected_url,
                expected_sha256=args.expected_sha256,
            )
        elif args.command == "sign":
            summary = sign_baseline_lock(args.cache_dir, private_key=args.private_key, identity=args.identity)
            ok, errors = True, []
        else:
            ok, errors, summary = verify_signed_baseline_lock(
                args.cache_dir,
                expected_fingerprint=args.expected_fingerprint,
            )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary, indent=2, sort_keys=True))
    for error in errors:
        print(f"ERROR: {error}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

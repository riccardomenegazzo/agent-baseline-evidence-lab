from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CREDENTIAL_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
}
CREDENTIAL_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SOURCE_SUFFIXES = {
    ".py",
    ".go",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".rs",
    ".rb",
    ".php",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".sh",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".dockerfile",
}


@dataclass(frozen=True)
class UnintendedActionResult:
    schema_version: int
    artifact_type: str
    session_id: str
    analyzed_at: str
    changed_paths: list[str]
    credential_like_paths: list[str]
    source_code_paths: list[str]
    credential_code_cochange_detected: bool
    severity: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _credential_like(path: str) -> bool:
    p = Path(path)
    lowered_name = p.name.lower()
    if lowered_name in CREDENTIAL_NAMES:
        return True
    if p.suffix.lower() in CREDENTIAL_SUFFIXES:
        return True
    return any(part.lower() in {".ssh", ".aws", ".azure", ".kube"} for part in p.parts)


def _source_like(path: str) -> bool:
    p = Path(path)
    if p.name.lower() == "dockerfile":
        return True
    return p.suffix.lower() in SOURCE_SUFFIXES


def analyze_session(session_path: str | Path) -> UnintendedActionResult:
    path = Path(session_path)
    if path.is_dir():
        path = path / "session.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    changes = payload.get("changes", {})
    changed: list[str] = []
    if isinstance(changes, dict):
        for key in ("added", "modified", "removed"):
            values = changes.get(key, [])
            if isinstance(values, list):
                changed.extend(str(item) for item in values)
    changed = sorted(set(changed))
    credentials = sorted(path for path in changed if _credential_like(path))
    source = sorted(path for path in changed if _source_like(path) and path not in credentials)
    detected = bool(credentials and source)
    return UnintendedActionResult(
        schema_version=1,
        artifact_type="unintended-action-report",
        session_id=str(payload.get("session_id", "")),
        analyzed_at=_utc_now(),
        changed_paths=changed,
        credential_like_paths=credentials,
        source_code_paths=source,
        credential_code_cochange_detected=detected,
        severity="high" if detected else "none",
        claims_boundary=(
            "This detector is metadata-only: it classifies changed path names and never opens or "
            "persists potential credential contents. A positive result means credential-like and "
            "source-code paths changed in the same agent run; it does not prove a real secret was committed."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect credential/code co-change patterns in an agent run")
    parser.add_argument("session")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        result = analyze_session(args.session)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 1 if result.credential_code_cochange_detected else 0


if __name__ == "__main__":
    raise SystemExit(main())

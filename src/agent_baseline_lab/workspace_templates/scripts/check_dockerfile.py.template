from __future__ import annotations

import sys
from pathlib import Path


REQUIRED = {
    "USER": "non-root runtime user",
    "HEALTHCHECK": "container health check",
    "COPY --chown=": "ownership set at copy time",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_dockerfile.py DOCKERFILE", file=sys.stderr)
        return 2
    text = Path(sys.argv[1]).read_text(encoding="utf-8")
    missing = [description for token, description in REQUIRED.items() if token not in text]
    if "USER root" in text:
        missing.append("runtime must not switch back to root")
    if missing:
        for item in missing:
            print(f"FAIL: {item}")
        return 1
    for description in REQUIRED.values():
        print(f"PASS: {description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

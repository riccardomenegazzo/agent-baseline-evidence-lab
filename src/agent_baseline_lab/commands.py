from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(args: Sequence[str], timeout: int = 20) -> CommandResult:
    try:
        proc = subprocess.run(
            list(args),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(list(args), proc.returncode, proc.stdout.strip(), proc.stderr.strip())
    except subprocess.TimeoutExpired as exc:
        return CommandResult(list(args), 124, (exc.stdout or "").strip(), "command timed out")
    except OSError as exc:
        return CommandResult(list(args), 127, "", str(exc))


def exists(binary: str) -> bool:
    return shutil.which(binary) is not None


def parse_json_output(result: CommandResult):
    if not result.ok:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

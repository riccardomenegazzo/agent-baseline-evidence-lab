from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "N/A"
    ERROR = "ERROR"


@dataclass(frozen=True)
class Control:
    id: str
    outcome: str
    title: str
    control_type: str


@dataclass
class EvidenceItem:
    path: str
    sha256: str = ""
    media_type: str = "application/json"
    description: str = ""


@dataclass
class Result:
    control_id: str
    status: Status
    summary: str
    details: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    evaluator: str = "manual"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class RunReport:
    run_id: str
    started_at: str
    completed_at: str
    baseline_version: str
    config_path: str
    results: list[Result]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "baseline_version": self.baseline_version,
            "config_path": self.config_path,
            "metadata": self.metadata,
            "results": [r.to_dict() for r in self.results],
        }

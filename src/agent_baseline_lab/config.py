from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    pass


def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Configuration file not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ConfigError("Top-level configuration must be a mapping")
    if data.get("schema_version") != 1:
        raise ConfigError("Unsupported or missing schema_version (expected 1)")
    if not isinstance(data.get("agent"), dict):
        raise ConfigError("agent mapping is required")
    return data


def get_path(data: dict[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def missing_paths(data: dict[str, Any], paths: list[str]) -> list[str]:
    missing: list[str] = []
    for path in paths:
        value = get_path(data, path)
        if value is None or value == "" or value == [] or value == {}:
            missing.append(path)
    return missing

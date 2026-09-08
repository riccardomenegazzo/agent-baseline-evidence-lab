from __future__ import annotations

from pathlib import Path
from typing import Any


def portable_path(root: str | Path, path: str | Path) -> str:
    """Return a non-identifying path reference suitable for persisted evidence."""
    root_path = Path(root).resolve()
    candidate = Path(path).expanduser().resolve()
    try:
        relative = candidate.relative_to(root_path)
        return relative.as_posix() or "."
    except ValueError:
        return f"<external>/{candidate.name}"


def sanitize_text(value: str, root: str | Path) -> str:
    """Replace project/home prefixes without changing unrelated command text."""
    root_text = str(Path(root).resolve())
    home_text = str(Path.home().resolve())
    sanitized = value.replace(root_text, "<project>")
    if home_text and home_text != root_text:
        sanitized = sanitized.replace(home_text, "<home>")
    return sanitized


def sanitize_value(value: Any, root: str | Path) -> Any:
    if isinstance(value, str):
        return sanitize_text(value, root)
    if isinstance(value, list):
        return [sanitize_value(item, root) for item in value]
    if isinstance(value, tuple):
        return [sanitize_value(item, root) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_value(item, root) for key, item in value.items()}
    return value


def forbidden_local_path_markers(root: str | Path) -> list[str]:
    root_text = str(Path(root).resolve())
    home_text = str(Path.home().resolve())
    markers = [root_text]
    if home_text and home_text != root_text and len(home_text) > 1:
        markers.append(home_text)
    return markers


def find_local_path_markers(data: bytes, root: str | Path) -> list[str]:
    """Return local path prefixes found in UTF-8-ish evidence; binary blobs are ignored."""
    text = data.decode("utf-8", errors="ignore")
    return [marker for marker in forbidden_local_path_markers(root) if marker in text]

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .commands import exists, parse_json_output, run


@dataclass(frozen=True)
class McpRegistration:
    name: str
    url: str
    transport: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class McpInventoryResult:
    schema_version: int
    observed: bool
    registrations: list[McpRegistration]
    expected_names: list[str]
    missing_expected_names: list[str]
    unexpected_names: list[str]
    identity_mismatches: list[str]
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observed": self.observed,
            "registrations": [registration.to_dict() for registration in self.registrations],
            "expected_names": self.expected_names,
            "missing_expected_names": self.missing_expected_names,
            "unexpected_names": self.unexpected_names,
            "identity_mismatches": self.identity_mismatches,
            "claims_boundary": self.claims_boundary,
        }


def _walk(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        keys = {str(key).lower() for key in value}
        if keys & {"name", "server", "id"} and keys & {"url", "endpoint", "transport", "type"}:
            found.append(value)
        for child in value.values():
            found.extend(_walk(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk(child))
    return found


def _registration_from_record(record: dict[str, Any]) -> McpRegistration | None:
    name = str(record.get("name") or record.get("server") or record.get("id") or "").strip()
    url = str(record.get("url") or record.get("endpoint") or record.get("identityURL") or "").strip()
    transport = str(record.get("transport") or record.get("type") or "").strip()
    if not name:
        return None
    return McpRegistration(name=name, url=url, transport=transport, source="sbx-mcp-inventory-json")


def parse_mcp_inventory(payload: Any) -> list[McpRegistration]:
    registrations: dict[str, McpRegistration] = {}
    for record in _walk(payload):
        registration = _registration_from_record(record)
        if registration is not None:
            registrations[registration.name] = registration
    return [registrations[name] for name in sorted(registrations)]


def parse_mcp_table(text: str) -> list[McpRegistration]:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []
    header_index = next(
        (index for index, line in enumerate(lines) if "NAME" in line.upper() and "TYPE" in line.upper()),
        None,
    )
    data_lines = lines[header_index + 1 :] if header_index is not None else lines
    registrations: dict[str, McpRegistration] = {}
    for line in data_lines:
        if set(line.strip()) <= {"-", " ", "="}:
            continue
        parts = re.split(r"\s{2,}|\t+", line.strip(), maxsplit=2)
        if len(parts) < 2:
            continue
        name = parts[0].strip()
        transport = parts[1].strip()
        url = parts[2].strip() if len(parts) > 2 else ""
        if not name or name.upper() == "NAME":
            continue
        registrations[name] = McpRegistration(
            name=name,
            url=url,
            transport=transport,
            source="sbx-mcp-inventory-table",
        )
    return [registrations[name] for name in sorted(registrations)]


def collect_mcp_inventory() -> tuple[bool, list[McpRegistration], str]:
    if not exists("sbx"):
        return False, [], "Docker Sandboxes CLI is unavailable"
    for command in (["sbx", "mcp", "ls", "--json"], ["sbx", "mcp", "list", "--json"]):
        result = run(command, timeout=30)
        parsed = parse_json_output(result)
        if result.ok and parsed is not None:
            return True, parse_mcp_inventory(parsed), "structured-json"

    documented = run(["sbx", "mcp", "ls"], timeout=30)
    if documented.ok:
        registrations = parse_mcp_table(documented.stdout)
        return True, registrations, "documented-table"
    return False, [], "Docker MCP inventory could not be observed"


def evaluate_inventory(
    registrations: list[McpRegistration],
    *,
    expected: dict[str, str],
    observed: bool,
) -> McpInventoryResult:
    observed_by_name = {registration.name: registration for registration in registrations}
    expected_names = sorted(expected)
    observed_names = set(observed_by_name)
    missing = sorted(set(expected_names) - observed_names)
    unexpected = sorted(observed_names - set(expected_names))
    mismatches: list[str] = []
    for name, expected_url in sorted(expected.items()):
        registration = observed_by_name.get(name)
        if registration is None or not expected_url:
            continue
        if registration.url != expected_url:
            mismatches.append(f"{name}: expected {expected_url}, observed {registration.url or '<empty>'}")
    return McpInventoryResult(
        schema_version=1,
        observed=observed,
        registrations=registrations,
        expected_names=expected_names,
        missing_expected_names=missing,
        unexpected_names=unexpected,
        identity_mismatches=mismatches,
        claims_boundary=(
            "Registration inventory proves observed MCP configuration only. It does not prove that a server was invoked, that policy was enforced, or that direct non-gateway access was impossible."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Observe Docker MCP registrations and compare expected identities")
    parser.add_argument("--expect", action="append", default=[], metavar="NAME=URL")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    expected: dict[str, str] = {}
    for item in args.expect:
        if "=" not in item:
            parser.error("--expect must use NAME=URL")
        name, url = item.split("=", 1)
        expected[name] = url
    observed, registrations, note = collect_mcp_inventory()
    result = evaluate_inventory(registrations, expected=expected, observed=observed)
    payload = result.to_dict()
    payload["source_mode"] = note
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not observed:
        return 2
    return 0 if not result.missing_expected_names and not result.identity_mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())

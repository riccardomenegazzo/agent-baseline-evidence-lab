from __future__ import annotations

import argparse
import hashlib
import html
import json
import secrets
import shutil
import tarfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .commands import CommandResult, exists, run
from .evidence import sha256_file

SCHEMA_VERSION = 1
SPDX_PREDICATE = "https://spdx.dev/Document"
SLSA_PREFIX = "https://slsa.dev/provenance/"
ATTESTATION_MANIFEST = "attestation-manifest"
MAX_JSON_BLOB_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class TrustCheck:
    id: str
    status: str
    summary: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrustedArtifactReport:
    schema_version: int
    generated_at: str
    context: str
    dockerfile: str
    dry_run: bool
    build_attempted: bool
    build_succeeded: bool
    overall_status: str
    checks: list[TrustCheck]
    oci_archive: str
    oci_archive_sha256: str
    build_metadata: str
    scout_policy_mode: str
    scout_status: str
    scout_report: str
    scout_result: str
    scout_sarif: str
    claims_boundary: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["checks"] = [check.to_dict() for check in self.checks]
        return payload


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _portable(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"<external>/{path.name}"


def _logical_dockerfile_lines(text: str) -> list[str]:
    logical: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        current = f"{current} {stripped}".strip() if current else stripped
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        logical.append(current)
        current = ""
    if current:
        logical.append(current)
    return logical


def inspect_dockerfile(path: Path) -> list[TrustCheck]:
    if not path.is_file():
        return [TrustCheck("dockerfile-present", "FAIL", "Dockerfile is missing.", {"path": str(path)})]

    text = path.read_text(encoding="utf-8")
    lines = _logical_dockerfile_lines(text)
    from_entries: list[dict[str, str]] = []
    stage_aliases: set[str] = set()
    final_stage_start = -1
    final_user = ""
    healthcheck = False

    for index, line in enumerate(lines):
        parts = line.split()
        if not parts:
            continue
        instruction = parts[0].upper()
        if instruction == "FROM":
            source_index = 1
            if len(parts) > 1 and parts[1].startswith("--platform="):
                source_index = 2
            source = parts[source_index] if len(parts) > source_index else ""
            alias = ""
            if len(parts) > source_index + 2 and parts[source_index + 1].upper() == "AS":
                alias = parts[source_index + 2]
            external = bool(source) and source.lower() not in stage_aliases
            from_entries.append({"source": source, "alias": alias, "external": str(external).lower()})
            if alias:
                stage_aliases.add(alias.lower())
            final_stage_start = index
            final_user = ""
            healthcheck = False
        elif index > final_stage_start and instruction == "USER":
            final_user = " ".join(parts[1:]).strip()
        elif index > final_stage_start and instruction == "HEALTHCHECK":
            healthcheck = True

    external_bases = [entry["source"] for entry in from_entries if entry["external"] == "true"]
    digest_pinned = [ref for ref in external_bases if "@sha256:" in ref]
    tag_only = [ref for ref in external_bases if ref not in digest_pinned]

    checks: list[TrustCheck] = [
        TrustCheck(
            "dockerfile-present",
            "PASS",
            "Dockerfile is present and readable.",
            {"path": str(path), "sha256": sha256_file(path)},
        )
    ]

    user_value = final_user.split(":", 1)[0].strip().lower()
    non_root = bool(user_value) and user_value not in {"0", "root"}
    checks.append(
        TrustCheck(
            "default-non-root-user",
            "PASS" if non_root else "FAIL",
            (
                f"Final image declares non-root USER {final_user!r}."
                if non_root
                else "Final image has no effective non-root USER declaration."
            ),
            {"user": final_user or "<implicit-root>"},
        )
    )

    checks.append(
        TrustCheck(
            "base-image-identity",
            "PASS" if external_bases else "FAIL",
            "External base-image references were identified." if external_bases else "No external base image could be identified.",
            {
                "external_bases": external_bases,
                "digest_pinned": digest_pinned,
                "tag_only": tag_only,
                "note": (
                    "Tag-only bases are recorded as a reproducibility finding, not automatically treated as a security failure."
                    if tag_only
                    else "All observed external bases are digest-pinned."
                ),
            },
        )
    )

    checks.append(
        TrustCheck(
            "base-image-reproducibility",
            "PASS" if external_bases and not tag_only else "FINDING",
            (
                "All observed external base images are digest-pinned."
                if external_bases and not tag_only
                else "One or more base images use mutable tag references; provenance/Scout evidence should be used to bind the resolved build materials."
            ),
            {"tag_only": tag_only, "digest_pinned": digest_pinned},
        )
    )

    checks.append(
        TrustCheck(
            "runtime-healthcheck",
            "PASS" if healthcheck else "FINDING",
            "Final image declares a HEALTHCHECK." if healthcheck else "Final image does not declare a HEALTHCHECK.",
            {"declared": healthcheck},
        )
    )
    return checks


def _digest_blob_name(digest: str) -> str:
    algorithm, sep, value = digest.partition(":")
    if sep != ":" or algorithm != "sha256" or len(value) != 64:
        raise ValueError(f"unsupported OCI digest: {digest}")
    return f"blobs/sha256/{value}"


def _read_member_bytes(tf: tarfile.TarFile, name: str) -> bytes:
    member = tf.getmember(name)
    if not member.isfile():
        raise ValueError(f"OCI member is not a regular file: {name}")
    if member.size > MAX_JSON_BLOB_BYTES:
        raise ValueError(f"OCI JSON member exceeds {MAX_JSON_BLOB_BYTES} bytes: {name}")
    stream = tf.extractfile(member)
    if stream is None:
        raise ValueError(f"OCI member cannot be read: {name}")
    return stream.read()


def _read_json_member(tf: tarfile.TarFile, name: str) -> dict[str, Any]:
    data = _read_member_bytes(tf, name)
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"OCI JSON member is invalid: {name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OCI JSON member is not an object: {name}")
    return payload


def _read_blob(tf: tarfile.TarFile, digest: str) -> tuple[bytes, dict[str, Any]]:
    name = _digest_blob_name(digest)
    data = _read_member_bytes(tf, name)
    observed = _sha256_bytes(data)
    expected = digest.split(":", 1)[1]
    if observed != expected:
        raise ValueError(f"OCI blob digest mismatch for {digest}")
    try:
        payload = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"OCI blob is not valid JSON: {digest}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OCI blob is not a JSON object: {digest}")
    return data, payload


def verify_oci_attestations(archive: Path) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    summary: dict[str, Any] = {
        "archive": str(archive),
        "archive_sha256": sha256_file(archive) if archive.is_file() else "",
        "runnable_manifest_digests": [],
        "attestation_manifest_digests": [],
        "verified_index_descriptors": [],
        "predicate_types": [],
        "statements": [],
        "subject_binding_failures": [],
    }
    if not archive.is_file():
        return False, ["OCI archive is missing"], summary

    try:
        with tarfile.open(archive, "r:*") as tf:
            names = {member.name for member in tf.getmembers()}
            if "index.json" not in names or "oci-layout" not in names:
                return False, ["archive is not an OCI image layout"], summary
            index = _read_json_member(tf, "index.json")
            descriptors = index.get("manifests", [])
            if not isinstance(descriptors, list):
                return False, ["OCI index manifests is not an array"], summary

            runnable: list[str] = []
            attestation_descriptors: list[dict[str, Any]] = []
            verified_descriptors: list[dict[str, Any]] = []
            for descriptor in descriptors:
                if not isinstance(descriptor, dict):
                    errors.append("OCI index contains a non-object descriptor")
                    continue
                annotations = descriptor.get("annotations", {})
                annotations = annotations if isinstance(annotations, dict) else {}
                digest = str(descriptor.get("digest", ""))
                if not digest:
                    errors.append("OCI index descriptor is missing digest")
                    continue
                try:
                    data, _ = _read_blob(tf, digest)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                declared_size = descriptor.get("size")
                size_matches = not isinstance(declared_size, int) or declared_size == len(data)
                if not size_matches:
                    errors.append(
                        f"OCI descriptor size mismatch for {digest}: declared {declared_size}, observed {len(data)}"
                    )
                verified_descriptors.append(
                    {
                        "digest": digest,
                        "declared_size": declared_size,
                        "observed_size": len(data),
                        "size_matches": size_matches,
                        "attestation": annotations.get("vnd.docker.reference.type") == ATTESTATION_MANIFEST,
                    }
                )
                if annotations.get("vnd.docker.reference.type") == ATTESTATION_MANIFEST:
                    attestation_descriptors.append(descriptor)
                else:
                    runnable.append(digest)
            summary["runnable_manifest_digests"] = runnable
            summary["attestation_manifest_digests"] = [
                str(item.get("digest", "")) for item in attestation_descriptors
            ]
            summary["verified_index_descriptors"] = verified_descriptors
            if not runnable:
                errors.append("OCI index contains no runnable image manifest")
            if not attestation_descriptors:
                errors.append("OCI index contains no Docker attestation manifest")

            predicates: set[str] = set()
            statement_rows: list[dict[str, Any]] = []
            binding_failures: list[str] = []
            for descriptor in attestation_descriptors:
                descriptor_digest = str(descriptor.get("digest", ""))
                annotations = descriptor.get("annotations", {})
                annotations = annotations if isinstance(annotations, dict) else {}
                referred_digest = str(annotations.get("vnd.docker.reference.digest", ""))
                if referred_digest and referred_digest not in runnable:
                    errors.append(
                        f"attestation manifest {descriptor_digest} refers to unknown image manifest {referred_digest}"
                    )
                _, manifest = _read_blob(tf, descriptor_digest)
                layers = manifest.get("layers", [])
                if not isinstance(layers, list) or not layers:
                    errors.append(f"attestation manifest has no layers: {descriptor_digest}")
                    continue
                for layer in layers:
                    if not isinstance(layer, dict):
                        continue
                    if layer.get("mediaType") != "application/vnd.in-toto+json":
                        continue
                    layer_digest = str(layer.get("digest", ""))
                    _, statement = _read_blob(tf, layer_digest)
                    predicate_type = str(statement.get("predicateType", ""))
                    layer_annotations = layer.get("annotations", {})
                    layer_annotations = layer_annotations if isinstance(layer_annotations, dict) else {}
                    annotated_predicate = str(layer_annotations.get("in-toto.io/predicate-type", ""))
                    if annotated_predicate and predicate_type != annotated_predicate:
                        errors.append(
                            f"predicate annotation mismatch in {layer_digest}: {annotated_predicate} != {predicate_type}"
                        )
                    if not str(statement.get("_type", "")).startswith("https://in-toto.io/Statement/"):
                        errors.append(f"unexpected in-toto statement type in {layer_digest}")
                    if predicate_type:
                        predicates.add(predicate_type)

                    subject_match = False
                    subjects = statement.get("subject", [])
                    if referred_digest and isinstance(subjects, list):
                        expected_hash = referred_digest.split(":", 1)[-1]
                        for subject in subjects:
                            if not isinstance(subject, dict):
                                continue
                            digest_map = subject.get("digest", {})
                            if isinstance(digest_map, dict) and digest_map.get("sha256") == expected_hash:
                                subject_match = True
                                break
                    if referred_digest and not subject_match:
                        binding_failures.append(layer_digest)
                    statement_rows.append(
                        {
                            "attestation_manifest": descriptor_digest,
                            "layer_digest": layer_digest,
                            "predicate_type": predicate_type,
                            "referred_image_manifest": referred_digest,
                            "subject_matches_referred_manifest": subject_match if referred_digest else None,
                        }
                    )

            summary["predicate_types"] = sorted(predicates)
            summary["statements"] = statement_rows
            summary["subject_binding_failures"] = binding_failures
            if binding_failures:
                errors.append("one or more attestations are not subject-bound to their referred image manifest")
            if SPDX_PREDICATE not in predicates:
                errors.append("SPDX SBOM attestation is missing")
            if not any(value.startswith(SLSA_PREFIX) for value in predicates):
                errors.append("SLSA provenance attestation is missing")
    except (OSError, tarfile.TarError, KeyError, ValueError) as exc:
        errors.append(str(exc))

    summary["sbom_present"] = SPDX_PREDICATE in set(summary.get("predicate_types", []))
    summary["provenance_present"] = any(
        str(value).startswith(SLSA_PREFIX) for value in summary.get("predicate_types", [])
    )
    summary["subject_bindings_valid"] = not summary.get("subject_binding_failures")
    return not errors, errors, summary


def _safe_extract_oci(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError(f"unsafe OCI archive member: {member.name}")
            target = (destination / Path(*pure.parts)).resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"OCI member escapes extraction root: {member.name}") from exc
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(f"unsupported OCI archive member type: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise ValueError(f"OCI member cannot be read: {member.name}")
            with target.open("wb") as handle:
                shutil.copyfileobj(source, handle)


def _command_evidence(result: CommandResult) -> dict[str, Any]:
    return {
        "args": result.args,
        "returncode": result.returncode,
        "stdout_sha256": _sha256_bytes(result.stdout.encode("utf-8", errors="replace")),
        "stderr_sha256": _sha256_bytes(result.stderr.encode("utf-8", errors="replace")),
        "stdout_bytes": len(result.stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(result.stderr.encode("utf-8", errors="replace")),
    }


def _run_scout(
    root: Path,
    oci_archive: Path,
    output_dir: Path,
    policy_config: Path | None,
    *,
    timeout: int,
    mode: str,
) -> tuple[str, str, str, str, list[TrustCheck]]:
    if mode == "off":
        return "NOT_RUN", "", "", "", [
            TrustCheck("docker-scout-policy", "NOT_RUN", "Docker Scout evaluation was disabled.", {})
        ]
    if not exists("docker"):
        return "NOT_RUN", "", "", "", [
            TrustCheck("docker-scout-policy", "NOT_RUN", "Docker CLI is unavailable; Scout was not evaluated.", {})
        ]
    version = run(["docker", "scout", "version"], timeout=30)
    if not version.ok:
        return "NOT_RUN", "", "", "", [
            TrustCheck(
                "docker-scout-policy",
                "NOT_RUN",
                "Docker Scout CLI plugin is unavailable; BuildKit attestation verification remains independent.",
                _command_evidence(version),
            )
        ]

    extracted = output_dir / "oci-layout"
    if extracted.exists():
        shutil.rmtree(extracted)
    _safe_extract_oci(oci_archive, extracted)
    scout_report = output_dir / "scout-policy.txt"
    scout_result = output_dir / "scout-policy-result.json"
    scout_sarif = output_dir / "scout-cves.sarif"
    artifact_ref = f"oci-dir://{extracted.resolve()}"

    command = [
        "docker",
        "scout",
        "policy",
        artifact_ref,
        "--exit-code",
        "--output",
        str(scout_report),
        "--result-file",
        str(scout_result),
    ]
    if policy_config and policy_config.is_file():
        command.extend(["--policy-config", str(policy_config.resolve())])
    policy = run(command, timeout=timeout)
    if policy.returncode == 0:
        status = "PASS"
        summary = "Docker Scout policy evaluation completed with all evaluated policies met."
    elif policy.returncode == 2:
        status = "FAIL"
        summary = "Docker Scout completed and reported one or more unmet policies."
    else:
        status = "ERROR"
        summary = "Docker Scout policy evaluation did not complete successfully."

    cves = run(
        [
            "docker",
            "scout",
            "cves",
            artifact_ref,
            "--only-severity",
            "critical,high",
            "--only-fixed",
            "--format",
            "sarif",
            "--output",
            str(scout_sarif),
        ],
        timeout=timeout,
    )
    checks = [
        TrustCheck(
            "docker-scout-policy",
            status,
            summary,
            {
                "policy_command": _command_evidence(policy),
                "policy_config": _portable(root, policy_config) if policy_config else "",
                "report": _portable(root, scout_report) if scout_report.exists() else "",
                "result": _portable(root, scout_result) if scout_result.exists() else "",
                "mode": mode,
            },
        ),
        TrustCheck(
            "docker-scout-sarif",
            "PASS" if cves.ok and scout_sarif.is_file() else "ERROR",
            (
                "Docker Scout produced a SARIF report for fixable critical/high vulnerabilities."
                if cves.ok and scout_sarif.is_file()
                else "Docker Scout SARIF export did not complete successfully."
            ),
            {"command": _command_evidence(cves), "sarif": _portable(root, scout_sarif) if scout_sarif.exists() else ""},
        ),
    ]
    return (
        status,
        _portable(root, scout_report) if scout_report.exists() else "",
        _portable(root, scout_result) if scout_result.exists() else "",
        _portable(root, scout_sarif) if scout_sarif.exists() else "",
        checks,
    )


def _write_html(report: TrustedArtifactReport, path: Path) -> None:
    status_class = {
        "PASS": "pass",
        "VERIFIED": "pass",
        "FAIL": "fail",
        "FAILED": "fail",
        "ERROR": "fail",
        "FINDING": "finding",
        "NOT_RUN": "muted",
    }
    rows = []
    for check in report.checks:
        evidence = html.escape(json.dumps(check.evidence, sort_keys=True))
        rows.append(
            f"<article><div class='head'><h3>{html.escape(check.id)}</h3>"
            f"<span class='chip {status_class.get(check.status, 'muted')}'>{html.escape(check.status)}</span></div>"
            f"<p>{html.escape(check.summary)}</p><details><summary>Evidence</summary><pre>{evidence}</pre></details></article>"
        )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Trusted Artifact Evidence</title><style>
:root{{--ink:#101828;--muted:#667085;--line:#e4e7ec;--bg:#f7f9fc;--navy:#0b1f3a;--blue:#1d63ed}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,sans-serif}}.wrap{{max-width:1060px;margin:auto;padding:48px 24px 80px}}header{{background:linear-gradient(135deg,var(--navy),#164d8b);color:#fff;border-radius:20px;padding:34px}}h1{{margin:6px 0 12px;font-size:38px}}header p{{color:#dce7ff;max-width:800px}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:20px 0}}.card,article{{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px}}.card span{{display:block;color:var(--muted);font-size:12px}}.card strong{{display:block;font-size:18px;margin-top:5px;overflow-wrap:anywhere}}article{{margin:10px 0}}.head{{display:flex;justify-content:space-between;gap:16px}}h3{{margin:0;font-size:16px}}.chip{{font:800 11px ui-monospace,monospace;padding:5px 8px;border-radius:999px}}.pass{{background:#ecfdf3;color:#067647}}.fail{{background:#fef3f2;color:#b42318}}.finding{{background:#fff6ed;color:#b54708}}.muted{{background:#f2f4f7;color:#475467}}pre{{white-space:pre-wrap;word-break:break-word;background:#f8fafc;padding:12px;border-radius:8px;font-size:12px}}.notice{{margin:20px 0;padding:14px 16px;border-radius:12px;background:#fff8e8;border:1px solid #f5d477}}@media(max-width:760px){{.grid{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:30px}}}}</style></head>
<body><div class="wrap"><header><div>AGENT BASELINE EVIDENCE LAB</div><h1>Trusted Artifact Evidence</h1><p>BuildKit/OCI evidence for the artifact produced from the coding-agent workspace. This report distinguishes static image-contract checks, verified build attestations and optional Docker Scout policy results.</p></header>
<div class="grid"><div class="card"><span>Overall</span><strong>{html.escape(report.overall_status)}</strong></div><div class="card"><span>Build</span><strong>{'PASS' if report.build_succeeded else ('NOT RUN' if not report.build_attempted else 'FAIL')}</strong></div><div class="card"><span>Scout</span><strong>{html.escape(report.scout_status)}</strong></div><div class="card"><span>OCI SHA-256</span><strong>{html.escape(report.oci_archive_sha256[:16] + ('…' if report.oci_archive_sha256 else ''))}</strong></div></div>
<div class="notice"><strong>Claims boundary:</strong> {html.escape(report.claims_boundary)}</div>{''.join(rows)}</div></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")


def run_trusted_artifact(
    context_path: str | Path,
    *,
    output_root: str | Path = ".",
    output_dir: str | Path = "reports/trusted-artifact",
    dockerfile: str | Path | None = None,
    dry_run: bool = False,
    scout_mode: str = "observe",
    policy_config: str | Path | None = "policies/scout/trusted-artifact.json",
    timeout: int = 900,
) -> TrustedArtifactReport:
    if scout_mode not in {"off", "observe", "gate"}:
        raise ValueError("scout_mode must be one of: off, observe, gate")
    root = Path(output_root).resolve()
    context = Path(context_path)
    if not context.is_absolute():
        context = root / context
    context = context.resolve()
    if not context.is_dir():
        raise ValueError(f"build context does not exist: {context}")

    dockerfile_path = Path(dockerfile) if dockerfile else context / "Dockerfile"
    if not dockerfile_path.is_absolute():
        dockerfile_path = (root / dockerfile_path).resolve() if dockerfile else dockerfile_path.resolve()
    out = Path(output_dir)
    if not out.is_absolute():
        out = root / out
    out.mkdir(parents=True, exist_ok=True)
    policy_path = Path(policy_config) if policy_config else None
    if policy_path is not None and not policy_path.is_absolute():
        policy_path = root / policy_path

    checks = inspect_dockerfile(dockerfile_path)
    static_failed = any(item.status in {"FAIL", "ERROR"} for item in checks)
    archive = out / "image.oci.tar"
    metadata_path = out / "build-metadata.json"
    build_attempted = False
    build_succeeded = False
    scout_status = "NOT_RUN"
    scout_report = ""
    scout_result = ""
    scout_sarif = ""

    if dry_run:
        checks.append(
            TrustCheck(
                "buildkit-attestations",
                "NOT_RUN",
                "Dry-run mode does not invoke Docker Buildx and cannot claim SBOM/provenance generation.",
                {
                    "planned_flags": ["--sbom=true", "--provenance=mode=max", "--output type=oci"],
                    "context": _portable(root, context),
                },
            )
        )
        overall = "FAILED" if static_failed else "NOT_RUN"
    elif not exists("docker"):
        checks.append(
            TrustCheck("buildkit-attestations", "ERROR", "Docker CLI is unavailable.", {})
        )
        overall = "FAILED"
    else:
        build_attempted = True
        builder = f"abl-trust-{secrets.token_hex(4)}"
        create = run(["docker", "buildx", "create", "--name", builder, "--driver", "docker-container"], timeout=60)
        checks.append(
            TrustCheck(
                "ephemeral-buildx-builder",
                "PASS" if create.ok else "ERROR",
                "Created a disposable docker-container Buildx builder." if create.ok else "Could not create the disposable Buildx builder.",
                _command_evidence(create),
            )
        )
        build_result: CommandResult | None = None
        try:
            if create.ok:
                bootstrap = run(["docker", "buildx", "inspect", "--builder", builder, "--bootstrap"], timeout=120)
                checks.append(
                    TrustCheck(
                        "buildx-bootstrap",
                        "PASS" if bootstrap.ok else "ERROR",
                        "Disposable Buildx builder bootstrapped." if bootstrap.ok else "Buildx builder bootstrap failed.",
                        _command_evidence(bootstrap),
                    )
                )
                if bootstrap.ok:
                    command = [
                        "docker",
                        "buildx",
                        "build",
                        "--builder",
                        builder,
                        "--file",
                        str(dockerfile_path),
                        "--sbom=true",
                        "--provenance=mode=max",
                        "--metadata-file",
                        str(metadata_path),
                        "--output",
                        f"type=oci,dest={archive}",
                        str(context),
                    ]
                    build_result = run(command, timeout=timeout)
                    build_succeeded = build_result.ok and archive.is_file()
                    checks.append(
                        TrustCheck(
                            "buildkit-build",
                            "PASS" if build_succeeded else "ERROR",
                            "Buildx produced an OCI image layout archive." if build_succeeded else "Buildx did not produce a valid OCI output archive.",
                            {**_command_evidence(build_result), "archive": _portable(root, archive) if archive.exists() else ""},
                        )
                    )
        finally:
            if create.ok:
                remove = run(["docker", "buildx", "rm", builder], timeout=60)
                checks.append(
                    TrustCheck(
                        "ephemeral-builder-cleanup",
                        "PASS" if remove.ok else "FINDING",
                        "Disposable Buildx builder removed." if remove.ok else "Disposable Buildx builder cleanup requires attention.",
                        _command_evidence(remove),
                    )
                )

        if build_succeeded:
            verified, verification_errors, verification = verify_oci_attestations(archive)
            checks.append(
                TrustCheck(
                    "oci-attestation-integrity",
                    "PASS" if verified else "FAIL",
                    (
                        "OCI attestation manifests, blob digests, in-toto predicate types and image-subject bindings verified."
                        if verified
                        else "OCI attestation verification failed."
                    ),
                    {"summary": verification, "errors": verification_errors},
                )
            )
            scout_status, scout_report, scout_result, scout_sarif, scout_checks = _run_scout(
                root,
                archive,
                out,
                policy_path,
                timeout=timeout,
                mode=scout_mode,
            )
            checks.extend(scout_checks)
            scout_gate_failed = scout_mode == "gate" and scout_status != "PASS"
            overall = "VERIFIED" if verified and not static_failed and not scout_gate_failed else "FAILED"
        else:
            overall = "FAILED"

    report = TrustedArtifactReport(
        schema_version=SCHEMA_VERSION,
        generated_at=_utc_now(),
        context=_portable(root, context),
        dockerfile=_portable(root, dockerfile_path),
        dry_run=dry_run,
        build_attempted=build_attempted,
        build_succeeded=build_succeeded,
        overall_status=overall,
        checks=checks,
        oci_archive=_portable(root, archive) if archive.exists() else "",
        oci_archive_sha256=sha256_file(archive) if archive.exists() else "",
        build_metadata=_portable(root, metadata_path) if metadata_path.exists() else "",
        scout_policy_mode=scout_mode,
        scout_status=scout_status,
        scout_report=scout_report,
        scout_result=scout_result,
        scout_sarif=scout_sarif,
        claims_boundary=(
            "VERIFIED means this run produced an OCI artifact whose observed BuildKit attestation structure contains "
            "digest-valid SPDX SBOM and SLSA provenance statements bound to the referred image manifest, and whose "
            "final Dockerfile stage declares a non-root user. Docker Scout status is reported separately unless gate "
            "mode is requested. This is implementation evidence, not official Docker certification, vulnerability "
            "absence, signer identity, or proof that every supply-chain control is satisfied."
        ),
    )
    json_path = out / "trusted-artifact.json"
    html_path = out / "trusted-artifact.html"
    json_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_html(report, html_path)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and verify a Docker trusted-artifact evidence chain")
    sub = parser.add_subparsers(dest="command", required=False)

    build = sub.add_parser("build", help="build an OCI artifact with SBOM/provenance and verify it")
    build.add_argument("context", nargs="?", default="sample-app")
    build.add_argument("--root", default=".")
    build.add_argument("--output-dir", default="reports/trusted-artifact")
    build.add_argument("--dockerfile", default=None)
    build.add_argument("--dry-run", action="store_true")
    build.add_argument("--scout-mode", choices=["off", "observe", "gate"], default="observe")
    build.add_argument("--policy-config", default="policies/scout/trusted-artifact.json")
    build.add_argument("--timeout", type=int, default=900)

    verify = sub.add_parser("verify", help="independently verify an existing OCI archive")
    verify.add_argument("archive")
    verify.add_argument("--output", default=None)

    args = parser.parse_args(argv)
    command = args.command or "build"
    if command == "verify":
        ok, errors, summary = verify_oci_attestations(Path(args.archive))
        payload = {"verified": ok, "errors": errors, "summary": summary}
        if args.output:
            Path(args.output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if ok else 1

    try:
        report = run_trusted_artifact(
            args.context,
            output_root=args.root,
            output_dir=args.output_dir,
            dockerfile=args.dockerfile,
            dry_run=args.dry_run,
            scout_mode=args.scout_mode,
            policy_config=args.policy_config,
            timeout=args.timeout,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("TRUSTED ARTIFACT EVIDENCE")
    print(f"  context:   {report.context}")
    print(f"  overall:   {report.overall_status}")
    print(f"  build:     {report.build_succeeded}")
    print(f"  scout:     {report.scout_status} ({report.scout_policy_mode})")
    print(f"  OCI SHA:   {report.oci_archive_sha256}")
    return 1 if report.overall_status == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())

import hashlib
import io
import json
import tarfile
from pathlib import Path

from agent_baseline_lab.oci_integrity import verify_oci_layout_integrity


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _descriptor(data: bytes, media_type: str) -> dict:
    return {"mediaType": media_type, "digest": _digest(data), "size": len(data)}


def _archive(path: Path) -> tuple[str, str]:
    config = _json({"architecture": "amd64", "os": "linux", "config": {"User": "app"}})
    layer = b"fake-layer-bytes-for-integrity-test\n"
    config_descriptor = _descriptor(config, "application/vnd.oci.image.config.v1+json")
    layer_descriptor = _descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    manifest = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_descriptor,
            "layers": [layer_descriptor],
        }
    )
    manifest_descriptor = _descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    index = _json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [manifest_descriptor],
        }
    )
    blobs = {
        manifest_descriptor["digest"]: manifest,
        config_descriptor["digest"]: config,
        layer_descriptor["digest"]: layer,
    }
    with tarfile.open(path, "w") as tf:
        items = {
            "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
            "index.json": index,
            **{f"blobs/sha256/{digest.split(':', 1)[1]}": data for digest, data in blobs.items()},
        }
        for name, data in items.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return layer_descriptor["digest"], manifest_descriptor["digest"]


def test_oci_integrity_verifies_manifest_config_and_binary_layer(tmp_path: Path):
    archive = tmp_path / "image.tar"
    _archive(archive)

    ok, errors, summary = verify_oci_layout_integrity(archive)

    assert ok is True
    assert errors == []
    assert summary["verified_blob_count"] == 3
    assert summary["referenced_blob_count"] == 3
    roles = {item["role"] for item in summary["verified_blobs"]}
    assert roles == {"index-manifest", "manifest-config", "manifest-layer"}


def test_oci_integrity_detects_binary_layer_tampering(tmp_path: Path):
    source = tmp_path / "image.tar"
    layer_digest, _ = _archive(source)
    target = tmp_path / "tampered.tar"
    layer_name = f"blobs/sha256/{layer_digest.split(':', 1)[1]}"

    with tarfile.open(source, "r") as src, tarfile.open(target, "w") as dst:
        for original in src.getmembers():
            member = tarfile.TarInfo(original.name)
            member.mode = original.mode
            member.type = original.type
            stream = src.extractfile(original) if original.isfile() else None
            data = stream.read() if stream is not None else b""
            if original.name == layer_name:
                data += b"tampered"
            member.size = len(data)
            dst.addfile(member, io.BytesIO(data) if original.isfile() else None)

    ok, errors, _ = verify_oci_layout_integrity(target)

    assert ok is False
    assert any("digest mismatch" in error for error in errors)


def test_oci_integrity_rejects_duplicate_member_names(tmp_path: Path):
    archive = tmp_path / "duplicates.tar"
    with tarfile.open(archive, "w") as tf:
        for data in (b'{"imageLayoutVersion":"1.0.0"}', b'{"imageLayoutVersion":"1.0.0"}'):
            info = tarfile.TarInfo("oci-layout")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        index = b'{"schemaVersion":2,"manifests":[]}'
        info = tarfile.TarInfo("index.json")
        info.size = len(index)
        tf.addfile(info, io.BytesIO(index))

    ok, errors, summary = verify_oci_layout_integrity(archive)

    assert ok is False
    assert summary["duplicate_members"] == ["oci-layout"]
    assert any("duplicate member" in error for error in errors)

#!/usr/bin/env python3
"""Package and verify bounded OCI image layouts for SevenMirror Server."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile

ARCHITECTURES = ("amd64", "arm64")
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "https://github.com/huaxianyan/SevenMirror-Server"
SCHEMA = "sevenmirror-server-container-release-v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--amd64-archive", type=Path)
    parser.add_argument("--arm64-archive", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_json(content: bytes, description: str) -> dict[str, object]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{description} is invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{description} must be an object")
    return value


def descriptor_blob(
    descriptor: object, blobs: dict[str, bytes], description: str,
) -> tuple[str, bytes]:
    if not isinstance(descriptor, dict):
        raise RuntimeError(f"{description} descriptor is invalid")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or \
            not isinstance(size, int) or size < 1:
        raise RuntimeError(f"{description} descriptor binding is invalid")
    content = blobs.get(digest)
    if content is None or len(content) != size or f"sha256:{sha256_bytes(content)}" != digest:
        raise RuntimeError(f"{description} blob does not match its descriptor")
    return digest, content


def inspect_archive(path: Path, architecture: str, revision: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("OCI archive must be a regular file")
    regular: dict[str, bytes] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix("./")
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or member.issym() or member.islnk():
                raise RuntimeError("OCI archive contains an unsafe entry")
            if member.isdir():
                continue
            if not member.isfile() or name in regular:
                raise RuntimeError("OCI archive contains a duplicate or non-regular entry")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise RuntimeError("OCI archive entry cannot be read")
            regular[name] = extracted.read()
    if "oci-layout" not in regular or "index.json" not in regular:
        raise RuntimeError("OCI archive is missing its layout or index")
    layout = parse_json(regular["oci-layout"], "OCI layout")
    if layout != {"imageLayoutVersion": "1.0.0"}:
        raise RuntimeError("OCI layout version is unsupported")
    blobs = {
        f"sha256:{name.removeprefix('blobs/sha256/')}": content
        for name, content in regular.items()
        if name.startswith("blobs/sha256/")
        and re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
    }
    expected_regular = {"oci-layout", "index.json"} | {
        f"blobs/sha256/{digest.removeprefix('sha256:')}" for digest in blobs
    }
    if set(regular) != expected_regular:
        raise RuntimeError("OCI archive has unknown or malformed entries")
    index = parse_json(regular["index.json"], "OCI index")
    manifests = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(manifests, list) or len(manifests) != 1:
        raise RuntimeError("OCI index must bind exactly one image manifest")
    manifest_digest, manifest_content = descriptor_blob(
        manifests[0], blobs, "OCI image manifest",
    )
    manifest = parse_json(manifest_content, "OCI image manifest")
    if manifest.get("schemaVersion") != 2:
        raise RuntimeError("OCI image manifest schema is unsupported")
    config_digest, config_content = descriptor_blob(
        manifest.get("config"), blobs, "OCI image config",
    )
    layers = manifest.get("layers")
    if not isinstance(layers, list) or not layers:
        raise RuntimeError("OCI image must contain at least one layer")
    referenced = {manifest_digest, config_digest}
    for index_number, layer in enumerate(layers):
        layer_digest, _ = descriptor_blob(layer, blobs, f"OCI layer {index_number}")
        referenced.add(layer_digest)
    if referenced != set(blobs):
        raise RuntimeError("OCI archive contains unreferenced blobs")
    config = parse_json(config_content, "OCI image config")
    runtime = config.get("config")
    if not isinstance(runtime, dict):
        raise RuntimeError("OCI runtime config is invalid")
    labels = runtime.get("Labels")
    if config.get("architecture") != architecture or config.get("os") != "linux" or \
            runtime.get("User") != "nonroot:nonroot" or \
            runtime.get("Entrypoint") != ["/app/server"] or \
            not isinstance(labels, dict) or labels.get("org.opencontainers.image.source") != REPOSITORY or \
            labels.get("org.opencontainers.image.revision") != revision:
        raise RuntimeError("OCI platform, runtime, or source identity is invalid")
    return {
        "architecture": architecture,
        "os": "linux",
        "archive_sha256": sha256_file(path),
        "archive_size": path.stat().st_size,
        "manifest_digest": manifest_digest,
        "config_digest": config_digest,
        "layer_count": len(layers),
        "runtime_user": "nonroot:nonroot",
        "entrypoint": ["/app/server"],
    }


def archive_name(architecture: str) -> str:
    return f"sevenmirror-server-linux-{architecture}.oci.tar"


def build(
    archives: dict[str, Path], output: Path, revision: str,
) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("container revision must be a canonical commit")
    if output.exists() or output.is_symlink():
        raise RuntimeError("container output must not already exist")
    records: list[dict[str, object]] = []
    for architecture in ARCHITECTURES:
        source = archives[architecture]
        record = inspect_archive(source, architecture, revision)
        record["name"] = archive_name(architecture)
        records.append(record)
    output.mkdir(mode=0o700)
    for architecture in ARCHITECTURES:
        shutil.copyfile(archives[architecture], output / archive_name(architecture))
    manifest = {
        "schema": SCHEMA,
        "source_repository": REPOSITORY,
        "source_revision": revision,
        "images": records,
    }
    (output / "container-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{record['archive_sha256']}  {record['name']}\n" for record in records
        ),
        encoding="ascii",
    )


def verify(output: Path, revision: str) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("expected revision must be a canonical commit")
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("container output must be a non-symlink directory")
    try:
        manifest = json.loads(
            (output / "container-manifest.json").read_text(encoding="utf-8"),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("container manifest is invalid") from error
    if manifest.get("schema") != SCHEMA or manifest.get("source_repository") != REPOSITORY or \
            manifest.get("source_revision") != revision:
        raise RuntimeError("container manifest source binding is invalid")
    records = manifest.get("images")
    if not isinstance(records, list) or len(records) != len(ARCHITECTURES):
        raise RuntimeError("container image inventory is invalid")
    expected_entries = {"container-manifest.json", "SHA256SUMS"} | {
        archive_name(architecture) for architecture in ARCHITECTURES
    }
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_entries or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("container output has missing, extra, or unsafe entries")
    checksum_lines: list[str] = []
    for architecture, record in zip(ARCHITECTURES, records, strict=True):
        if not isinstance(record, dict) or record.get("name") != archive_name(architecture):
            raise RuntimeError("container image record order or name is invalid")
        actual = inspect_archive(output / archive_name(architecture), architecture, revision)
        for key, value in actual.items():
            if record.get(key) != value:
                raise RuntimeError(f"container image {architecture} field {key} is invalid")
        checksum_lines.append(
            f"{actual['archive_sha256']}  {archive_name(architecture)}\n"
        )
    if (output / "SHA256SUMS").read_text(encoding="ascii") != "".join(checksum_lines):
        raise RuntimeError("container checksums do not match the manifest")


def main() -> None:
    args = parse_args()
    output = args.output.resolve()
    if not args.verify_only:
        if args.amd64_archive is None or args.arm64_archive is None:
            raise RuntimeError("both architecture archives are required for building")
        build(
            {
                "amd64": args.amd64_archive.resolve(),
                "arm64": args.arm64_archive.resolve(),
            },
            output,
            args.revision,
        )
    verify(output, args.revision)
    print("SevenMirror Server OCI container artifact set verified.")


if __name__ == "__main__":
    main()

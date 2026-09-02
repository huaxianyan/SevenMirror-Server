#!/usr/bin/env python3
"""Verify a pulled registry graph and record runtime scan evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from base_image_evidence import (
    active_exceptions,
    require_fresh_database,
    validate_sbom,
    vulnerability_summary,
)
from build_container_artifacts import (
    ARCHITECTURES,
    descriptor_blob,
    parse_json,
    verify as verify_container_release,
)

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_REPOSITORY = "ghcr.io/huaxianyan/sevenmirror-server"
REVISION = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "sevenmirror-registry-publication-evidence-v1"
TRIVY_DATABASE = "ghcr.io/aquasecurity/trivy-db:2"
TRIVY_VERSION = "0.74.0"
REGCTL_VERSION = "0.11.5"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--container-release", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--pulled-layout", type=Path)
    parser.add_argument("--trivy", type=Path)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path, description: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{description} is invalid JSON") from error


def container_records(container_release: Path, revision: str) -> list[dict[str, object]]:
    verify_container_release(container_release, revision)
    value = read_json(container_release / "container-manifest.json", "container manifest")
    if not isinstance(value, dict) or not isinstance(value.get("images"), list):
        raise RuntimeError("container manifest image inventory is invalid")
    records = value["images"]
    if len(records) != len(ARCHITECTURES) or any(not isinstance(record, dict) for record in records):
        raise RuntimeError("container manifest image inventory is invalid")
    return records


def layout_blobs(layout: Path) -> tuple[dict[str, bytes], bytes]:
    if not layout.is_dir() or layout.is_symlink():
        raise RuntimeError("pulled OCI layout must be a non-symlink directory")
    regular: dict[str, bytes] = {}
    for entry in layout.rglob("*"):
        relative = entry.relative_to(layout).as_posix()
        if entry.is_symlink() or (not entry.is_dir() and not entry.is_file()):
            raise RuntimeError("pulled OCI layout contains an unsafe entry")
        if entry.is_file():
            regular[relative] = entry.read_bytes()
    if parse_json(regular.get("oci-layout", b""), "pulled OCI layout") != {
        "imageLayoutVersion": "1.0.0",
    }:
        raise RuntimeError("pulled OCI layout version is unsupported")
    index_content = regular.get("index.json")
    if index_content is None:
        raise RuntimeError("pulled OCI layout is missing index.json")
    blobs = {
        f"sha256:{name.removeprefix('blobs/sha256/')}": content
        for name, content in regular.items()
        if re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
    }
    expected = {"oci-layout", "index.json"} | {
        f"blobs/sha256/{digest.removeprefix('sha256:')}" for digest in blobs
    }
    if set(regular) != expected:
        raise RuntimeError("pulled OCI layout contains unknown or malformed entries")
    return blobs, index_content


def inspect_pulled_layout(
    layout: Path,
    expected_records: list[dict[str, object]],
    revision: str,
) -> tuple[str, bytes]:
    blobs, outer_content = layout_blobs(layout)
    outer = parse_json(outer_content, "pulled OCI outer index")
    outer_manifests = outer.get("manifests")
    if outer.get("schemaVersion") != 2 or not isinstance(outer_manifests, list) or \
            len(outer_manifests) != 1:
        raise RuntimeError("pulled OCI layout must select exactly one registry index")
    index_digest, index_content = descriptor_blob(
        outer_manifests[0], blobs, "pulled registry index",
    )
    index = parse_json(index_content, "pulled registry index")
    manifests = index.get("manifests")
    if index.get("schemaVersion") != 2 or \
            index.get("mediaType") != "application/vnd.oci.image.index.v1+json" or \
            not isinstance(manifests, list) or len(manifests) != len(ARCHITECTURES):
        raise RuntimeError("published registry index shape is invalid")
    referenced = {index_digest}
    for architecture, descriptor, expected in zip(
        ARCHITECTURES, manifests, expected_records, strict=True,
    ):
        if not isinstance(descriptor, dict) or descriptor.get("platform") != {
            "architecture": architecture,
            "os": "linux",
        } or descriptor.get("digest") != expected.get("manifest_digest"):
            raise RuntimeError("published registry platform binding is invalid")
        manifest_digest, manifest_content = descriptor_blob(
            descriptor, blobs, f"published linux/{architecture} manifest",
        )
        referenced.add(manifest_digest)
        manifest = parse_json(manifest_content, f"published linux/{architecture} manifest")
        config_digest, config_content = descriptor_blob(
            manifest.get("config"), blobs, f"published linux/{architecture} config",
        )
        if config_digest != expected.get("config_digest"):
            raise RuntimeError("published registry config digest changed")
        referenced.add(config_digest)
        config = parse_json(config_content, f"published linux/{architecture} config")
        runtime = config.get("config")
        if config.get("architecture") != architecture or config.get("os") != "linux" or \
                not isinstance(runtime, dict) or runtime.get("User") != "nonroot:nonroot" or \
                runtime.get("Entrypoint") != ["/app/server"]:
            raise RuntimeError("published registry runtime identity is invalid")
        labels = runtime.get("Labels")
        if not isinstance(labels, dict) or labels.get("org.opencontainers.image.revision") != revision:
            raise RuntimeError("published registry source revision is invalid")
        layers = manifest.get("layers")
        if not isinstance(layers, list) or len(layers) != expected.get("layer_count"):
            raise RuntimeError("published registry layer inventory changed")
        for layer_number, layer in enumerate(layers):
            layer_digest, _ = descriptor_blob(
                layer, blobs, f"published linux/{architecture} layer {layer_number}",
            )
            referenced.add(layer_digest)
    if referenced != set(blobs):
        raise RuntimeError("pulled registry layout contains unreferenced graph content")
    return index_digest, index_content


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def scan_name(architecture: str, suffix: str) -> str:
    return f"runtime-linux-{architecture}-{suffix}.json"


def build(
    container_release: Path,
    pulled_layout: Path,
    output: Path,
    revision: str,
    trivy: Path,
    cache_dir: Path,
) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeError("registry evidence output must not already exist")
    if not trivy.is_file() or trivy.is_symlink():
        raise RuntimeError("Trivy must be a regular file")
    version = subprocess.run(
        [str(trivy), "--version"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    if version != f"Version: {TRIVY_VERSION}":
        raise RuntimeError("unexpected Trivy version")
    records = container_records(container_release, revision)
    index_digest, index_content = inspect_pulled_layout(pulled_layout, records, revision)
    immutable_ref = f"{REGISTRY_REPOSITORY}@{index_digest}"

    cache_dir.mkdir(parents=True, exist_ok=True)
    run([str(trivy), "image", "--cache-dir", str(cache_dir), "--download-db-only", "--no-progress"])
    metadata_source = cache_dir / "db" / "metadata.json"
    metadata = read_json(metadata_source, "Trivy database metadata")
    if not isinstance(metadata, dict):
        raise RuntimeError("Trivy database metadata must be an object")
    output.mkdir(mode=0o700)
    (output / "registry-index.json").write_bytes(index_content)
    shutil.copyfile(metadata_source, output / "trivy-db-metadata.json")
    exceptions = active_exceptions()
    scans: list[dict[str, object]] = []
    for architecture in ARCHITECTURES:
        prefix = [
            str(trivy), "image", "--cache-dir", str(cache_dir), "--skip-db-update",
            "--no-progress", "--platform", f"linux/{architecture}", "--pkg-types", "os",
            "--scanners", "vuln",
        ]
        vulnerability_name = scan_name(architecture, "vulnerabilities")
        sbom_name = scan_name(architecture, "sbom.cdx")
        run(prefix + ["--format", "json", "--output", str(output / vulnerability_name), immutable_ref])
        run(prefix + ["--format", "cyclonedx", "--output", str(output / sbom_name), immutable_ref])
        summary = vulnerability_summary(
            read_json(output / vulnerability_name, "published runtime vulnerability report"),
            exceptions,
        )
        if summary["blocking_findings"]:
            raise RuntimeError(f"published linux/{architecture} runtime has unapproved Critical/High findings")
        scans.append({
            "architecture": architecture,
            "sbom": sbom_name,
            "sbom_component_count": validate_sbom(
                read_json(output / sbom_name, "published runtime CycloneDX SBOM"),
            ),
            "sbom_sha256": sha256_file(output / sbom_name),
            "vulnerabilities": vulnerability_name,
            "vulnerabilities_sha256": sha256_file(output / vulnerability_name),
            **summary,
        })
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    database_updated_at = metadata.get("UpdatedAt")
    require_fresh_database(database_updated_at, observed_at)
    manifest = {
        "database": TRIVY_DATABASE,
        "database_metadata": "trivy-db-metadata.json",
        "database_metadata_sha256": sha256_file(output / "trivy-db-metadata.json"),
        "database_updated_at": database_updated_at,
        "index_digest": index_digest,
        "index_sha256": sha256_bytes(index_content),
        "immutable_reference": immutable_ref,
        "observed_at": observed_at,
        "registry_index": "registry-index.json",
        "registry_repository": REGISTRY_REPOSITORY,
        "regctl_version": REGCTL_VERSION,
        "scans": scans,
        "schema": SCHEMA,
        "source_revision": revision,
        "trivy_version": TRIVY_VERSION,
    }
    (output / "registry-publication-manifest.json").write_bytes(canonical_json(manifest))
    names = sorted(path.name for path in output.iterdir() if path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(output / name)}  {name}\n" for name in names), encoding="ascii",
    )


def verify(output: Path, container_release: Path, revision: str) -> None:
    records = container_records(container_release, revision)
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("registry evidence must be a non-symlink directory")
    manifest = read_json(output / "registry-publication-manifest.json", "registry publication manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "database", "database_metadata", "database_metadata_sha256", "database_updated_at",
        "immutable_reference", "index_digest", "index_sha256", "observed_at", "registry_index",
        "registry_repository", "regctl_version", "scans", "schema", "source_revision",
        "trivy_version",
    } or manifest.get("schema") != SCHEMA or manifest.get("source_revision") != revision or \
            manifest.get("registry_repository") != REGISTRY_REPOSITORY or \
            manifest.get("regctl_version") != REGCTL_VERSION or \
            manifest.get("trivy_version") != TRIVY_VERSION or manifest.get("database") != TRIVY_DATABASE:
        raise RuntimeError("registry publication manifest identity is invalid")
    require_fresh_database(manifest["database_updated_at"], manifest["observed_at"])
    index_content = (output / "registry-index.json").read_bytes()
    index_digest = f"sha256:{sha256_bytes(index_content)}"
    if manifest.get("index_digest") != index_digest or manifest.get("index_sha256") != sha256_bytes(index_content) or \
            manifest.get("immutable_reference") != f"{REGISTRY_REPOSITORY}@{index_digest}" or \
            manifest.get("registry_index") != "registry-index.json":
        raise RuntimeError("registry index digest binding is invalid")
    index = parse_json(index_content, "registry index")
    descriptors = index.get("manifests")
    if index.get("schemaVersion") != 2 or not isinstance(descriptors, list) or len(descriptors) != 2:
        raise RuntimeError("registry index inventory is invalid")
    for architecture, descriptor, record in zip(ARCHITECTURES, descriptors, records, strict=True):
        if not isinstance(descriptor, dict) or descriptor.get("digest") != record.get("manifest_digest") or \
                descriptor.get("platform") != {"architecture": architecture, "os": "linux"}:
            raise RuntimeError("registry index platform binding is invalid")
    scans = manifest.get("scans")
    if not isinstance(scans, list) or len(scans) != len(ARCHITECTURES):
        raise RuntimeError("published runtime scan inventory is invalid")
    exceptions = active_exceptions()
    expected_names = {
        "registry-publication-manifest.json", "registry-index.json", "SHA256SUMS",
        "trivy-db-metadata.json",
    }
    for architecture, scan in zip(ARCHITECTURES, scans, strict=True):
        vulnerability_name = scan_name(architecture, "vulnerabilities")
        sbom_name = scan_name(architecture, "sbom.cdx")
        expected_names.update({vulnerability_name, sbom_name})
        if not isinstance(scan, dict) or scan.get("architecture") != architecture or \
                scan.get("vulnerabilities") != vulnerability_name or scan.get("sbom") != sbom_name:
            raise RuntimeError("published runtime scan filename binding is invalid")
        summary = vulnerability_summary(
            read_json(output / vulnerability_name, "published runtime vulnerability report"), exceptions,
        )
        if summary["blocking_findings"] or any(scan.get(key) != value for key, value in summary.items()) or \
                scan.get("sbom_component_count") != validate_sbom(
                    read_json(output / sbom_name, "published runtime CycloneDX SBOM"),
                ) or scan.get("vulnerabilities_sha256") != sha256_file(output / vulnerability_name) or \
                scan.get("sbom_sha256") != sha256_file(output / sbom_name):
            raise RuntimeError("published runtime scan evidence is invalid")
    metadata = read_json(output / "trivy-db-metadata.json", "Trivy database metadata")
    if not isinstance(metadata, dict) or metadata.get("UpdatedAt") != manifest["database_updated_at"] or \
            manifest["database_metadata"] != "trivy-db-metadata.json" or \
            manifest["database_metadata_sha256"] != sha256_file(output / "trivy-db-metadata.json"):
        raise RuntimeError("registry scan database binding is invalid")
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("registry evidence has missing, extra, or unsafe entries")
    checksum_names = sorted(expected_names - {"SHA256SUMS"})
    expected_checksums = "".join(
        f"{sha256_file(output / name)}  {name}\n" for name in checksum_names
    )
    if (output / "SHA256SUMS").read_text(encoding="ascii") != expected_checksums:
        raise RuntimeError("registry evidence checksums are invalid")


def main() -> None:
    args = parse_args()
    if not REVISION.fullmatch(args.revision):
        raise RuntimeError("source revision must be a canonical commit")
    output = args.output.resolve()
    container_release = args.container_release.resolve()
    if not args.verify_only:
        if args.pulled_layout is None or args.trivy is None or args.cache_dir is None:
            raise RuntimeError("pulled layout, Trivy and cache directory are required")
        build(
            container_release, args.pulled_layout.resolve(), output, args.revision,
            args.trivy.resolve(), args.cache_dir.resolve(),
        )
    verify(output, container_release, args.revision)
    print("SevenMirror registry publication and runtime scan evidence verified.")


if __name__ == "__main__":
    main()

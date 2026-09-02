#!/usr/bin/env python3
"""Generate and verify bounded Trivy evidence for Dockerfile base images."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

from validate_vulnerability_exceptions import validate_registry

ARCHITECTURES = ("amd64", "arm64")
BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"
EXCEPTIONS = Path(__file__).resolve().parents[1] / "security" / "vulnerability-exceptions.json"
IMAGE = re.compile(
    r"^FROM(?:\s+--platform=\S+)?\s+([^\s@]+@sha256:[0-9a-f]{64})(?:\s+AS\s+(\S+))?$",
    re.IGNORECASE,
)
REVISION = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "sevenmirror-base-image-evidence-v1"
TRIVY_VERSION = "0.74.0"
TRIVY_DATABASE = "ghcr.io/aquasecurity/trivy-db:2"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--trivy", type=Path)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


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


def parse_time(value: object, description: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError(f"{description} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RuntimeError(f"{description} is invalid") from error
    if parsed.utcoffset() != timedelta(0):
        raise RuntimeError(f"{description} must be UTC")
    return parsed


def require_fresh_database(updated_at: object, observed_at: object) -> None:
    updated = parse_time(updated_at, "Trivy database update time")
    observed = parse_time(observed_at, "observation time")
    if updated > observed + timedelta(minutes=5) or observed - updated > timedelta(days=7):
        raise RuntimeError("Trivy database is outside the allowed freshness window")


def dockerfile_images(path: Path = DOCKERFILE) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("FROM "):
            continue
        match = IMAGE.fullmatch(line)
        if match is None:
            raise RuntimeError("every Dockerfile base image must use one sha256 digest")
        role = match.group(2).lower() if match.group(2) else "runtime"
        records.append({"role": role, "reference": match.group(1)})
    if [record["role"] for record in records] != ["build", "runtime"]:
        raise RuntimeError("Dockerfile must contain exact build and runtime base images")
    return records


def active_exceptions(path: Path = EXCEPTIONS) -> dict[tuple[str, str], str]:
    validate_registry(path, date.today())
    value = read_json(path, "vulnerability exception registry")
    if not isinstance(value, dict) or not isinstance(value.get("exceptions"), list):
        raise RuntimeError("vulnerability exception registry shape is invalid")
    matches: dict[tuple[str, str], str] = {}
    for entry in value["exceptions"]:
        if not isinstance(entry, dict) or entry.get("repository") != "SevenMirror-Server" or \
                entry.get("scanner") != "base-image" or entry.get("scope") != "base-image":
            continue
        component = entry.get("component")
        identifier = entry.get("id")
        vulnerability_ids = entry.get("vulnerability_ids")
        if not isinstance(component, str) or not isinstance(identifier, str) or \
                not isinstance(vulnerability_ids, list):
            raise RuntimeError("base-image exception binding is invalid")
        for vulnerability_id in vulnerability_ids:
            key = (component, vulnerability_id)
            if key in matches:
                raise RuntimeError("base-image finding has multiple exceptions")
            matches[key] = identifier
    return matches


def vulnerability_summary(value: object, exceptions: dict[tuple[str, str], str]) -> dict[str, object]:
    if not isinstance(value, dict) or not isinstance(value.get("Results"), list):
        raise RuntimeError("Trivy vulnerability report shape is invalid")
    counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    applied_exceptions: list[dict[str, str]] = []
    blocking: list[dict[str, str]] = []
    finding_count = 0
    package_count = 0
    for result in value["Results"]:
        if not isinstance(result, dict):
            raise RuntimeError("Trivy result is invalid")
        packages = result.get("Packages") or []
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(packages, list) or not isinstance(vulnerabilities, list):
            raise RuntimeError("Trivy package or vulnerability inventory is invalid")
        package_count += len(packages)
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                raise RuntimeError("Trivy finding is invalid")
            vulnerability_id = finding.get("VulnerabilityID")
            severity = finding.get("Severity", "UNKNOWN")
            identifier = finding.get("PkgIdentifier") or {}
            purl = identifier.get("PURL") if isinstance(identifier, dict) else None
            if not isinstance(vulnerability_id, str) or not vulnerability_id or \
                    severity not in counts or not isinstance(purl, str) or not purl.startswith("pkg:"):
                raise RuntimeError("Trivy finding identity is incomplete")
            finding_count += 1
            counts[severity] += 1
            if severity in BLOCKING_SEVERITIES:
                exception_id = exceptions.get((purl, vulnerability_id))
                if exception_id is None:
                    blocking.append({
                        "purl": purl,
                        "severity": severity,
                        "vulnerability_id": vulnerability_id,
                    })
                else:
                    applied_exceptions.append({
                        "exception_id": exception_id,
                        "purl": purl,
                        "vulnerability_id": vulnerability_id,
                    })
    applied_exceptions.sort(
        key=lambda item: (item["exception_id"], item["vulnerability_id"], item["purl"]),
    )
    blocking.sort(key=lambda item: (item["severity"], item["vulnerability_id"], item["purl"]))
    return {
        "applied_exceptions": applied_exceptions,
        "blocking_findings": blocking,
        "finding_count": finding_count,
        "package_count": package_count,
        "severity_counts": counts,
    }


def release_blocking(role: str, summary: dict[str, object]) -> bool:
    return role == "runtime" and bool(summary["blocking_findings"])


def validate_sbom(value: object) -> int:
    if not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX" or \
            not isinstance(value.get("specVersion"), str) or not isinstance(value.get("components"), list):
        raise RuntimeError("Trivy CycloneDX SBOM shape is invalid")
    return len(value["components"])


def evidence_name(role: str, architecture: str, suffix: str) -> str:
    return f"{role}-linux-{architecture}-{suffix}.json"


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def build(output: Path, revision: str, trivy: Path, cache_dir: Path) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeError("base-image evidence output must not already exist")
    if not trivy.is_file() or trivy.is_symlink():
        raise RuntimeError("Trivy must be a regular file")
    version = subprocess.run(
        [str(trivy), "--version"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    if version != f"Version: {TRIVY_VERSION}":
        raise RuntimeError("unexpected Trivy version")
    cache_dir.mkdir(parents=True, exist_ok=True)
    run([
        str(trivy), "image", "--cache-dir", str(cache_dir), "--download-db-only", "--no-progress",
    ])
    metadata_source = cache_dir / "db" / "metadata.json"
    metadata = read_json(metadata_source, "Trivy database metadata")
    if not isinstance(metadata, dict):
        raise RuntimeError("Trivy database metadata must be an object")
    updated_at = metadata.get("UpdatedAt")
    parse_time(updated_at, "Trivy database update time")

    output.mkdir(mode=0o700)
    shutil.copyfile(metadata_source, output / "trivy-db-metadata.json")
    exceptions = active_exceptions()
    scans: list[dict[str, object]] = []
    for image in dockerfile_images():
        for architecture in ARCHITECTURES:
            prefix = [
                str(trivy), "image", "--cache-dir", str(cache_dir), "--skip-db-update",
                "--no-progress", "--platform", f"linux/{architecture}", "--pkg-types", "os",
                "--scanners", "vuln",
            ]
            vulnerability_name = evidence_name(image["role"], architecture, "vulnerabilities")
            sbom_name = evidence_name(image["role"], architecture, "sbom.cdx")
            run(prefix + ["--format", "json", "--output", str(output / vulnerability_name), image["reference"]])
            run(prefix + ["--format", "cyclonedx", "--output", str(output / sbom_name), image["reference"]])
            vulnerability_value = read_json(output / vulnerability_name, "Trivy vulnerability report")
            sbom_value = read_json(output / sbom_name, "Trivy CycloneDX SBOM")
            summary = vulnerability_summary(vulnerability_value, exceptions)
            scans.append({
                "architecture": architecture,
                "gate_scope": "build-tool" if image["role"] == "build" else "release-runtime",
                "image": image["reference"],
                "role": image["role"],
                "sbom": sbom_name,
                "sbom_component_count": validate_sbom(sbom_value),
                "sbom_sha256": sha256_file(output / sbom_name),
                "vulnerabilities": vulnerability_name,
                "vulnerabilities_sha256": sha256_file(output / vulnerability_name),
                **summary,
            })
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    require_fresh_database(updated_at, observed_at)
    manifest = {
        "database": TRIVY_DATABASE,
        "database_metadata": "trivy-db-metadata.json",
        "database_metadata_sha256": sha256_file(output / "trivy-db-metadata.json"),
        "database_updated_at": updated_at,
        "observed_at": observed_at,
        "schema": SCHEMA,
        "source_revision": revision,
        "trivy_version": TRIVY_VERSION,
        "scans": scans,
    }
    (output / "base-image-manifest.json").write_bytes(canonical_json(manifest))
    names = sorted(path.name for path in output.iterdir() if path.name != "SHA256SUMS")
    (output / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(output / name)}  {name}\n" for name in names), encoding="ascii",
    )


def verify(output: Path, revision: str) -> None:
    if not REVISION.fullmatch(revision):
        raise RuntimeError("expected revision must be a canonical commit")
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("base-image evidence must be a non-symlink directory")
    manifest = read_json(output / "base-image-manifest.json", "base-image manifest")
    if not isinstance(manifest, dict) or set(manifest) != {
        "database", "database_metadata", "database_metadata_sha256", "database_updated_at",
        "observed_at", "schema", "source_revision", "trivy_version", "scans",
    } or manifest.get("schema") != SCHEMA or manifest.get("source_revision") != revision or \
            manifest.get("trivy_version") != TRIVY_VERSION or manifest.get("database") != TRIVY_DATABASE:
        raise RuntimeError("base-image manifest identity is invalid")
    require_fresh_database(manifest["database_updated_at"], manifest["observed_at"])
    scans = manifest.get("scans")
    if not isinstance(scans, list) or len(scans) != 4:
        raise RuntimeError("base-image scan inventory is invalid")
    expected_images = dockerfile_images()
    expected_pairs = [
        (image["role"], architecture, image["reference"])
        for image in expected_images for architecture in ARCHITECTURES
    ]
    exceptions = active_exceptions()
    expected_names = {"base-image-manifest.json", "SHA256SUMS", "trivy-db-metadata.json"}
    for scan, expected in zip(scans, expected_pairs, strict=True):
        expected_scope = "build-tool" if expected[0] == "build" else "release-runtime"
        if not isinstance(scan, dict) or \
                (scan.get("role"), scan.get("architecture"), scan.get("image")) != expected or \
                scan.get("gate_scope") != expected_scope:
            raise RuntimeError("base-image scan target binding is invalid")
        vulnerability_name = evidence_name(expected[0], expected[1], "vulnerabilities")
        sbom_name = evidence_name(expected[0], expected[1], "sbom.cdx")
        if scan.get("vulnerabilities") != vulnerability_name or scan.get("sbom") != sbom_name:
            raise RuntimeError("base-image evidence filename binding is invalid")
        expected_names.update({vulnerability_name, sbom_name})
        summary = vulnerability_summary(
            read_json(output / vulnerability_name, "Trivy vulnerability report"), exceptions,
        )
        if release_blocking(expected[0], summary):
            raise RuntimeError("runtime base image has unapproved Critical/High findings")
        if any(scan.get(key) != value for key, value in summary.items()) or \
                scan.get("sbom_component_count") != validate_sbom(
                    read_json(output / sbom_name, "Trivy CycloneDX SBOM"),
                ) or scan.get("vulnerabilities_sha256") != sha256_file(output / vulnerability_name) or \
                scan.get("sbom_sha256") != sha256_file(output / sbom_name):
            raise RuntimeError("base-image scan summary or digest is invalid")
    metadata_name = manifest["database_metadata"]
    if metadata_name != "trivy-db-metadata.json" or \
            manifest["database_metadata_sha256"] != sha256_file(output / metadata_name):
        raise RuntimeError("Trivy database metadata binding is invalid")
    metadata = read_json(output / metadata_name, "Trivy database metadata")
    if not isinstance(metadata, dict) or metadata.get("UpdatedAt") != manifest["database_updated_at"]:
        raise RuntimeError("Trivy database update time binding is invalid")
    entries = list(output.iterdir())
    if {entry.name for entry in entries} != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RuntimeError("base-image evidence has missing, extra, or unsafe entries")
    checksum_names = sorted(expected_names - {"SHA256SUMS"})
    expected_checksums = "".join(
        f"{sha256_file(output / name)}  {name}\n" for name in checksum_names
    )
    if (output / "SHA256SUMS").read_text(encoding="ascii") != expected_checksums:
        raise RuntimeError("base-image evidence checksums are invalid")


def main() -> None:
    args = parse_args()
    output = args.output.resolve()
    if not REVISION.fullmatch(args.revision):
        raise RuntimeError("source revision must be a canonical commit")
    if not args.verify_only:
        if args.trivy is None or args.cache_dir is None:
            raise RuntimeError("Trivy and cache directory are required")
        build(output, args.revision, args.trivy.resolve(), args.cache_dir.resolve())
    verify(output, args.revision)
    print("SevenMirror base-image SBOM and vulnerability evidence verified.")


if __name__ == "__main__":
    main()

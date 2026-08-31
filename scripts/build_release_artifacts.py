#!/usr/bin/env python3
"""Build and verify the bounded SevenMirror Server release artifact set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ARTIFACTS = (
    ("server", "linux", "amd64"),
    ("admin", "linux", "amd64"),
    ("server", "linux", "arm64"),
    ("admin", "linux", "arm64"),
)
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--verify-only", action="store_true")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_name(command: str, goos: str, goarch: str) -> str:
    return f"sevenmirror-{command}-{goos}-{goarch}"


def build(output: Path, revision: str, repository: Path) -> None:
    if output.exists() or output.is_symlink():
        raise RuntimeError("release output must not already exist")
    if not REVISION.fullmatch(revision):
        raise RuntimeError("release revision must be a canonical 40-character commit")
    protocol_version = (repository / "protocol" / "PROTOCOL_VERSION").read_text(
        encoding="ascii").strip()
    if not protocol_version or any(character.isspace() for character in protocol_version):
        raise RuntimeError("protocol version is invalid")
    go_version = subprocess.check_output(
        ["go", "env", "GOVERSION"], cwd=repository, text=True,
        encoding="utf-8").strip()
    output.mkdir(mode=0o700)
    records: list[dict[str, object]] = []
    for command, goos, goarch in ARTIFACTS:
        name = artifact_name(command, goos, goarch)
        destination = output / name
        env = os.environ.copy()
        env.update({"CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch})
        subprocess.run(
            [
                "go", "build", "-trimpath", "-buildvcs=true",
                "-ldflags=-s -w", "-o", str(destination), f"./cmd/{command}",
            ],
            cwd=repository,
            env=env,
            check=True,
        )
        metadata = subprocess.check_output(
            ["go", "version", "-m", str(destination)],
            text=True,
            encoding="utf-8",
        )
        required = (
            f"path\tgithub.com/huaxianyan/SyncNotifications-Server/cmd/{command}",
            f"build\tGOARCH={goarch}",
            f"build\tGOOS={goos}",
            f"build\tvcs.revision={revision}",
            "build\tvcs.modified=false",
        )
        if any(value not in metadata for value in required):
            raise RuntimeError(f"{name} does not contain the required clean VCS build metadata")
        records.append({
            "name": name,
            "sha256": sha256(destination),
            "size": destination.stat().st_size,
            "command": command,
            "goos": goos,
            "goarch": goarch,
        })
    records.sort(key=lambda record: str(record["name"]))
    manifest = {
        "schema": "sevenmirror-server-release-v1",
        "source_repository": "https://github.com/huaxianyan/SevenMirror-Server",
        "source_revision": revision,
        "protocol_version": protocol_version,
        "go_version": go_version,
        "artifacts": records,
    }
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "SHA256SUMS").write_text(
        "".join(f"{record['sha256']}  {record['name']}\n" for record in records),
        encoding="ascii",
    )


def verify(output: Path, revision: str) -> None:
    if not output.is_dir() or output.is_symlink():
        raise RuntimeError("release artifact directory must be a non-symlink directory")
    if not REVISION.fullmatch(revision):
        raise RuntimeError("expected revision must be a canonical commit")
    expected_names = {
        artifact_name(command, goos, goarch) for command, goos, goarch in ARTIFACTS
    }
    expected_entries = expected_names | {"release-manifest.json", "SHA256SUMS"}
    actual_entries = {path.name for path in output.iterdir()}
    if actual_entries != expected_entries or any(
        path.is_symlink() or not path.is_file() for path in output.iterdir()
    ):
        raise RuntimeError("release artifact directory has missing, extra, or unsafe entries")
    manifest = json.loads((output / "release-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "sevenmirror-server-release-v1" or \
            manifest.get("source_revision") != revision or \
            manifest.get("source_repository") != "https://github.com/huaxianyan/SevenMirror-Server":
        raise RuntimeError("release manifest source binding is invalid")
    records = manifest.get("artifacts")
    if not isinstance(records, list) or len(records) != len(ARTIFACTS):
        raise RuntimeError("release manifest artifact inventory is invalid")
    checksum_lines: list[str] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("release manifest artifact record is invalid")
        name = record.get("name")
        digest = record.get("sha256")
        size = record.get("size")
        if name not in expected_names or name in seen or \
                not isinstance(digest, str) or not DIGEST.fullmatch(digest) or \
                not isinstance(size, int) or size < 1:
            raise RuntimeError("release manifest artifact binding is invalid")
        path = output / name
        if path.stat().st_size != size or sha256(path) != digest:
            raise RuntimeError(f"release artifact {name} does not match its manifest")
        seen.add(name)
        checksum_lines.append(f"{digest}  {name}\n")
    if seen != expected_names or \
            (output / "SHA256SUMS").read_text(encoding="ascii") != "".join(checksum_lines):
        raise RuntimeError("release checksum inventory does not match the manifest")


def main() -> None:
    args = parse_args()
    repository = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if not args.verify_only:
        build(output, args.revision, repository)
    verify(output, args.revision)
    print("SevenMirror Server release artifact set verified.")


if __name__ == "__main__":
    main()

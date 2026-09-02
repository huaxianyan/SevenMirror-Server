#!/usr/bin/env python3
"""Validate the durable source-controlled GHCR release decision ledger."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

LEDGER = Path(__file__).resolve().parents[1] / "security" / "registry-release-ledger.json"
SCHEMA = "sevenmirror-registry-release-ledger-v1"
REGISTRY_REPOSITORY = "ghcr.io/huaxianyan/sevenmirror-server"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
RUN_URL = re.compile(
    r"https://github\.com/huaxianyan/SevenMirror-Server/actions/runs/[1-9][0-9]*",
)
ACTOR = re.compile(r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
ENTRY_KEYS = {
    "archive_reference",
    "decision_actors",
    "decision_reference",
    "decided_at",
    "index_digest",
    "platforms",
    "publication_run",
    "published_at",
    "registry_availability",
    "replacement_index_digest",
    "source_revision",
    "state",
}


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or \
            any(ord(character) < 0x20 for character in value):
        raise RuntimeError(f"release ledger field {field} must be nonempty canonical text")
    return value


def parse_time(value: object, field: str) -> datetime:
    text = require_text(value, field)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text):
        raise RuntimeError(f"release ledger field {field} must be canonical UTC seconds")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RuntimeError(f"release ledger field {field} is not a real timestamp") from error
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise RuntimeError(f"release ledger field {field} must be UTC")
    return parsed


def optional_text(value: object, field: str) -> str | None:
    return None if value is None else require_text(value, field)


def optional_digest(value: object, field: str) -> str | None:
    if value is None:
        return None
    text = require_text(value, field)
    if DIGEST.fullmatch(text) is None:
        raise RuntimeError(f"release ledger field {field} must be a sha256 digest")
    return text


def validate_entry(entry: object) -> tuple[datetime, str, str]:
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        raise RuntimeError("registry release entry has an invalid field set")
    revision = require_text(entry["source_revision"], "source_revision")
    index_digest = require_text(entry["index_digest"], "index_digest")
    if REVISION.fullmatch(revision) is None or DIGEST.fullmatch(index_digest) is None:
        raise RuntimeError("registry release identity is invalid")
    publication_run = require_text(entry["publication_run"], "publication_run")
    if RUN_URL.fullmatch(publication_run) is None:
        raise RuntimeError("registry release publication run is invalid")
    published_at = parse_time(entry["published_at"], "published_at")

    platforms = entry["platforms"]
    expected_architectures = ["amd64", "arm64"]
    if not isinstance(platforms, list) or len(platforms) != 2 or any(
        not isinstance(platform, dict)
        or set(platform) != {"architecture", "manifest_digest"}
        or platform.get("architecture") != architecture
        or not isinstance(platform.get("manifest_digest"), str)
        or DIGEST.fullmatch(platform["manifest_digest"]) is None
        for architecture, platform in zip(expected_architectures, platforms, strict=True)
    ):
        raise RuntimeError("registry release platform inventory is invalid")
    platform_digests = [platform["manifest_digest"] for platform in platforms]
    if len(set(platform_digests + [index_digest])) != 3:
        raise RuntimeError("registry release digests must be unique")

    state = entry["state"]
    availability = entry["registry_availability"]
    if state not in {"candidate", "approved", "retired", "revoked"} or \
            availability not in {"expected", "removed"}:
        raise RuntimeError("registry release state is invalid")
    actors = entry["decision_actors"]
    if not isinstance(actors, list) or actors != sorted(set(actors)) or any(
        not isinstance(actor, str) or ACTOR.fullmatch(actor) is None for actor in actors
    ):
        raise RuntimeError("registry release decision actors are invalid")
    decision_reference = optional_text(entry["decision_reference"], "decision_reference")
    archive_reference = optional_text(entry["archive_reference"], "archive_reference")
    replacement = optional_digest(entry["replacement_index_digest"], "replacement_index_digest")
    decided_at = None if entry["decided_at"] is None else parse_time(entry["decided_at"], "decided_at")
    if decided_at is not None and decided_at < published_at:
        raise RuntimeError("registry release decision predates publication")

    if state == "candidate":
        if actors or decision_reference is not None or decided_at is not None or \
                replacement is not None or availability != "expected" or archive_reference is not None:
            raise RuntimeError("candidate release cannot contain a decision or removal")
    elif state == "approved":
        if len(actors) < 2 or decision_reference is None or decided_at is None or \
                replacement is not None or availability != "expected" or archive_reference is not None:
            raise RuntimeError("approved release needs an independent retained decision")
    else:
        if state == "retired" and (len(actors) < 2 or decision_reference is None or decided_at is None):
            raise RuntimeError("retired release needs an independent retention decision")
        if state == "revoked" and (not actors or decision_reference is None or decided_at is None):
            raise RuntimeError("revoked release needs an attributable incident decision")
        if replacement == index_digest:
            raise RuntimeError("release replacement must differ")
        if availability == "removed" and archive_reference is None:
            raise RuntimeError("registry removal needs preserved evidence")
        if availability == "expected" and archive_reference is not None:
            raise RuntimeError("preserved removal evidence requires removed availability")

    return published_at, revision, index_digest


def validate_ledger(path: Path = LEDGER, publication_revision: str | None = None) -> int:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("registry release ledger must be a regular file")
    try:
        ledger = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("registry release ledger is invalid JSON") from error
    if not isinstance(ledger, dict) or set(ledger) != {
        "entries", "registry_repository", "schema",
    } or ledger.get("schema") != SCHEMA or \
            ledger.get("registry_repository") != REGISTRY_REPOSITORY or \
            not isinstance(ledger.get("entries"), list):
        raise RuntimeError("registry release ledger shape is invalid")
    identities = [validate_entry(entry) for entry in ledger["entries"]]
    if identities != sorted(identities) or len({item[1] for item in identities}) != len(identities) or \
            len({item[2] for item in identities}) != len(identities):
        raise RuntimeError("registry releases must be ordered with unique revisions and indexes")
    if publication_revision is not None:
        if REVISION.fullmatch(publication_revision) is None:
            raise RuntimeError("publication revision must be a canonical commit")
        blocked = [
            entry for entry in ledger["entries"]
            if entry["source_revision"] == publication_revision and entry["state"] in {"retired", "revoked"}
        ]
        if blocked:
            raise RuntimeError("retired or revoked source revision cannot be republished")
    return len(identities)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publication-revision")
    args = parser.parse_args()
    count = validate_ledger(publication_revision=args.publication_revision)
    print(f"SevenMirror registry release ledger valid: {count} entry or entries.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Run govulncheck once and emit bounded database freshness evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

SCANNER_VERSION = "v1.1.4"
DATABASE = "https://vuln.go.dev"
MAX_DATABASE_AGE = timedelta(days=7)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    return parser.parse_args()


def parse_stream(content: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder()
    messages: list[dict[str, object]] = []
    offset = 0
    while offset < len(content):
        while offset < len(content) and content[offset].isspace():
            offset += 1
        if offset == len(content):
            break
        value, offset = decoder.raw_decode(content, offset)
        if not isinstance(value, dict):
            raise RuntimeError("govulncheck emitted a non-object message")
        messages.append(value)
    if not messages:
        raise RuntimeError("govulncheck emitted no JSON messages")
    return messages


def parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeError("govulncheck database timestamp is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise RuntimeError("govulncheck database timestamp is invalid") from error
    return parsed


def run_gate(output: Path, revision: str, observed_at: datetime) -> dict[str, object]:
    if output.exists() or output.is_symlink():
        raise RuntimeError("govulncheck evidence output must not already exist")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise RuntimeError("govulncheck revision must be a canonical commit")
    completed = subprocess.run(
        [
            "go", "run", f"golang.org/x/vuln/cmd/govulncheck@{SCANNER_VERSION}",
            "-json", "./...",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=os.environ.copy(),
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stderr)
        sys.stderr.write(completed.stdout)
        raise RuntimeError(f"govulncheck exited with status {completed.returncode}")
    messages = parse_stream(completed.stdout)
    configs = [message["config"] for message in messages if "config" in message]
    if len(configs) != 1 or not isinstance(configs[0], dict):
        raise RuntimeError("govulncheck did not emit exactly one config")
    config = configs[0]
    runtime_go = subprocess.check_output(
        ["go", "env", "GOVERSION"], text=True, encoding="utf-8",
    ).strip()
    if config.get("scanner_name") != "govulncheck" or \
            config.get("scanner_version") != SCANNER_VERSION or \
            config.get("db") != DATABASE or config.get("scan_level") != "symbol" or \
            config.get("scan_mode") != "source" or config.get("go_version") != runtime_go:
        raise RuntimeError("govulncheck configuration does not match the release gate")
    database_time = parse_timestamp(config.get("db_last_modified"))
    if database_time > observed_at + timedelta(minutes=5) or \
            observed_at - database_time > MAX_DATABASE_AGE:
        raise RuntimeError("govulncheck vulnerability database is stale or future-dated")
    findings = [message["finding"] for message in messages if "finding" in message]
    reachable = [
        finding for finding in findings
        if isinstance(finding, dict)
        and any(
            isinstance(frame, dict) and isinstance(frame.get("function"), str)
            for frame in finding.get("trace", [])
        )
    ]
    if reachable:
        reachable_ids = sorted({
            str(finding.get("osv")) for finding in reachable if finding.get("osv")
        })
        raise RuntimeError(f"govulncheck reported reachable findings: {reachable_ids}")
    informational_ids = sorted({
        str(finding.get("osv"))
        for finding in findings
        if isinstance(finding, dict) and finding.get("osv")
    })
    evidence = {
        "schema": "sevenmirror-vulnerability-scan-evidence-v1",
        "repository": "SevenMirror-Server",
        "source_revision": revision,
        "scanner": "govulncheck",
        "scanner_version": SCANNER_VERSION,
        "database": DATABASE,
        "database_last_modified": database_time.isoformat().replace("+00:00", "Z"),
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "go_version": runtime_go,
        "scan_level": "symbol",
        "reachable_finding_count": 0,
        "informational_finding_ids": informational_ids,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> None:
    args = parse_args()
    evidence = run_gate(args.output.resolve(), args.revision, datetime.now(timezone.utc))
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    main()

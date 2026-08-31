#!/usr/bin/env python3
"""Build a bounded aggregate-only deployment support bundle."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re

ACCESS_LINE = re.compile(r"^(GET|POST) (/[^ ?#]*) ([1-5][0-9]{2})$")
ALLOWED_LEVELS = frozenset({"DEBUG", "INFO", "WARN", "ERROR"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-stdout", required=True, type=Path)
    parser.add_argument("--server-stderr", required=True, type=Path)
    parser.add_argument("--access-log", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def require_regular_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    return resolved


def runtime_level_counts(stdout_path: Path, stderr_path: Path) -> Counter[str]:
    stdout = require_regular_file(stdout_path, "server stdout")
    stderr = require_regular_file(stderr_path, "server stderr")
    if stderr.read_bytes():
        raise RuntimeError("server stderr is not eligible for a support bundle")
    counts: Counter[str] = Counter()
    for line in stdout.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise RuntimeError("server stdout contains a non-JSON event") from error
        if not isinstance(event, dict) or "level" not in event:
            raise RuntimeError("server stdout event shape is invalid")
        level = event.get("level")
        if level not in ALLOWED_LEVELS:
            raise RuntimeError("server stdout event level is invalid")
        counts[level] += 1
    return counts


def access_counts(access_log_path: Path) -> Counter[tuple[str, int]]:
    access_log = require_regular_file(access_log_path, "access log")
    counts: Counter[tuple[str, int]] = Counter()
    for line in access_log.read_text(encoding="utf-8").splitlines():
        match = ACCESS_LINE.fullmatch(line)
        if match is None:
            raise RuntimeError("access log contains a non-canonical event")
        method, _path, status = match.groups()
        counts[(method, int(status))] += 1
    return counts


def build_support_bundle(
    stdout_path: Path,
    stderr_path: Path,
    access_log_path: Path,
    output_directory: Path,
) -> Path:
    levels = runtime_level_counts(stdout_path, stderr_path)
    requests = access_counts(access_log_path)
    output = output_directory.resolve()
    if output.exists() or output.is_symlink():
        raise RuntimeError("support bundle output must not already exist")
    output.mkdir(mode=0o700, parents=False)
    manifest = {
        "schema": "sevenmirror-support-summary-v1",
        "runtime_level_counts": dict(sorted(levels.items())),
        "request_counts": [
            {"method": method, "status": status, "count": count}
            for (method, status), count in sorted(requests.items())
        ],
        "raw_logs_included": False,
        "http_paths_included": False,
        "admin_output_included": False,
        "operator_terminal_retention": "external-control-required",
    }
    destination = output / "summary.json"
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        destination.chmod(0o600)
    return output


def main() -> None:
    args = parse_args()
    build_support_bundle(
        args.server_stdout,
        args.server_stderr,
        args.access_log,
        args.output,
    )
    print("SevenMirror aggregate support bundle created.")


if __name__ == "__main__":
    main()

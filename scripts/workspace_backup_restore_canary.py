#!/usr/bin/env python3
"""Exercise real admin workspace backup, isolated restore, and authority rotation."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin", required=True, type=Path)
    return parser.parse_args()


def run_admin(binary: Path, env: dict[str, str], *args: str) -> str:
    completed = subprocess.run(
        [str(binary), *args],
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"admin command {args[0]} failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    if completed.stderr:
        raise RuntimeError("admin command wrote unexpected stderr")
    return completed.stdout


def field(output: str, name: str) -> str:
    prefix = name + "="
    values = [line[len(prefix):] for line in output.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"admin output did not contain exactly one {name}")
    return values[0]


def main() -> None:
    admin = parse_args().admin.resolve()
    if not admin.is_file():
        raise RuntimeError("built admin binary is required")

    with tempfile.TemporaryDirectory(prefix="sevenmirror-workspace-backup-") as temporary:
        root = Path(temporary)
        live = root / "live"
        backup = root / "backup"
        restored = root / "restored"
        live_env = os.environ.copy()
        live_env.update({
            "NM_DATABASE_PATH": str(live / "registry.sqlite"),
            "NM_AUTHORITY_KEY_DIR": str(live / "authority"),
        })
        initialized = run_admin(admin, live_env, "init-workspace")
        workspace = field(initialized, "workspace_id")
        original_key_id = field(initialized, "authority_key_id")

        backed_up = run_admin(
            admin, live_env, "backup-workspace",
            "--workspace", workspace,
            "--output", str(backup),
        )
        if field(backed_up, "authority_key_id") != original_key_id:
            raise RuntimeError("workspace backup selected a different authority")
        verified = run_admin(
            admin, os.environ.copy(), "verify-workspace-backup",
            "--workspace", workspace,
            "--backup", str(backup),
        )
        if field(verified, "result") != "verified":
            raise RuntimeError("workspace backup did not verify")

        shutil.rmtree(live)
        restored_registry = restored / "registry.sqlite"
        restored_authority = restored / "authority"
        restored_output = run_admin(
            admin, os.environ.copy(), "restore-workspace-backup",
            "--workspace", workspace,
            "--backup", str(backup),
            "--database", str(restored_registry),
            "--authority-key-directory", str(restored_authority),
        )
        if field(restored_output, "result") != "restored":
            raise RuntimeError("workspace backup did not restore into empty destinations")

        restored_env = os.environ.copy()
        restored_env.update({
            "NM_DATABASE_PATH": str(restored_registry),
            "NM_AUTHORITY_KEY_DIR": str(restored_authority),
        })
        second_backup = root / "second-backup"
        backed_up_again = run_admin(
            admin, restored_env, "backup-workspace",
            "--workspace", workspace,
            "--output", str(second_backup),
        )
        if field(backed_up_again, "authority_key_id") != original_key_id:
            raise RuntimeError("restored registry and authority could not create a bound backup")
        verified_again = run_admin(
            admin, os.environ.copy(), "verify-workspace-backup",
            "--workspace", workspace,
            "--backup", str(second_backup),
        )
        if field(verified_again, "result") != "verified":
            raise RuntimeError("backup created from restored state did not verify")

    print("Workspace registry and authority backup/restore canary passed.")


if __name__ == "__main__":
    main()

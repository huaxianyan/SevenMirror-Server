#!/usr/bin/env python3
"""Exercise real Server binaries and reject credential or plaintext leakage."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

PUBLIC_P256_POINT = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RuntimeError(f"unexpected redirect status {code}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--admin", required=True, type=Path)
    return parser.parse_args()


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def run_admin(binary: Path, env: dict[str, str], *args: str) -> str:
    completed = subprocess.run(
        [str(binary), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    if completed.stderr:
        raise RuntimeError("admin command wrote unexpected stderr")
    return completed.stdout


def field(output: str, name: str) -> str:
    prefix = f"{name}="
    values = [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"admin output did not contain exactly one {name}")
    return values[0]


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    body: dict[str, object],
    expected_status: int,
) -> tuple[bytes, str]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with opener.open(request, timeout=5) as response:
            status = response.status
            payload = response.read()
            effective_url = response.url
    except urllib.error.HTTPError as error:
        status = error.code
        payload = error.read()
        effective_url = error.url
    if status != expected_status:
        raise RuntimeError(f"unexpected HTTP status {status}, expected {expected_status}")
    if effective_url != url:
        raise RuntimeError("request target changed")
    return payload, effective_url


def wait_until_ready(opener: urllib.request.OpenerDirector, origin: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with opener.open(f"{origin}/readyz", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("server did not become ready")


def stop_server(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("server did not shut down cleanly")
    if os.name != "nt" and process.returncode != 0:
        raise RuntimeError(f"server exited with status {process.returncode}")


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def scan_artifacts(directory: Path, canaries: dict[str, tuple[bytes, ...]]) -> None:
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        content = path.read_bytes()
        for label, variants in canaries.items():
            if any(variant and variant in content for variant in variants):
                raise RuntimeError(f"{label} leaked into {path.name}")


def main() -> None:
    args = parse_args()
    server_binary = args.server.resolve()
    admin_binary = args.admin.resolve()
    if not server_binary.is_file() or not admin_binary.is_file():
        raise RuntimeError("built server and admin binaries are required")

    with tempfile.TemporaryDirectory(prefix="sevenmirror-server-canary-") as temporary:
        root = Path(temporary)
        business_canary = f"sevenmirror-business-plaintext-canary-{secrets.token_hex(8)}"
        database = root / "registry.db"
        stdout_path = root / "server.stdout.log"
        stderr_path = root / "server.stderr.log"
        urls_path = root / "request-targets.log"
        errors_path = root / "http-errors.log"
        env = os.environ.copy()
        env.update(
            {
                "NM_ADDRESS": f"127.0.0.1:{free_loopback_port()}",
                "NM_DATABASE_PATH": str(database),
                "NM_AUTHORITY_KEY_DIR": str(root / "authority-keys"),
            }
        )

        workspace = field(run_admin(admin_binary, env, "init-workspace"), "workspace_id")
        issue_output = run_admin(
            admin_binary,
            env,
            "issue-pairing-code",
            "--workspace",
            workspace,
            "--type",
            "chrome",
            "--name",
            "Canary Browser",
            "--ttl",
            "10m",
        )
        pairing_code = field(issue_output, "pairing_code")
        if issue_output.count(pairing_code) != 1:
            raise RuntimeError("admin stdout did not contain the pairing code exactly once")

        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [str(server_binary)],
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env=env,
                creationflags=creation_flags,
            )
        try:
            origin = f"http://{env['NM_ADDRESS']}"
            opener = urllib.request.build_opener(NoRedirect())
            wait_until_ready(opener, origin)
            registration_url = f"{origin}/v1/devices/register"
            registration = {
                "pairing_code": pairing_code,
                "device_type": "chrome",
                "device_name": "Canary Browser",
                "e2ee_public_key": base64.urlsafe_b64encode(PUBLIC_P256_POINT).rstrip(b"=").decode("ascii"),
            }
            success, success_url = request_json(opener, registration_url, registration, 201)
            response = json.loads(success)
            auth_token = response.get("auth_token")
            if not isinstance(auth_token, str) or len(decode_base64url(auth_token)) != 32:
                raise RuntimeError("registration did not return one canonical credential")

            replay_error, replay_url = request_json(opener, registration_url, registration, 403)
            invalid_error, invalid_url = request_json(
                opener,
                registration_url,
                {**registration, "notification_title": business_canary},
                400,
            )
            errors_path.write_bytes(replay_error + invalid_error)
            urls_path.write_text(
                "\n".join((success_url, replay_url, invalid_url)) + "\n",
                encoding="utf-8",
            )

            canaries = {
                "pairing code": (pairing_code.encode("ascii"), decode_base64url(pairing_code)),
                "transport credential": (auth_token.encode("ascii"), decode_base64url(auth_token)),
                "business plaintext": (business_canary.encode("utf-8"),),
            }
            scan_artifacts(root, canaries)
            stop_server(process)
            scan_artifacts(root, canaries)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    print("Server credential and plaintext canary scan passed.")


if __name__ == "__main__":
    main()

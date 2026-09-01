#!/usr/bin/env python3
"""Exercise real Server slow-client, rate-limit, and auth-capacity boundaries."""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    return parser.parse_args()


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def request_status(url: str, path: str, forwarded: str | None = None) -> int:
    headers = {"Content-Type": "application/json"}
    if forwarded is not None:
        headers["X-Forwarded-For"] = forwarded
    request = urllib.request.Request(
        url + path, data=b"", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def websocket_handshake(port: int, forwarded: str) -> tuple[socket.socket, int, bytes]:
    connection = socket.create_connection(("127.0.0.1", port), timeout=3)
    connection.settimeout(3)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /v1/relay HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"X-Forwarded-For: {forwarded}\r\n"
        "\r\n"
    ).encode("ascii")
    connection.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(4096)
        if not chunk:
            break
        response += chunk
    first_line = response.split(b"\r\n", 1)[0]
    parts = first_line.split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        connection.close()
        raise RuntimeError(f"invalid WebSocket handshake response: {first_line!r}")
    return connection, int(parts[1]), response.split(b"\r\n\r\n", 1)[-1]


def expect_http_connection_terminated(connection: socket.socket, label: str) -> None:
    connection.settimeout(3)
    response = b""
    try:
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout as error:
        connection.close()
        raise RuntimeError(f"{label} connection remained open") from error
    connection.close()
    if b" 200 " in response.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"{label} request unexpectedly succeeded")


def expect_policy_close(connection: socket.socket, buffered: bytes = b"") -> None:
    frame = buffered
    deadline = time.monotonic() + 3
    while len(frame) < 4 and time.monotonic() < deadline:
        chunk = connection.recv(4096)
        if not chunk:
            break
        frame += chunk
    connection.close()
    if not frame or frame[0] != 0x88 or b"\x03\xf0" not in frame:
        raise RuntimeError("slow authentication did not receive policy close 1008")


def main() -> None:
    server_binary = parse_args().server.resolve()
    if not server_binary.is_file():
        raise RuntimeError("built Server binary is required")
    port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="sevenmirror-abuse-limit-") as temporary:
        root = Path(temporary)
        env = os.environ.copy()
        env.update({
            "NM_ADDRESS": f"127.0.0.1:{port}",
            "NM_DATABASE_PATH": str(root / "registry.sqlite"),
            "NM_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            "NM_READ_HEADER_TIMEOUT_SECONDS": "1",
            "NM_REQUEST_READ_TIMEOUT_SECONDS": "1",
            "NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE": "2",
            "NM_ROTATION_ATTEMPTS_PER_MINUTE": "2",
            "NM_RATE_LIMIT_MAX_CLIENT_BUCKETS": "2",
            "NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE": "6",
            "NM_RELAY_AUTH_MAX_CLIENT_BUCKETS": "2",
            "NM_RELAY_AUTH_MAX_CONCURRENT": "1",
            "NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS": "1",
        })
        process = subprocess.Popen(
            [str(server_binary)], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        origin = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urllib.request.urlopen(origin + "/healthz", timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("Server did not become ready")
                time.sleep(0.05)

            membership = [request_status(
                origin, "/v1/membership/register", "198.51.100.10") for _ in range(3)]
            if 429 in membership[:2] or membership[2] != 429:
                raise RuntimeError(f"membership attempt limit statuses={membership}")
            if request_status(origin, "/v1/membership/register", "198.51.100.11") == 429 or \
                    request_status(origin, "/v1/membership/register", "198.51.100.12") != 429:
                raise RuntimeError("membership client-bucket capacity was not enforced")

            rotation = [request_status(
                origin, "/v1/devices/rotate", "198.51.100.20") for _ in range(3)]
            if 429 in rotation[:2] or rotation[2] != 429:
                raise RuntimeError(f"rotation attempt limit statuses={rotation}")

            slow_header = socket.create_connection(("127.0.0.1", port), timeout=3)
            slow_header.settimeout(3)
            slow_header.sendall(b"GET /healthz HTTP/1.1\r\nHost:")
            time.sleep(1.3)
            expect_http_connection_terminated(slow_header, "slow HTTP header")

            slow_body = socket.create_connection(("127.0.0.1", port), timeout=3)
            slow_body.sendall(
                b"POST /v1/membership/register HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"X-Forwarded-For: 198.51.100.11\r\n"
                b"Content-Length: 100\r\n\r\n{")
            time.sleep(1.3)
            expect_http_connection_terminated(slow_body, "slow HTTP body")

            held, status, buffered = websocket_handshake(port, "198.51.100.30")
            if status != 101:
                held.close()
                raise RuntimeError(f"first auth handshake status={status}")
            capacity, status, _ = websocket_handshake(port, "198.51.100.30")
            capacity.close()
            if status != 503:
                held.close()
                raise RuntimeError(f"concurrent auth capacity status={status}")
            time.sleep(1.3)
            expect_policy_close(held, buffered)

            slow_auth, status, buffered = websocket_handshake(port, "198.51.100.30")
            if status != 101:
                slow_auth.close()
                raise RuntimeError(f"slow auth handshake status={status}")
            time.sleep(1.3)
            expect_policy_close(slow_auth, buffered)

            for _ in range(3):
                connection, status, _ = websocket_handshake(port, "198.51.100.30")
                if status != 101:
                    connection.close()
                    raise RuntimeError(f"bounded auth attempt status={status}")
                connection.close()
            blocked, status, _ = websocket_handshake(port, "198.51.100.30")
            blocked.close()
            if status != 429:
                raise RuntimeError(f"relay authentication attempt limit status={status}")
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)

    print("Server abuse-limit canary passed.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Validate the production Caddy TLS, forwarding, rate-limit, and log baseline."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time

PUBLIC_P256_POINT = bytes.fromhex(
    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--caddy", required=True, type=Path)
    parser.add_argument(
        "--caddyfile",
        type=Path,
        default=Path("deploy/caddy/Caddyfile"),
    )
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--private-key", type=Path)
    args = parser.parse_args()
    if (args.certificate is None) != (args.private_key is None):
        parser.error("--certificate and --private-key must be provided together")
    return args


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError("test process did not stop cleanly")


def https_request(
    port: int,
    source: str,
    method: str,
    target: str,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(
        "127.0.0.1",
        port,
        timeout=5,
        context=context,
        source_address=(source, 0),
    )
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_until_ready(port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            status, _ = https_request(port, "127.0.0.1", "GET", "/readyz")
            if status == 200:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("Caddy proxy did not become ready")


def receive_exact(connection: ssl.SSLSocket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RuntimeError("WebSocket closed before the expected frame")
        result.extend(chunk)
    return bytes(result)


def verify_websocket_forwarding(port: int, header_canary: str) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    connection = context.wrap_socket(raw, server_hostname="127.0.0.1")
    try:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            "GET /v1/relay HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"X-Canary-Secret: {header_canary}\r\n\r\n"
        ).encode("ascii")
        connection.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(connection.recv(4096))
        if not response.startswith(b"HTTP/1.1 101 "):
            raise RuntimeError("Caddy did not forward the WebSocket upgrade")

        mask = secrets.token_bytes(4)
        payload = b"x"
        connection.sendall(bytes((0x82, 0x81)) + mask + bytes((payload[0] ^ mask[0],)))
        header = receive_exact(connection, 2)
        if header[0] & 0x0F != 0x08 or header[1] & 0x80:
            raise RuntimeError("relay did not return an unmasked close frame")
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", receive_exact(connection, 2))[0]
        payload = receive_exact(connection, length)
        if len(payload) < 2 or struct.unpack(">H", payload[:2])[0] != 1008:
            raise RuntimeError("malformed authentication did not receive policy close 1008")
    finally:
        connection.close()


def verify_access_log(path: Path, forbidden: tuple[bytes, ...]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not path.exists():
        time.sleep(0.05)
    content = path.read_bytes()
    if any(value in content for value in forbidden):
        raise RuntimeError("Caddy access log retained a query, header, or body canary")
    entries = [json.loads(line) for line in content.splitlines() if line]
    if not entries:
        raise RuntimeError("Caddy access log is empty")
    allowed_top_level = {"level", "ts", "logger", "msg", "request", "status"}
    for entry in entries:
        if set(entry) - allowed_top_level:
            raise RuntimeError(f"Caddy access log retained unexpected fields: {sorted(set(entry) - allowed_top_level)}")
        request = entry.get("request")
        if not isinstance(request, dict) or set(request) != {"method", "uri"}:
            raise RuntimeError("Caddy access log request fields exceed method and path")
        if "?" in request["uri"]:
            raise RuntimeError("Caddy access log retained a query string")
        if not isinstance(entry.get("status"), int):
            raise RuntimeError("Caddy access log omitted response status")


def main() -> None:
    args = parse_args()
    server_binary = args.server.resolve()
    caddy_binary = args.caddy.resolve()
    caddyfile = args.caddyfile.resolve()
    if not server_binary.is_file() or not caddy_binary.is_file() or not caddyfile.is_file():
        raise RuntimeError("Server binary, Caddy binary, and Caddyfile are required")

    with tempfile.TemporaryDirectory(prefix="sevenmirror-caddy-canary-") as temporary:
        root = Path(temporary)
        server_port = free_loopback_port()
        proxy_port = free_loopback_port()
        certificate = args.certificate.resolve() if args.certificate else root / "proxy-cert.pem"
        private_key = args.private_key.resolve() if args.private_key else root / "proxy-key.pem"
        access_log = root / "access.log"
        query_canary = f"query-{secrets.token_hex(12)}"
        header_canary = f"header-{secrets.token_hex(12)}"
        body_canary = f"body-{secrets.token_hex(12)}"

        if args.certificate is None:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(private_key), "-out", str(certificate), "-days", "1",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            private_key.chmod(0o600)
        elif not certificate.is_file() or not private_key.is_file():
            raise RuntimeError("provided TLS certificate and private key are required")

        server_env = os.environ.copy()
        server_env.update({
            "NM_ADDRESS": f"127.0.0.1:{server_port}",
            "NM_DATABASE_PATH": str(root / "registry.db"),
            "NM_AUTHORITY_KEY_DIR": str(root / "authority-keys"),
            "NM_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
        })
        caddy_env = os.environ.copy()
        caddy_env.update({
            "SEVENMIRROR_LISTEN_ADDRESS": f"https://127.0.0.1:{proxy_port}",
            "SEVENMIRROR_TLS_CERT_FILE": str(certificate),
            "SEVENMIRROR_TLS_KEY_FILE": str(private_key),
            "SEVENMIRROR_ACCESS_LOG": str(access_log),
            "SEVENMIRROR_UPSTREAM": f"127.0.0.1:{server_port}",
        })
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        with (root / "server.stdout").open("wb") as server_stdout, \
                (root / "server.stderr").open("wb") as server_stderr, \
                (root / "caddy.stdout").open("wb") as caddy_stdout, \
                (root / "caddy.stderr").open("wb") as caddy_stderr:
            server = subprocess.Popen(
                [str(server_binary)], env=server_env, stdin=subprocess.DEVNULL,
                stdout=server_stdout, stderr=server_stderr, creationflags=creation_flags,
            )
            caddy = subprocess.Popen(
                [str(caddy_binary), "run", "--config", str(caddyfile), "--adapter", "caddyfile"],
                env=caddy_env, stdin=subprocess.DEVNULL, stdout=caddy_stdout,
                stderr=caddy_stderr, creationflags=creation_flags,
            )
        try:
            wait_until_ready(proxy_port)
            registration = json.dumps({
                "pairing_code": encode_base64url(secrets.token_bytes(24)),
                "device_type": "chrome",
                "device_name": "Proxy Canary",
                "e2ee_public_key": encode_base64url(PUBLIC_P256_POINT),
                "business_canary": body_canary,
            }, separators=(",", ":")).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "X-Canary-Secret": header_canary,
            }
            for index in range(10):
                headers["X-Forwarded-For"] = f"203.0.113.{index + 1}"
                status, _ = https_request(
                    proxy_port, "127.0.0.2", "POST", "/v1/membership/register",
                    registration, headers,
                )
                if status != 400:
                    raise RuntimeError(f"registration attempt {index + 1} returned {status}")
            status, _ = https_request(
                proxy_port, "127.0.0.2", "POST", "/v1/membership/register",
                registration, headers,
            )
            if status != 429:
                raise RuntimeError("trusted-proxy client address did not reach its own rate limit")
            status, _ = https_request(
                proxy_port, "127.0.0.3", "POST", "/v1/membership/register",
                registration, headers,
            )
            if status != 400:
                raise RuntimeError("distinct proxied client was collapsed into another rate-limit bucket")

            status, _ = https_request(
                proxy_port, "127.0.0.1", "GET", f"/healthz?secret={query_canary}",
                headers={"X-Canary-Secret": header_canary},
            )
            if status != 200:
                raise RuntimeError("TLS health request failed")
            verify_websocket_forwarding(proxy_port, header_canary)
        finally:
            stop_process(caddy)
            stop_process(server)

        verify_access_log(
            access_log,
            tuple(value.encode("utf-8") for value in (query_canary, header_canary, body_canary)),
        )

    print("Caddy TLS, trusted-proxy, WebSocket, and access-log canary passed.")


if __name__ == "__main__":
    main()

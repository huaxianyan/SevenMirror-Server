#!/usr/bin/env python3
"""Exercise real Server binaries and reject credential or plaintext leakage."""

from __future__ import annotations

import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
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


def start_access_log_proxy(
    upstream_origin: str,
    access_log: Path,
) -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    opener = urllib.request.build_opener(NoRedirect())
    log_lock = threading.Lock()

    class AccessLogProxy(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.headers.get("Upgrade", "").lower() == "websocket":
                self.record(502)
                self.send_error(502, "WebSocket forwarding is outside this test fixture")
                return
            self.forward()

        def do_POST(self) -> None:  # noqa: N802
            self.forward()

        def forward(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else None
            request = urllib.request.Request(
                upstream_origin + self.path,
                data=body,
                headers={
                    "Content-Type": self.headers.get("Content-Type", ""),
                    "Accept": self.headers.get("Accept", "application/json"),
                },
                method=self.command,
            )
            try:
                with opener.open(request, timeout=5) as response:
                    status = response.status
                    payload = response.read()
                    content_type = response.headers.get("Content-Type")
            except urllib.error.HTTPError as error:
                status = error.code
                payload = error.read()
                content_type = error.headers.get("Content-Type")
            self.record(status)
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def record(self, status: int) -> None:
            # Access evidence intentionally records only the request target, never
            # headers or bodies that may contain one-time credentials.
            with log_lock:
                with access_log.open("a", encoding="utf-8") as output:
                    output.write(f"{self.command} {self.path} {status}\n")

        def log_message(self, _format: str, *args: object) -> None:
            return

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), AccessLogProxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    host, port = proxy.server_address
    return proxy, thread, f"http://{host}:{port}"


def stop_access_log_proxy(proxy: ThreadingHTTPServer, thread: threading.Thread) -> None:
    proxy.shutdown()
    proxy.server_close()
    thread.join(timeout=5)
    if thread.is_alive():
        raise RuntimeError("access-log proxy did not stop")


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


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def receive_exact(connection: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            raise RuntimeError("WebSocket closed during frame read")
        chunks.extend(chunk)
    return bytes(chunks)


def websocket_handshake(url_origin: str, path: str) -> tuple[socket.socket, int]:
    host, port_text = url_origin.removeprefix("http://").split(":", 1)
    port = int(port_text)
    connection = socket.create_connection((host, port), timeout=5)
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    connection.sendall(request.encode("ascii"))
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(connection.recv(4096))
        if len(response) > 16384:
            connection.close()
            raise RuntimeError("WebSocket handshake response was oversized")
    header = bytes(response).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    status = int(header.split(" ", 2)[1])
    if status == 101:
        expected_accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        if f"Sec-WebSocket-Accept: {expected_accept}".lower() not in header.lower():
            connection.close()
            raise RuntimeError("WebSocket accept binding did not match")
    return connection, status


def send_masked_binary(connection: socket.socket, payload: bytes) -> None:
    if len(payload) >= 126:
        raise RuntimeError("canary WebSocket frame unexpectedly requires extended length")
    mask = secrets.token_bytes(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(bytes((0x82, 0x80 | len(payload))) + mask + masked)


def read_websocket_result(connection: socket.socket) -> tuple[str, bytes | int]:
    while True:
        first, second = receive_exact(connection, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", receive_exact(connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", receive_exact(connection, 8))[0]
        if second & 0x80:
            mask = receive_exact(connection, 4)
            payload = bytes(
                byte ^ mask[index % 4]
                for index, byte in enumerate(receive_exact(connection, length))
            )
        else:
            payload = receive_exact(connection, length)
        if opcode == 0x2:
            return "binary", payload
        if opcode == 0x8:
            code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
            return "close", code
        if opcode == 0x9:
            # Authentication completes before the normal heartbeat interval, but
            # answer a server Ping correctly if scheduling is unusually delayed.
            mask = secrets.token_bytes(4)
            masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            connection.sendall(bytes((0x8A, 0x80 | len(payload))) + mask + masked)


def authenticate_websocket(
    origin: str,
    workspace_id: bytes,
    device_id: bytes,
    token: bytes,
) -> tuple[str, bytes | int]:
    connection, status = websocket_handshake(origin, "/v1/relay")
    if status != 101:
        connection.close()
        raise RuntimeError(f"unexpected WebSocket handshake status {status}")
    try:
        send_masked_binary(
            connection,
            b"SNA1" + workspace_id + device_id + token,
        )
        return read_websocket_result(connection)
    finally:
        connection.close()


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
        proxy_log_path = root / "reverse-proxy-access.log"
        websocket_targets_path = root / "websocket-targets.log"
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
        proxy: ThreadingHTTPServer | None = None
        proxy_thread: threading.Thread | None = None
        try:
            origin = f"http://{env['NM_ADDRESS']}"
            opener = urllib.request.build_opener(NoRedirect())
            wait_until_ready(opener, origin)
            proxy, proxy_thread, proxy_origin = start_access_log_proxy(origin, proxy_log_path)
            wait_until_ready(opener, proxy_origin)
            legacy_registration_url = f"{proxy_origin}/v1/devices/register"
            registration_url = f"{proxy_origin}/v1/membership/register"
            registration = {
                "pairing_code": pairing_code,
                "device_type": "chrome",
                "device_name": "Canary Browser",
                "e2ee_public_key": encode_base64url(PUBLIC_P256_POINT),
            }
            legacy_error, legacy_url = request_json(
                opener, legacy_registration_url, registration, 404)
            success, success_url = request_json(opener, registration_url, registration, 201)
            response = json.loads(success)
            workspace_id = response.get("workspace_id")
            device_id = response.get("device_id")
            auth_token = response.get("auth_token")
            if not isinstance(workspace_id, str) or len(decode_base64url(workspace_id)) != 16:
                raise RuntimeError("registration did not return one canonical workspace ID")
            if not isinstance(device_id, str) or len(decode_base64url(device_id)) != 16:
                raise RuntimeError("registration did not return one canonical device ID")
            if not isinstance(auth_token, str) or len(decode_base64url(auth_token)) != 32:
                raise RuntimeError("registration did not return one canonical credential")

            replay_error, replay_url = request_json(opener, registration_url, registration, 403)
            invalid_error, invalid_url = request_json(
                opener,
                registration_url,
                {**registration, "notification_title": business_canary},
                400,
            )

            # This scanner's subject is credential/plaintext placement, not HPKE
            # proof correctness (covered by membership integration and vectors).
            # Promote only this temporary pending row so rotation and relay canaries
            # can exercise the production binaries without shipping a test endpoint.
            fixture_database = sqlite3.connect(database)
            try:
                updated = fixture_database.execute(
                    "UPDATE devices SET membership_state = 'approved' "
                    "WHERE workspace_id = ? AND id = ? AND membership_state = 'pending_proof'",
                    (decode_base64url(workspace_id), decode_base64url(device_id)),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("canary fixture could not promote pending membership")
                fixture_database.commit()
            finally:
                fixture_database.close()

            devices_output = run_admin(
                admin_binary, env, "list-devices", "--workspace", workspace)
            device_reference = field(devices_output, "device_ref").split(" ", 1)[0]
            rotation_output = run_admin(
                admin_binary,
                env,
                "issue-rotation-code",
                "--workspace",
                workspace,
                "--device-ref",
                device_reference,
                "--ttl",
                "10m",
            )
            rotation_code = field(rotation_output, "rotation_code")
            if rotation_output.count(rotation_code) != 1:
                raise RuntimeError("admin stdout did not contain the rotation code exactly once")
            pending_token_bytes = secrets.token_bytes(32)
            pending_token = encode_base64url(pending_token_bytes)
            rotation_url = f"{proxy_origin}/v1/devices/rotate"
            rotation = {
                "workspace_id": workspace_id,
                "device_id": device_id,
                "current_auth_token": auth_token,
                "rotation_code": rotation_code,
                "pending_auth_token": pending_token,
            }
            rotated, rotated_url = request_json(opener, rotation_url, rotation, 200)
            if json.loads(rotated) != {"status": "rotated"}:
                raise RuntimeError("rotation did not return the exact success response")
            rotation_replay_error, rotation_replay_url = request_json(
                opener, rotation_url, rotation, 403)
            rotation_invalid_error, rotation_invalid_url = request_json(
                opener,
                rotation_url,
                {**rotation, "notification_title": business_canary},
                400,
            )

            websocket_url = f"ws://{env['NM_ADDRESS']}/v1/relay"
            proxy_websocket_url = proxy_origin.replace("http://", "ws://") + "/v1/relay"
            websocket_targets_path.write_text(
                websocket_url + "\n" + proxy_websocket_url + "\n",
                encoding="utf-8",
            )
            proxy_connection, proxy_status = websocket_handshake(proxy_origin, "/v1/relay")
            proxy_connection.close()
            if proxy_status != 502:
                raise RuntimeError("access-log proxy WebSocket probe did not return 502")
            proxy_lines = proxy_log_path.read_text(encoding="utf-8").splitlines()
            for expected_target in (
                "POST /v1/devices/register ",
                "POST /v1/membership/register ",
                "POST /v1/devices/rotate ",
                "GET /v1/relay ",
            ):
                if not any(line.startswith(expected_target) for line in proxy_lines):
                    raise RuntimeError(f"access-log proxy missed {expected_target.strip()}")
            if any("?" in line.split(" ", 2)[1] for line in proxy_lines):
                raise RuntimeError("access-log proxy observed an unexpected query string")

            workspace_bytes = decode_base64url(workspace_id)
            device_bytes = decode_base64url(device_id)
            old_result = authenticate_websocket(
                origin, workspace_bytes, device_bytes, decode_base64url(auth_token))
            if old_result != ("close", 1008):
                raise RuntimeError("old credential did not receive the generic policy close")
            pending_result = authenticate_websocket(
                origin, workspace_bytes, device_bytes, pending_token_bytes)
            if pending_result != ("binary", b"SNO1"):
                raise RuntimeError("pending credential did not receive exact SNO1")

            errors_path.write_bytes(
                legacy_error + replay_error + invalid_error +
                rotation_replay_error + rotation_invalid_error)
            urls_path.write_text(
                "\n".join((
                    legacy_url,
                    success_url,
                    replay_url,
                    invalid_url,
                    rotated_url,
                    rotation_replay_url,
                    rotation_invalid_url,
                )) + "\n",
                encoding="utf-8",
            )

            canaries = {
                "pairing code": (pairing_code.encode("ascii"), decode_base64url(pairing_code)),
                "rotation code": (rotation_code.encode("ascii"), decode_base64url(rotation_code)),
                "current transport credential": (
                    auth_token.encode("ascii"), decode_base64url(auth_token)),
                "pending transport credential": (
                    pending_token.encode("ascii"), pending_token_bytes),
                "business plaintext": (business_canary.encode("utf-8"),),
            }
            scan_artifacts(root, canaries)
            stop_access_log_proxy(proxy, proxy_thread)
            proxy = None
            proxy_thread = None
            stop_server(process)
            scan_artifacts(root, canaries)
        finally:
            if proxy is not None and proxy_thread is not None:
                stop_access_log_proxy(proxy, proxy_thread)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    print("Server credential and plaintext canary scan passed.")


if __name__ == "__main__":
    main()

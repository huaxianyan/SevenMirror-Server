#!/usr/bin/env python3
"""Exercise real Server reconnect waves and sustained online ciphertext routing."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.request

from server_canary_scan import (
    PUBLIC_P256_POINT,
    field,
    read_websocket_result,
    run_admin,
    send_masked_binary,
    stop_server,
    websocket_handshake,
)

STORM_CLIENTS = 32
STORM_WAVES = 4
ROUTING_PAIRS = 16
FRAMES_PER_PAIR = 125
MAX_RSS_GROWTH_BYTES = 128 * 1024 * 1024
MAX_FINAL_DESCRIPTOR_GROWTH = 96
MINIMUM_FRAMES_PER_SECOND = 100


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--admin", required=True, type=Path)
    return parser.parse_args()


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def wait_until_ready(origin: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(origin + "/readyz", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        if process.poll() is not None:
            raise RuntimeError("Server stopped before becoming ready")
        time.sleep(0.05)
    raise RuntimeError("Server did not become ready")


def seed_approved_devices(
    database: Path,
    workspace_id: bytes,
    count: int,
) -> list[tuple[bytes, bytes]]:
    devices: list[tuple[bytes, bytes]] = []
    now = int(time.time() * 1000)
    connection = sqlite3.connect(database)
    try:
        for index in range(count):
            device_id = secrets.token_bytes(16)
            token = secrets.token_bytes(32)
            connection.execute(
                "INSERT INTO devices "
                "(workspace_id, id, device_type, device_name, auth_token_hash, "
                "e2ee_public_key, registered_at_ms, last_online_at_ms, "
                "membership_state, approved_at_ms) "
                "VALUES (?, ?, 'chrome', ?, ?, ?, ?, ?, 'approved', ?)",
                (
                    workspace_id,
                    device_id,
                    f"Capacity fixture {index}",
                    hashlib.sha256(token).digest(),
                    PUBLIC_P256_POINT,
                    now,
                    now,
                    now,
                ),
            )
            devices.append((device_id, token))
        connection.commit()
    finally:
        connection.close()
    return devices


def authenticate(origin: str, workspace_id: bytes, device: tuple[bytes, bytes]) -> socket.socket:
    device_id, token = device
    connection, status = websocket_handshake(origin, "/v1/relay")
    connection.settimeout(5)
    if status != 101:
        connection.close()
        raise RuntimeError(f"WebSocket handshake returned {status}")
    send_masked_binary(connection, b"SNA1" + workspace_id + device_id + token)
    result = read_websocket_result(connection)
    if result != ("binary", b"SNO1"):
        connection.close()
        raise RuntimeError("WebSocket authentication did not return exact SNO1")
    return connection


def process_usage(process: subprocess.Popen[bytes]) -> tuple[int, int]:
    if os.name == "nt":
        class MemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = MemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(  # type: ignore[attr-defined]
            int(process._handle), ctypes.byref(counters), counters.cb  # noqa: SLF001
        ):
            raise RuntimeError("Could not read Server memory counters")
        handles = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetProcessHandleCount(  # type: ignore[attr-defined]
            int(process._handle), ctypes.byref(handles)  # noqa: SLF001
        ):
            raise RuntimeError("Could not read Server handle count")
        return int(counters.WorkingSetSize), int(handles.value)

    status = Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8")
    rss_line = next(line for line in status.splitlines() if line.startswith("VmRSS:"))
    rss_bytes = int(rss_line.split()[1]) * 1024
    descriptors = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
    return rss_bytes, descriptors


def routed_envelope(
    template: bytes,
    workspace_id: bytes,
    sender_id: bytes,
    recipient_id: bytes,
    sequence: int,
) -> bytes:
    frame = bytearray(template)
    header = 4
    frame[header + 8:header + 24] = workspace_id
    frame[header + 24:header + 40] = sender_id
    frame[header + 40:header + 56] = recipient_id
    frame[header + 56:header + 88] = hashlib.sha256(sender_id).digest()
    frame[header + 88:header + 120] = hashlib.sha256(recipient_id).digest()
    frame[header + 120:header + 136] = secrets.token_bytes(16)
    struct.pack_into(">Q", frame, header + 136, sequence)
    now = int(time.time() * 1000)
    struct.pack_into(">Q", frame, header + 144, now)
    struct.pack_into(">Q", frame, header + 152, now + 60_000)
    return bytes(frame)


def main() -> None:
    args = parse_args()
    server_binary = args.server.resolve()
    admin_binary = args.admin.resolve()
    if not server_binary.is_file() or not admin_binary.is_file():
        raise RuntimeError("built Server and admin binaries are required")
    vector = json.loads(
        (Path(__file__).resolve().parents[1] /
         "protocol/test-vectors/encrypted-envelope-v1.json").read_text(encoding="utf-8")
    )
    template = bytes.fromhex(vector["frameHex"])

    with tempfile.TemporaryDirectory(prefix="sevenmirror-relay-capacity-") as temporary:
        root = Path(temporary)
        database = root / "registry.sqlite"
        stdout_path = root / "server.stdout.log"
        stderr_path = root / "server.stderr.log"
        env = os.environ.copy()
        env.update({
            "NM_ADDRESS": f"127.0.0.1:{free_loopback_port()}",
            "NM_DATABASE_PATH": str(database),
            "NM_AUTHORITY_KEY_DIR": str(root / "authority-keys"),
            "NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE": "10000",
            "NM_RELAY_AUTH_MAX_CLIENT_BUCKETS": "16",
            "NM_RELAY_AUTH_MAX_CONCURRENT": "64",
        })
        workspace_text = field(run_admin(admin_binary, env, "init-workspace"), "workspace_id")
        workspace_id = decode_base64url(workspace_text)
        devices = seed_approved_devices(database, workspace_id, STORM_CLIENTS)
        process = subprocess.Popen(
            [str(server_binary)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout_path.open("wb"),
            stderr=stderr_path.open("wb"),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            origin = f"http://{env['NM_ADDRESS']}"
            wait_until_ready(origin, process)
            baseline_rss, baseline_descriptors = process_usage(process)
            authenticated = 0
            peak_rss = baseline_rss
            peak_descriptors = baseline_descriptors
            for _wave in range(STORM_WAVES):
                with ThreadPoolExecutor(max_workers=STORM_CLIENTS) as executor:
                    connections = list(executor.map(
                        lambda device: authenticate(origin, workspace_id, device),
                        devices,
                    ))
                authenticated += len(connections)
                rss, descriptors = process_usage(process)
                peak_rss = max(peak_rss, rss)
                peak_descriptors = max(peak_descriptors, descriptors)
                for connection in connections:
                    connection.close()
                time.sleep(0.25)
            if authenticated != STORM_CLIENTS * STORM_WAVES:
                raise RuntimeError("Reconnect wave authentication success rate was not 100%")

            with ThreadPoolExecutor(max_workers=STORM_CLIENTS) as executor:
                live = list(executor.map(
                    lambda device: authenticate(origin, workspace_id, device),
                    devices,
                ))
            rss, descriptors = process_usage(process)
            peak_rss = max(peak_rss, rss)
            peak_descriptors = max(peak_descriptors, descriptors)
            started = time.monotonic()
            delivered = 0
            for pair in range(ROUTING_PAIRS):
                sender = live[pair * 2]
                recipient = live[pair * 2 + 1]
                sender_id = devices[pair * 2][0]
                recipient_id = devices[pair * 2 + 1][0]
                for sequence in range(1, FRAMES_PER_PAIR + 1):
                    envelope = routed_envelope(
                        template, workspace_id, sender_id, recipient_id, sequence)
                    send_masked_binary(sender, envelope)
                    result = read_websocket_result(recipient)
                    if result != ("binary", envelope):
                        raise RuntimeError("Relay did not deliver the exact online ciphertext")
                    delivered += 1
                rss, descriptors = process_usage(process)
                peak_rss = max(peak_rss, rss)
                peak_descriptors = max(peak_descriptors, descriptors)
            elapsed = time.monotonic() - started
            for connection in live:
                connection.close()
            cleanup_deadline = time.monotonic() + 5
            while True:
                final_rss, final_descriptors = process_usage(process)
                if final_descriptors - baseline_descriptors <= MAX_FINAL_DESCRIPTOR_GROWTH or \
                        time.monotonic() >= cleanup_deadline:
                    break
                time.sleep(0.1)

            if delivered != ROUTING_PAIRS * FRAMES_PER_PAIR:
                raise RuntimeError("Sustained relay delivery count did not converge")
            rate = delivered / elapsed
            if rate < MINIMUM_FRAMES_PER_SECOND:
                raise RuntimeError(f"Sustained relay rate {rate:.1f} frames/s is below baseline")
            if peak_rss - baseline_rss > MAX_RSS_GROWTH_BYTES:
                raise RuntimeError("Server RSS growth exceeded the capacity baseline")
            if final_descriptors - baseline_descriptors > MAX_FINAL_DESCRIPTOR_GROWTH:
                raise RuntimeError(
                    "Server descriptor/handle count did not return to baseline: "
                    f"baseline={baseline_descriptors} peak={peak_descriptors} final={final_descriptors}")

            print(json.dumps({
                "result": "passed",
                "authenticated_connections": authenticated + STORM_CLIENTS,
                "authentication_failures": 0,
                "delivered_online_frames": delivered,
                "minimum_frames_per_second": MINIMUM_FRAMES_PER_SECOND,
                "observed_frames_per_second": round(rate, 1),
                "baseline_rss_bytes": baseline_rss,
                "peak_rss_bytes": peak_rss,
                "final_rss_bytes": final_rss,
                "baseline_descriptors_or_handles": baseline_descriptors,
                "peak_descriptors_or_handles": peak_descriptors,
                "final_descriptors_or_handles": final_descriptors,
            }, sort_keys=True))
        finally:
            stop_server(process)


if __name__ == "__main__":
    main()

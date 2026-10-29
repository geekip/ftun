#!/usr/bin/env python3
"""Verify that the Proxy-free product composition serves DNS and stops cleanly."""

import json
from pathlib import Path
import signal
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def fail(message: str) -> None:
    raise SystemExit(f"dns-only product: {message}")


def reserve_udp_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        return [int(sock.getsockname()[1]) for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def question_end(packet: bytes) -> int:
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        offset += length
    if offset + 4 > len(packet):
        fail("received malformed upstream question")
    return offset + 4


def upstream_server(port: int, address: str, requests: int,
                    ready: threading.Event, done: threading.Event,
                    block_request: int = 0,
                    blocked: threading.Event | None = None,
                    release: threading.Event | None = None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", port))
        sock.settimeout(5.0)
        ready.set()
        try:
            for _ in range(requests):
                query, peer = sock.recvfrom(4096)
                if block_request == _ + 1:
                    assert blocked is not None and release is not None
                    blocked.set()
                    if not release.wait(5.0):
                        fail("blocked upstream request was not released")
                end = question_end(query)
                header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                answer = b"\xc0\x0c" + struct.pack(
                    "!HHIH4s", 1, 1, 60, 4, socket.inet_aton(address)
                )
                sock.sendto(header + query[12:end] + answer, peer)
        finally:
            done.set()


def dns_query(port: int) -> bytes:
    query_id = 0x5A12
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    deadline = time.monotonic() + 5.0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.2)
        while time.monotonic() < deadline:
            sock.sendto(packet, ("127.0.0.1", port))
            try:
                response, _ = sock.recvfrom(4096)
                if len(response) >= 12 and response[:2] == packet[:2]:
                    return response
            except TimeoutError:
                continue
    fail("listener did not return the upstream DNS response")


def dns_query_once(port: int, result: list[bytes | BaseException]) -> None:
    query_id = 0x5A13
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5.0)
            sock.sendto(packet, ("127.0.0.1", port))
            response, _ = sock.recvfrom(4096)
            result.append(response)
    except BaseException as error:
        result.append(error)


def wait_for_stderr(process: subprocess.Popen[str], needle: str) -> str:
    deadline = time.monotonic() + 5.0
    assert process.stderr is not None
    while time.monotonic() < deadline:
        readable, _, _ = select.select([process.stderr], [], [], 0.2)
        if not readable:
            if process.poll() is not None:
                fail(f"run exited while waiting for {needle!r}")
            continue
        line = process.stderr.readline()
        if needle in line:
            return line
    fail(f"run did not report {needle!r}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("ftun executable path is required")
    executable = Path(sys.argv[1]).resolve()
    if not executable.is_file():
        fail(f"missing executable: {executable}")
    upstream_port, replacement_port, listener_port = reserve_udp_ports(3)
    ready = threading.Event()
    done = threading.Event()
    old_request_blocked = threading.Event()
    release_old_request = threading.Event()
    replacement_ready = threading.Event()
    replacement_done = threading.Event()
    thread = threading.Thread(
        target=upstream_server,
        args=(upstream_port, "203.0.113.7", 2, ready, done, 2,
              old_request_blocked, release_old_request),
        daemon=True,
    )
    replacement_thread = threading.Thread(
        target=upstream_server,
        args=(replacement_port, "203.0.113.8", 2,
              replacement_ready, replacement_done),
        daemon=True,
    )
    thread.start()
    replacement_thread.start()
    if not ready.wait(2.0) or not replacement_ready.wait(2.0):
        fail("upstream fixture did not start")
    with tempfile.TemporaryDirectory(prefix="ftun-dns-only-") as directory:
        config_path = Path(directory) / "dns-only.json"
        config = {
                    "base": {"state-cache": False},
                    "log": {"level": "error", "file": str(Path(directory) / "ftun.log")},
                    "dns": {
                        "enable": True,
                        "cache": False,
                        "fake-ip": {"enable": False},
                        "default-server": "direct",
                        "listeners": [
                            {
                                "listen": f"127.0.0.1:{listener_port}",
                                "server": "direct",
                            }
                        ],
                        "servers": [
                            {
                                "name": "direct",
                                "type": "udp",
                                "address": [f"127.0.0.1:{upstream_port}"],
                                "outbound": "DIRECT",
                            }
                        ],
                    },
                }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        checked = subprocess.run(
            [str(executable), "check", str(config_path)],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if checked.returncode != 0:
            fail(f"configuration check failed: {checked.stderr.strip()}")
        process = subprocess.Popen(
            [str(executable), "run", str(config_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            response = dns_query(listener_port)
            if socket.inet_aton("203.0.113.7") not in response:
                fail("listener response did not contain the fixture address")
            old_result: list[bytes | BaseException] = []
            old_thread = threading.Thread(
                target=dns_query_once,
                args=(listener_port, old_result),
                daemon=True,
            )
            old_thread.start()
            if not old_request_blocked.wait(2.0):
                fail("in-flight request did not reach the original upstream")
            config["dns"]["servers"][0]["address"] = [
                f"127.0.0.1:{replacement_port}"
            ]
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process.send_signal(signal.SIGHUP)
            wait_for_stderr(process, "reload committed")
            release_old_request.set()
            old_thread.join(timeout=5.0)
            if len(old_result) != 1 or isinstance(old_result[0], BaseException):
                fail(f"retired DNS generation did not drain: {old_result!r}")
            if socket.inet_aton("203.0.113.7") not in old_result[0]:
                fail("in-flight request was not completed by the retired generation")
            if not done.wait(2.0):
                fail("original upstream did not finish both requests")
            response = dns_query(listener_port)
            if socket.inet_aton("203.0.113.8") not in response:
                fail("committed reload did not switch to the replacement upstream")
            config["dns"]["enable"] = False
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process.send_signal(signal.SIGHUP)
            rejected = wait_for_stderr(process, "reload rejected")
            if "restart-required" not in rejected:
                fail(f"root-service reload returned the wrong status: {rejected.strip()}")
            response = dns_query(listener_port)
            if socket.inet_aton("203.0.113.8") not in response:
                fail("rejected root-service reload did not preserve the active DNS generation")
            if not replacement_done.wait(2.0):
                fail("replacement upstream did not receive both post-reload requests")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            if process.returncode != 0:
                fail(
                    f"run exited with {process.returncode}: "
                    f"stdout={stdout.strip()} stderr={stderr.strip()}"
                )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    thread.join(timeout=1.0)
    replacement_thread.join(timeout=1.0)
    print("dns-only product: ok")


if __name__ == "__main__":
    main()

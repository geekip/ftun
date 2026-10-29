#!/usr/bin/env python3
"""Verify inbound handshake, preread and reload through the production listener."""
import argparse
import contextlib
import json
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time


def receive(client, length):
    data = b""
    while len(data) < length:
        part = client.recv(length - len(data))
        assert part, f"unexpected EOF after {len(data)}/{length} bytes"
        data += part
    return data


def headers(client):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += receive(client, 1)
        assert len(data) < 4096
    return data


def echo(listener, stopped, failures):
    clients = []
    try:
        while not stopped.is_set():
            ready, _, _ = select.select([listener, *clients], [], [], 0.05)
            for sock in ready:
                if sock is listener:
                    client, _ = listener.accept()
                    client.settimeout(3)
                    clients.append(client)
                else:
                    try:
                        data = sock.recv(65536)
                        if data:
                            sock.sendall(data)
                            continue
                    except (ConnectionError, TimeoutError):
                        pass
                    clients.remove(sock)
                    sock.close()
    except Exception as error:
        failures.append(error)
    finally:
        for client in clients:
            client.close()


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    payload = bytes(range(256)) * 257
    with tempfile.TemporaryDirectory(prefix="ftun-inbound-") as directory, contextlib.ExitStack() as stack:
        root = Path(directory)
        reservations = [stack.enter_context(socket.socket()) for _ in range(5)]
        for sock in reservations:
            sock.bind(("127.0.0.1", 0))
        plain, auth, mixed, rejected, target = [s.getsockname()[1] for s in reservations]
        listener = reservations[-1]
        listener.listen()
        stopped = threading.Event()
        failures = []
        thread = threading.Thread(target=echo, args=(listener, stopped, failures))
        thread.start()
        config = {"base": {"state-cache": False}, "dns": {"enable": False},
                  "log": {"level": "info"},
                  "inbounds": [
                      {"name": "plain", "type": "socks5", "listen": f"127.0.0.1:{plain}", "udp": True},
                      {"name": "auth", "type": "socks5", "listen": f"127.0.0.1:{auth}", "users": {"u": "p"}},
                      {"name": "mixed", "type": "mixed", "listen": f"127.0.0.1:{mixed}"},
                      {"name": "deny", "type": "mixed", "listen": f"127.0.0.1:{rejected}", "outbound": "REJECT"}],
                  "rules": ["MATCH,DIRECT"]}
        path = root / "config.json"
        path.write_text(json.dumps(config))
        log = stack.enter_context((root / "run.log").open("w+"))
        for sock in reservations[:-1]:
            sock.close()
        process = None
        clients = []
        try:
            process = subprocess.Popen([str(args.binary.resolve()), "run", "-c", str(path)], stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "daemon exited during startup"
                try:
                    with connect(plain):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "listener startup timeout"
                    time.sleep(0.01)
            command = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target)
            # 方法、认证、命令及大载荷合并发送，旧连接在 reload 后继续转发。
            for port, handshake, replies in [
                (plain, b"\x05\x01\x00", b"\x05\x00"),
                (auth, b"\x05\x01\x02\x01\x01u\x01p", b"\x05\x02\x01\x00"),
                (mixed, b"\x05\x01\x00", b"\x05\x00")]:
                client = connect(port)
                clients.append(client)
                client.sendall(handshake + command + payload)
                assert receive(client, len(replies)) == replies
                assert receive(client, 10)[:4] == b"\x05\x00\x00\x01"
                assert receive(client, len(payload)) == payload
            with connect(auth) as client:
                for byte in b"\x05\x01\x02":
                    client.sendall(bytes([byte]))
                assert receive(client, 2) == b"\x05\x02"
                for byte in b"\x01\x01u\x01x":
                    client.sendall(bytes([byte]))
                assert receive(client, 2) == b"\x01\x01"
                assert client.recv(1) == b""
            with connect(mixed) as client:
                client.sendall(f"CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n".encode() + payload)
                assert headers(client).startswith(b"HTTP/1.1 200 ")
                assert receive(client, len(payload)) == payload
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1) == b""
            with connect(mixed) as client:
                authority = f"127.0.0.1:{target}"
                tail = f" HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 3\r\n\r\nabcTAIL".encode()
                client.sendall(f"POST http://{authority}/x".encode() + tail)
                expected = b"POST /x" + tail
                assert receive(client, len(expected)) == expected
            with connect(rejected) as client:
                client.sendall(f"CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n".encode())
                assert headers(client).startswith(b"HTTP/1.1 403 ")
                assert client.recv(1) == b""
            with socket.socket() as unavailable:
                unavailable.bind(("127.0.0.1", 0))
                refused = unavailable.getsockname()[1]
                with connect(mixed) as client:
                    client.sendall(f"CONNECT 127.0.0.1:{refused} HTTP/1.1\r\nHost: 127.0.0.1:{refused}\r\n\r\n".encode())
                    response = headers(client)
                    assert response.startswith(b"HTTP/1.1 403 "), response
                    assert client.recv(1) == b""
            config["inbounds"][1]["users"] = {"u": "q"}
            path.write_text(json.dumps(config))
            process.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 5
            while True:
                with connect(auth) as client:
                    client.sendall(b"\x05\x01\x02\x01\x01u\x01q" + command)
                    assert receive(client, 2) == b"\x05\x02"
                    if receive(client, 2) == b"\x01\x00":
                        assert receive(client, 10)[:2] == b"\x05\x00"
                        break
                assert time.monotonic() < deadline, "reload did not apply new credentials"
                time.sleep(0.01)
            for client in clients:
                client.sendall(payload)
                assert receive(client, len(payload)) == payload
            # 同时保留部分握手和已建立连接，验证真实停止能够清理。
            for port in (plain, auth, mixed):
                client = connect(port)
                clients.append(client)
                client.sendall(b"\x05")
            process.terminate()
            assert process.wait(timeout=5) == 0
            assert not failures, failures
            print("production inbound adapter passed: coalesced/fragmented auth, preread, replies, half-close, reload and stop")
        except Exception:
            log.flush()
            print((root / "run.log").read_text())
            raise
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for client in clients:
                client.close()
            stopped.set()
            thread.join(timeout=5)
            assert not thread.is_alive(), "echo fixture failed to stop"


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Exercise CLI reload results against real sinks and live data traffic."""
import argparse
import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tty


# 插桩构建（TSan）整体更慢：停止期限类断言允许额外的余量，普通构建为 0。
SLACK = float(os.environ.get("FTUN_TEST_SLACK_SECONDS", "0"))

def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        assert part, "unexpected EOF"
        data += part
    return data


def reserve_dns_sockets():
    # 产品同时绑定UDP/TCP；在交给子进程前保留两种协议的端口。
    for _ in range(100):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            udp.bind(("127.0.0.1", 0))
            tcp.bind(udp.getsockname())
            return udp, tcp
        except OSError as error:
            udp.close()
            tcp.close()
            if error.errno != errno.EADDRINUSE:
                raise
    raise AssertionError("could not reserve a shared UDP/TCP listener port")


def port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def dns_query(listener, ident):
    wire = struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0)
    wire += b"\x03cli\x07example\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.25)
        sock.sendto(wire, ("127.0.0.1", listener))
        response, _ = sock.recvfrom(4096)
    assert response[:2] == wire[:2] and response[-4:] == b"\xcb\x00\x71\x07"


def fixture(udp, tcp, stopped):
    clients = []
    try:
        while not stopped.is_set():
            ready, _, _ = select.select([udp, tcp, *clients], [], [], 0.05)
            for sock in ready:
                if sock is udp:
                    wire, peer = udp.recvfrom(4096)
                    response = wire[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                    response += wire[12:] + b"\xc0\x0c" + struct.pack(
                        "!HHIH4s", 1, 1, 60, 4, b"\xcb\x00\x71\x07")
                    udp.sendto(response, peer)
                elif sock is tcp:
                    client, _ = tcp.accept()
                    clients.append(client)
                else:
                    data = sock.recv(4096)
                    if data:
                        sock.sendall(data)
                    else:
                        clients.remove(sock)
                        sock.close()
    finally:
        for client in clients:
            client.close()


def check_progress(listener, stream, ident):
    dns_query(listener, ident)
    if stream is not None:
        payload = b"cli-progress-" + struct.pack("!I", ident)
        stream.sendall(payload)
        assert receive(stream, len(payload)) == payload


def run_case(binary, directory, kind, proxy, upstream, echo_port):
    with contextlib.ExitStack() as leases:
        reservations = list(reserve_dns_sockets())
        for sock in reservations:
            leases.enter_context(sock)
        sock = leases.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.bind(("127.0.0.1", 0))
        reservations.append(sock)
        run_reserved_case(binary, directory, kind, proxy, upstream, echo_port, reservations)


def run_reserved_case(binary, directory, kind, proxy, upstream, echo_port, reservations):
    listener = reservations[0].getsockname()[1]
    proxy_port = reservations[2].getsockname()[1]
    config = {"base": {"state-cache": False},
              "log": {"level": "warn" if kind == "file" else "silent",
                      "file": str(directory / f"{kind}.log")},
              "dns": {"enable": True, "cache": False,
                      "fake-ip": {"enable": False},
                      "default-server": "direct",
                      "servers": [{"name": "direct", "type": "udp",
                                   "address": [f"127.0.0.1:{upstream}"],
                                   "outbound": "DIRECT"}],
                      "listeners": [{"listen": f"127.0.0.1:{listener}",
                                     "server": "direct"}]}}
    if proxy:
        config["inbounds"] = [{"name": "cli", "type": "socks5",
                               "listen": f"127.0.0.1:{proxy_port}", "udp": False}]
        config["rules"] = ["MATCH,DIRECT"]
    path = directory / f"{kind}.json"
    path.write_text(json.dumps(config))
    checked = subprocess.run([str(binary), "check", "-c", str(path)],
                             capture_output=True, timeout=5)
    assert checked.returncode == 0, checked.stderr.decode(errors="replace")
    reader = writer = None
    pair = []
    if kind in ("pipe", "blocked", "recovered", "broken"):
        reader, writer = os.pipe()
        if kind in ("blocked", "recovered"):
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b"x" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(writer, True)
        if kind == "broken":
            os.close(reader)
            reader = None
    elif kind == "socket":
        pair = list(socket.socketpair())
        reader, writer = [sock.fileno() for sock in pair]
    elif kind == "pty":
        reader, writer = pty.openpty()
        tty.setraw(writer)
    else:
        writer = os.open(directory / "stderr", os.O_CREAT | os.O_RDWR, 0o600)
        os.write(writer, b"prefix\n")
    flags = fcntl.fcntl(writer, fcntl.F_GETFL)
    for sock in reservations:
        sock.close()
    process = subprocess.Popen([str(binary), "run", "-c", str(path)],
                               stdout=subprocess.DEVNULL, stderr=writer)
    stream = None
    captured = b""
    try:
        deadline = time.monotonic() + 5
        while True:
            assert process.poll() is None, f"{kind}: premature exit {process.returncode}"
            try:
                dns_query(listener, 1)
                break
            except TimeoutError:
                assert time.monotonic() < deadline, f"{kind}: DNS not ready"
        if proxy:
            stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=1)
            stream.sendall(b"\x05\x01\x00")
            assert receive(stream, 2) == b"\x05\x00"
            stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                           struct.pack("!H", echo_port))
            assert receive(stream, 10)[:2] == b"\x05\x00"
        rounds = 48 if kind in ("blocked", "recovered") else 1
        for index in range(rounds):
            process.send_signal(signal.SIGHUP)
            time.sleep(0.025)
            check_progress(listener, stream, index + 2)
        if kind not in ("blocked", "broken"):
            deadline = time.monotonic() + 5
            while b"ftun: reload committed\n" not in captured:
                assert process.poll() is None
                assert time.monotonic() < deadline, f"{kind}: missing result {captured!r}"
                if kind == "file":
                    captured = os.pread(writer, 8192, 0)
                    time.sleep(0.01)
                elif select.select([reader], [], [], 0.1)[0]:
                    captured += os.read(reader, 8192)
            if kind == "file":
                assert captured.startswith(b"prefix\n")
        if kind == "recovered":
            deadline = time.monotonic() + 5
            while b"rejected: limit" not in captured:
                assert time.monotonic() < deadline, "full queue was not reported"
                if select.select([reader], [], [], 0.1)[0]:
                    captured += os.read(reader, 8192)
        if kind == "pipe":
            path.write_text("{invalid configuration")
            process.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 5
            while b"ftun: reload rejected at stage " not in captured:
                assert process.poll() is None
                assert time.monotonic() < deadline, "missing rejected result"
                if select.select([reader], [], [], 0.1)[0]:
                    captured += os.read(reader, 8192)
            path.write_text(json.dumps(config))
        check_progress(listener, stream, 1000)
        if stream is not None:
            stream.close()
            stream = None
        start = time.monotonic()
        process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=12 + SLACK)
        elapsed = time.monotonic() - start
        assert code == 0, f"{kind}: exit {code}"
        assert elapsed < (11 if kind == "blocked" else 2) + SLACK, (kind, elapsed)
        assert fcntl.fcntl(writer, fcntl.F_GETFL) == flags
        print(json.dumps({"sink": kind, "proxy": proxy, "reload_signals": rounds,
                          "dns_responses": rounds + 2,
                          "tcp_exchanges": rounds + 1 if proxy else 0,
                          "exit": code, "stop_seconds": elapsed}), flush=True)
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        # 先停止writer再读取，保留首个失败的诊断且不改变测试判定。
        if kind == "file":
            captured = os.pread(writer, 16384, 0)
        elif reader is not None:
            while len(captured) < 16384 and select.select([reader], [], [], 0)[0]:
                try:
                    data = os.read(reader, 16384 - len(captured))
                except OSError:
                    break
                if not data:
                    break
                captured += data
        print(json.dumps({"sink": kind, "exit": process.returncode,
                          "dns_port": listener, "proxy_port": proxy_port,
                          "stderr": captured.decode(errors="replace")}), file=sys.stderr, flush=True)
        raise
    finally:
        if stream is not None:
            stream.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        if pair:
            for sock in pair:
                sock.close()
        else:
            if reader is not None:
                os.close(reader)
            os.close(writer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--proxy", action="store_true")
    args = parser.parse_args()
    stopped = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
            tempfile.TemporaryDirectory(prefix="ftun-cli-results-") as directory:
        udp.bind(("127.0.0.1", 0))
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(8)
        thread = threading.Thread(target=fixture, args=(udp, tcp, stopped))
        thread.start()
        try:
            for kind in ("pipe", "file", "pty", "socket", "broken",
                         "recovered", "blocked"):
                run_case(args.binary.resolve(), Path(directory), kind, args.proxy,
                         udp.getsockname()[1], tcp.getsockname()[1])
        finally:
            stopped.set()
            thread.join(timeout=2)
            assert not thread.is_alive()


if __name__ == "__main__":
    main()

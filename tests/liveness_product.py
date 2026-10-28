#!/usr/bin/env python3
"""存活探测与空闲回收：真实进程上，接入与拨出的 TCP 连接都带 keepalive，空闲连接按入站配置回收。"""
import json
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def free_port():
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        return reserve.getsockname()[1]


def wait_for(process, predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert process.poll() is None, f'ftun exited early: {process.returncode}'
        assert time.monotonic() < deadline, 'condition deadline expired'
        time.sleep(0.02)


def socks_connect(proxy_port, target_port):
    client = socket.create_connection(('127.0.0.1', proxy_port))
    client.sendall(b'\x05\x01\x00')
    assert client.recv(2) == b'\x05\x00'
    client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('>H', target_port))
    reply = client.recv(10)
    assert len(reply) == 10 and reply[1] == 0, reply
    return client


def keepalive_sockets(local_port=None, remote_port=None):
    """返回 ss 报告带 keepalive 定时器的 ESTAB 连接数。"""
    output = subprocess.run(['ss', '-tno', 'state', 'established'], capture_output=True,
                            text=True, check=True).stdout
    count = 0
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or 'timer:(keepalive' not in line:
            continue
        local, remote = fields[2], fields[3]
        if local_port is not None and not local.endswith(f':{local_port}'):
            continue
        if remote_port is not None and not remote.endswith(f':{remote_port}'):
            continue
        count += 1
    return count


def closed(client):
    """对端是否已关闭连接（EOF 或复位）。"""
    client.setblocking(False)
    try:
        return client.recv(1) == b''
    except BlockingIOError:
        return False
    except ConnectionError:
        return True
    finally:
        client.setblocking(True)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    sink = socket.socket()
    sink.bind(('127.0.0.1', 0))
    sink.listen(8)
    sink_port = sink.getsockname()[1]
    held = []
    threading.Thread(target=lambda: [held.append(sink.accept()[0]) for _ in range(4)],
                     daemon=True).start()
    short_port, long_port = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix='ftun-liveness-') as directory:
        root = Path(directory)
        log_path = root / 'ftun.log'
        config = {
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache'),
                     'timeouts': {'tcp-keepalive': {'idle': '7s', 'interval': '3s', 'count': 2},
                                  'write-progress': '20s', 'tcp-idle': '3s'}},
            'dns': {'enable': False},
            'log': {'level': 'warn', 'file': str(log_path)},
            'inbounds': [
                {'name': 'short', 'type': 'socks5', 'listen': f'127.0.0.1:{short_port}'},
                {'name': 'long', 'type': 'socks5', 'listen': f'127.0.0.1:{long_port}',
                 'tcp-idle': '1h'}],
            'rules': ['MATCH,DIRECT'],
        }
        config_path = root / 'config.json'
        config_path.write_text(json.dumps(config))
        process = subprocess.Popen([binary, 'run', '-c', str(config_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(process, lambda: subprocess.run(
                ['ss', '-ltn', f'sport = :{short_port}'], capture_output=True,
                text=True).stdout.count(f':{short_port}') > 0)
            first = socks_connect(short_port, sink_port)
            second = socks_connect(long_port, sink_port)
            # 先发一个字节让嗅探阶段结束、进入转发；此后没有任何流量。
            first.sendall(b'x')
            second.sendall(b'x')
            time.sleep(0.5)
            started = time.monotonic()
            # 接入侧（本地端口是入站端口）和拨出侧（对端端口是 sink）都有 keepalive 定时器。
            # 刚写出的回复还没被对端确认时内核显示的是重传定时器，等确认后才显示 keepalive。
            wait_for(process, lambda: keepalive_sockets(local_port=short_port) == 1 and
                     keepalive_sockets(local_port=long_port) == 1 and
                     keepalive_sockets(remote_port=sink_port) == 2, seconds=3)
            # 默认回收 3s：短入站的空闲连接被关闭，覆盖为 1h 的长入站保持。
            wait_for(process, lambda: closed(first), seconds=10)
            elapsed = time.monotonic() - started
            assert 2.0 <= elapsed <= 8.0, elapsed
            assert not closed(second)
            # 被回收的连接，其拨出侧也一并关闭。
            assert keepalive_sockets(remote_port=sink_port) == 1
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    print('PASS liveness: keepalive on accepted and dialed sockets, idle reclaim with inbound override')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""FRS 无网络启动：本地规则文件存在时直接使用（不等待、不因下载失败而退出）；
文件缺失时以 NOT_READY 启动，命中 FRS 规则的新连接被拒绝，下载失败不让服务退出。"""
import json
from pathlib import Path
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


def socks_connect(proxy_port, address, target_port):
    """返回 SOCKS5 回复码；0 表示已连通。"""
    client = socket.create_connection(('127.0.0.1', proxy_port), timeout=5)
    try:
        client.sendall(b'\x05\x01\x00')
        assert client.recv(2) == b'\x05\x00'
        client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address) + struct.pack('>H', target_port))
        reply = client.recv(10)
        assert len(reply) >= 2, reply
        return reply[1]
    finally:
        client.close()


def run_case(binary, fixture, with_file):
    sink = socket.socket()
    sink.bind(('127.0.0.1', 0))
    sink.listen(8)
    sink_port = sink.getsockname()[1]
    stop = threading.Event()

    def accept():
        sink.settimeout(0.2)
        while not stop.is_set():
            try:
                sink.accept()[0].close()
            except (TimeoutError, OSError):
                continue
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    port = free_port()
    with tempfile.TemporaryDirectory(prefix='ftun-frs-offline-') as directory:
        root = Path(directory)
        rules = root / 'rules.frs'
        if with_file:
            subprocess.run([fixture, '--write', str(rules)], check=True)
        before = rules.read_bytes() if with_file else None
        config = {
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache')},
            'dns': {'enable': False},
            'log': {'level': 'info', 'file': str(root / 'ftun.log')},
            # 下载地址不可达（连接被拒绝）：没有网络时服务必须照常运行。
            'frs': {'path': str(rules), 'url': 'http://127.0.0.1:9/rules.frs',
                    'auto-update': True, 'update-interval': '1s'},
            'inbounds': [{'name': 'in', 'type': 'socks5', 'listen': f'127.0.0.1:{port}'}],
            'rules': ['frs-ip,CN,REJECT', 'MATCH,DIRECT'],
        }
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([binary, 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    socket.create_connection(('127.0.0.1', port), timeout=1).close()
                    break
                except OSError:
                    assert process.poll() is None, f'ftun exited early: {process.returncode}'
                    assert time.monotonic() < deadline
                    time.sleep(0.02)
            # 让后台下载至少失败并按退避重试两轮。
            time.sleep(3.5)
            assert process.poll() is None, f'download failure stopped the service: {process.returncode}'
            local = socks_connect(port, '127.0.0.1', sink_port)
            listed = socks_connect(port, '10.1.2.3', 80)
            log = (root / 'ftun.log').read_text()
            if with_file:
                # 本地文件立即生效：CN 集合内的地址被规则拒绝，其余直连成功。
                assert local == 0, local
                assert listed != 0, listed
                assert 'NOT_READY' not in log, log
                assert rules.read_bytes() == before
            else:
                # NOT_READY：第一条 FRS 规则对任何目标都拒绝新连接，下载失败不留下文件。
                assert local != 0, local
                assert listed != 0, listed
                assert 'starting NOT_READY' in log and 'frs-not-ready' in log, log
                assert not rules.exists()
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            stop.set()
            thread.join()
            sink.close()


def main(binary, fixture):
    run_case(binary, fixture, True)
    run_case(binary, fixture, False)
    print('FRS offline product: local file used offline; missing file starts NOT_READY and survives download failure')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

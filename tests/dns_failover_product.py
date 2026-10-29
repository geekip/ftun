#!/usr/bin/env python3
"""DNS 多上游地址的被动健康：真实进程，首选地址静默时查询自动换到备用地址，
之后的查询直接使用备用地址而不再等待首选地址超时。"""
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def free_ports():
    """挑出三个互不相同的端口。监听端口要 UDP 与 TCP 都空闲（DNS 监听两者都绑），
    另外两个只用 UDP。先把全部预留住再一起释放，避免挑到同一个端口。"""
    held = []
    try:
        listener = None
        while listener is None:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0))
            held.append(udp)
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(tcp)
            try:
                tcp.bind(('127.0.0.1', udp.getsockname()[1]))
                listener = udp.getsockname()[1]
            except OSError:
                continue
        others = []
        for _ in range(2):
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0))
            held.append(udp)
            others.append(udp.getsockname()[1])
        return others[0], others[1], listener
    finally:
        for reserve in held:
            reserve.close()


def responder(sock, address, stop):
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            query, peer = sock.recvfrom(4096)
        except TimeoutError:
            continue
        offset = 12
        while query[offset] != 0:
            offset += query[offset] + 1
        end = offset + 5
        header = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
        answer = b'\xc0\x0c' + struct.pack('!HHIH4s', 1, 1, 60, 4, socket.inet_aton(address))
        sock.sendto(header + query[12:end] + answer, peer)


def ask(port, ident):
    packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + \
        b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(15.0)
        started = time.monotonic()
        sock.sendto(packet, ('127.0.0.1', port))
        response, _ = sock.recvfrom(4096)
        return response, time.monotonic() - started


def main(binary):
    dead_port, live_port, listener_port = free_ports()
    # 首选地址：绑定但从不应答（静默丢包）；备用地址：正常应答。
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(('127.0.0.1', dead_port))
    live = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    live.bind(('127.0.0.1', live_port))
    stop = threading.Event()
    thread = threading.Thread(target=responder, args=(live, '203.0.113.9', stop), daemon=True)
    thread.start()
    with tempfile.TemporaryDirectory(prefix='ftun-dns-failover-') as directory:
        root = Path(directory)
        config = {
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache')},
            'log': {'level': 'error', 'file': str(root / 'ftun.log')},
            'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                    'default-server': 'multi',
                    'listeners': [{'listen': f'127.0.0.1:{listener_port}', 'server': 'multi'}],
                    'servers': [{'name': 'multi', 'type': 'udp', 'outbound': 'DIRECT',
                                 'address': [f'127.0.0.1:{dead_port}', f'127.0.0.1:{live_port}']}]},
        }
        config_path = root / 'config.json'
        config_path.write_text(json.dumps(config))
        process = subprocess.Popen([binary, 'run', '-c', str(config_path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.5)
            assert process.poll() is None, f'ftun exited early: {process.returncode}'
            # 第一次：先等首选地址的缩短期限（剩余期限的一半），再换到备用地址并得到应答。
            response, first = ask(listener_port, 0x1111)
            assert socket.inet_aton('203.0.113.9') in response, response
            assert first >= 1.0, f'first query did not wait for the silent address: {first:.2f}s'
            # 之后首选地址在退避中：直接用备用地址，不再等待首选地址超时。
            response, second = ask(listener_port, 0x2222)
            assert socket.inet_aton('203.0.113.9') in response, response
            assert second < 0.5, f'second query still waited for the silent address: {second:.2f}s'
        finally:
            process.terminate()
            process.wait(timeout=15)
            stop.set()
            thread.join()
            silent.close()
            live.close()
    print(f'DNS failover product: first={first:.2f}s second={second:.2f}s passed')


if __name__ == '__main__':
    main(sys.argv[1])

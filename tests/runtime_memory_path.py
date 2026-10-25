#!/usr/bin/env python3
"""Drive the production listener through a Path factory with no outbound sockets."""
import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time

from inbound_adapter_product import receive, headers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--socks5', choices=['noauth', 'auth'])
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ftun-memory-path-') as directory:
        root = Path(directory)
        with socket.socket() as reserved, socket.socket() as unavailable:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
            unavailable.bind(('0.0.0.0', 0))
            target = unavailable.getsockname()[1]
            # 目标只 bind 不 listen；任何绕过工厂的 native connect 必然拒绝。
            config = {'base': {'state-cache': False}, 'dns': {'enable': False},
                      'log': {'level': 'silent'}, 'rules': ['MATCH,DIRECT'],
                      'inbounds': [{'name': 'mixed', 'type': 'mixed', 'listen': f'127.0.0.1:{port}'}]}
            if args.socks5:
                config['outbounds'] = [{'name': 'proxy', 'type': 'socks5', 'server': f'127.0.0.1:{target}'}]
                if args.socks5 == 'auth':
                    config['outbounds'][0].update(username='user', password='pass')
                config['rules'] = ['MATCH,proxy']
            path = root / 'config.json'
            path.write_text(json.dumps(config))
            reserved.close()
            with (root / 'run.log').open('w+') as log:
                process = subprocess.Popen([str(args.binary.resolve()), 'run', '-c', str(path)], stdout=log, stderr=log)
                clients = []
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        assert process.poll() is None
                        try:
                            client = socket.create_connection(('127.0.0.1', port), timeout=3)
                            clients.append(client)
                            break
                        except OSError:
                            assert time.monotonic() < deadline
                            time.sleep(0.01)
                    payload = bytes(range(256)) * 257
                    request = b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target)
                    client.sendall(b'\x05\x01\x00' + request + payload)
                    assert receive(client, 2) == b'\x05\x00'
                    assert receive(client, 10)[:2] == b'\x05\x00'
                    assert receive(client, len(payload)) == payload
                    tunnel = socket.create_connection(('127.0.0.1', port), timeout=3)
                    clients.append(tunnel)
                    tunnel.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n'.encode() + payload)
                    assert headers(tunnel).startswith(b'HTTP/1.1 200 ')
                    assert receive(tunnel, len(payload)) == payload
                    for _ in range(8):
                        for established in clients:
                            established.sendall(payload)
                            assert receive(established, len(payload)) == payload
                    if not args.socks5:
                        with socket.create_connection(('127.0.0.1', port), timeout=3) as banner:
                            banner.sendall(b'\x05\x01\x00')
                            assert receive(banner, 2) == b'\x05\x00'
                            banner.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x02' + struct.pack('!H', target))
                            assert receive(banner, 10)[:2] == b'\x05\x00'
                            assert receive(banner, 5) == b'hello'
                            banner.sendall(payload)
                            assert receive(banner, len(payload)) == payload
                    if args.socks5:
                        # 上游回复后已带应用数据；入站成功回复前的提示不能丢失。
                        with socket.create_connection(('127.0.0.1', port), timeout=3) as banner:
                            banner.sendall(b'\x05\x01\x00')
                            assert receive(banner, 2) == b'\x05\x00'
                            banner.sendall(b'\x05\x01\x00\x03\x0bbanner.test' + struct.pack('!H', target))
                            assert receive(banner, 10)[:2] == b'\x05\x00'
                            assert receive(banner, 5) == b'hello'
                            banner.sendall(payload)
                            assert receive(banner, len(payload)) == payload
                    config['rules'] = ['MATCH,REJECT']
                    path.write_text(json.dumps(config))
                    process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 5
                    while True:
                        with socket.create_connection(('127.0.0.1', port), timeout=3) as fresh:
                            fresh.sendall(b'\x05\x01\x00' + request)
                            assert receive(fresh, 2) == b'\x05\x00'
                            reply = receive(fresh, 10)
                            if reply[1] != 0:
                                assert reply[1] == 2
                                break
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                    for established in clients:
                        established.sendall(payload)
                        assert receive(established, len(payload)) == payload
                    client.shutdown(socket.SHUT_WR)
                    assert client.recv(1) == b''
                    tunnel.sendall(payload)
                    assert receive(tunnel, 257) == payload[:257]
                    process.terminate()
                    assert process.wait(timeout=5) == 0
                    print(f'memory Path production passed ({args.socks5 or "direct"}): no outbound FD, preread, partial writes, reload and half-close')
                except Exception:
                    log.flush()
                    print((root / 'run.log').read_text())
                    raise
                finally:
                    for client in clients:
                        client.close()
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()


if __name__ == '__main__':
    main()

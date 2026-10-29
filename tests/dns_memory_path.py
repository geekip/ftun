#!/usr/bin/env python3
"""Exercise production DNS listeners with socket-free upstream channels."""
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def receive(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        assert part, 'Unexpected DNS TCP EOF'
        result += part
    return result


def query(identifier):
    return struct.pack('!6H', identifier, 0x100, 1, 0, 0, 0) + b'\x01a\x07example\0\0\x01\0\x01'


def exchange(port, identifier, tcp):
    wire = query(identifier)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect(('127.0.0.1', port))
        if tcp:
            framed = struct.pack('!H', len(wire)) + wire
            for byte in framed:
                client.sendall(bytes([byte]))
            response = receive(client, struct.unpack('!H', receive(client, 2))[0])
        else:
            client.send(wire)
            response = client.recv(65535)
    expected = wire[:2] + bytes([wire[2] | 0x80]) + wire[3:]
    assert response == expected, (identifier, response.hex(), expected.hex())


def config(port, transport, proxy, auth):
    result = {'base': {'state-cache': False}, 'log': {'level': 'silent'},
              'dns': {'enable': True, 'cache': False, 'default-server': 'real',
                      'listeners': [{'listen': f'127.0.0.1:{port}', 'server': 'real'}],
                      'servers': [{'name': 'real', 'type': transport,
                                   'address': ['192.0.2.53:53'],
                                   'outbound': 'proxy' if proxy else 'DIRECT'}]}}
    if proxy:
        result['outbounds'] = [{'name': 'proxy', 'type': 'socks5', 'udp': True,
                                'server': '192.0.2.88:1080'}]
        if auth:
            result['outbounds'][0].update(username='user', password='pass')
    return result


def main():
    binary = str(Path(sys.argv[1]).resolve())
    proxy_mode = '--proxy' in sys.argv[2:]
    with tempfile.TemporaryDirectory(prefix='ftun-dns-path-') as directory:
        root = Path(directory)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        path = root / 'config.json'
        path.write_text(json.dumps(config(port, 'udp', proxy_mode, False)))
        with (root / 'run.log').open('w+') as log:
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while True:
                    assert process.poll() is None, 'DNS process exited during startup'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=1):
                            break
                    except ConnectionRefusedError:
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                modes = [('udp', proxy_mode, False), ('tcp', proxy_mode, False)]
                if proxy_mode:
                    modes += [('udp', True, True), ('tcp', True, True)]
                for generation, (transport, proxy, auth) in enumerate(modes, 1):
                    if generation > 1:
                        path.write_text(json.dumps(config(port, transport, proxy, auth)))
                        process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 5
                    while True:
                        exchange(port, 100, False)
                        text = (root / 'run.log').read_text()
                        if f'generation={generation} ' in text:
                            break
                        assert time.monotonic() < deadline, 'DNS reload did not publish'
                        time.sleep(0.01)
                    for inbound_tcp in (False, True):
                        for identifier in (100, 101, 102, 103):
                            exchange(port, identifier, inbound_tcp)
                    text = (root / 'run.log').read_text()
                    lines = [line for line in text.splitlines() if f'generation={generation} ' in line]
                    if transport == 'udp':
                        assert any('transport=2 ' in line for line in lines), lines
                        # 奇数请求经 TC fallback 重新打开 TCP；UDP 响应不够证明 TCP 能工作。
                        assert any('transport=1 ' in line for line in lines), lines
                    if proxy:
                        assert any('port=1080' in line for line in lines), lines
                    print(f'PASS DNS memory {transport} proxy={proxy} auth={auth} generation={generation}')
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=5) == 0, 'DNS stop failed'
                text = (root / 'run.log').read_text()
                assert 'AddressSanitizer' not in text and 'runtime error:' not in text, text
            except BaseException:
                log.flush()
                print((root / 'run.log').read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()

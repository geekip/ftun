#!/usr/bin/env python3
"""Exercise real UDP ingress with outbound Datagram paths that have no sockets."""
import argparse
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time

from inbound_adapter_product import receive


def associate(port):
    control = socket.create_connection(('127.0.0.1', port), timeout=3)
    control.sendall(b'\x05\x01\x00\x05\x03\x00\x01' + bytes(6))
    assert receive(control, 2) == b'\x05\x00'
    reply = receive(control, 10)
    assert reply[:4] == b'\x05\x00\x00\x01'
    endpoint = (socket.inet_ntoa(reply[4:8]), struct.unpack('!H', reply[8:])[0])
    data = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data.bind(('127.0.0.1', 0))
    data.settimeout(3)
    return control, data, endpoint


def exchange(data, relay, header, payload):
    data.sendto(header + payload, relay)
    reply, source = data.recvfrom(65535)
    assert source == relay and reply == header + payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--socks5', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ftun-memory-datagram-') as directory:
        root = Path(directory)
        with socket.socket() as reserved, socket.socket() as tcp_guard, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_guard:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
            tcp_guard.bind(('127.0.0.1', 0))
            target = tcp_guard.getsockname()[1]
            udp_guard.bind(('127.0.0.1', target))
            udp_guard.setblocking(False)
            config = {'base': {'state-cache': False}, 'dns': {'enable': False},
                      'log': {'level': 'silent'}, 'rules': ['MATCH,DIRECT'],
                      'inbounds': [{'name': 'socks', 'type': 'socks5', 'udp': True,
                                    'listen': f'127.0.0.1:{port}'}]}
            if args.socks5:
                config['outbounds'] = [{'name': 'proxy', 'type': 'socks5', 'udp': True,
                                        'server': f'127.0.0.1:{target}',
                                        'username': 'user', 'password': 'pass'}]
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
                            first = associate(port)
                            clients.append(first)
                            break
                        except ConnectionRefusedError:
                            assert time.monotonic() < deadline
                            time.sleep(0.01)
                    second = associate(port)
                    clients.append(second)
                    header = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target)
                    for length in (0, 1, 3, 1200, 8192, 65000):
                        payload = bytes(index % 256 for index in range(length))
                        for _, data, relay in clients:
                            exchange(data, relay, header, payload)
                    # 排队期间维持报文 FIFO、源身份和完整边界。
                    _, data, relay = second
                    burst = [struct.pack('!I', index) + bytes([index]) * 1200 for index in range(16)]
                    for payload in burst:
                        data.sendto(header + payload, relay)
                    for payload in burst:
                        reply, source = data.recvfrom(65535)
                        assert source == relay and reply == header + payload
                    config['rules'] = ['MATCH,REJECT']
                    path.write_text(json.dumps(config))
                    process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 5
                    while True:
                        with socket.create_connection(('127.0.0.1', port), timeout=3) as probe:
                            probe.sendall(b'\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target))
                            assert receive(probe, 2) == b'\x05\x00'
                            if receive(probe, 10)[1] == 2:
                                break
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                    for _, data, relay in clients:
                        exchange(data, relay, header, b'old-generation')
                    fresh = associate(port)
                    clients.append(fresh)
                    fresh[1].settimeout(0.2)
                    fresh[1].sendto(header + b'rejected', fresh[2])
                    try:
                        fresh[1].recvfrom(65535)
                        raise AssertionError('new generation bypassed REJECT')
                    except socket.timeout:
                        pass
                    first[0].close()
                    exchange(second[1], second[2], header, b'independent-association')
                    # 目的端口没有应答者；真实 native UDP 发送也必须没有发生。
                    try:
                        udp_guard.recvfrom(65535)
                        raise AssertionError('outbound bypassed the Datagram factory')
                    except BlockingIOError:
                        pass
                    for payload in burst:
                        second[1].sendto(header + payload, second[2])
                    process.terminate()
                    assert process.wait(timeout=5) == 0
                    print(f'memory Datagram production passed ({"socks5" if args.socks5 else "direct"}): boundaries, FIFO, reload, isolated close and in-flight stop')
                except Exception:
                    log.flush()
                    print((root / 'run.log').read_text())
                    raise
                finally:
                    for control, data, _ in clients:
                        control.close()
                        data.close()
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()


if __name__ == '__main__':
    main()

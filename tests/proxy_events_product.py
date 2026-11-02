#!/usr/bin/env python3
"""Verify proxy flow SID, pinned generation, bounded details and quiet levels."""
from pathlib import Path
import re
import json
import socket
import struct
import sys
import tempfile
import threading
import time

from core_baseline import socks_tcp, socks_udp
from ctl_server_product import Instance, wait
from ipv6_product import TCP, EchoTCP, UDP, EchoUDP, serving, exact

SAMPLES = 80


def text(path):
    return path.read_text() if path.exists() else ''


def closed(path):
    return [line for line in text(path).splitlines() if '[proxy ][DEBUG] closed:' in line]


def run_case(binary, root, level, target):
    log = root.parent / (level + '.log')
    running = Instance(binary, root, initial={'log': {'level': level, 'output': 'file', 'file': str(log)}})
    try:
        if level in ('info', 'debug'):
            wait(lambda: '] ready:' in text(log), lambda: text(log))
        payload = b'proxy-event-payload'
        before = text(log)
        samples = []
        for ident in range(SAMPLES):
            started = time.perf_counter_ns()
            with socks_tcp(running.port, target) as stream:
                stream.sendall(payload)
                assert exact(stream, len(payload)) == payload
            samples.append((time.perf_counter_ns() - started) / 1000)
            if level == 'debug':
                wait(lambda: len(closed(log)) == ident + 1, lambda: text(log))
        if level == 'debug':
            groups = {}
            for line in text(log).splitlines():
                if '[proxy ][DEBUG]' not in line:
                    continue
                sid = re.search(r'\bsid=(\d+)', line)
                assert sid and int(sid[1]) > 0, line
                groups.setdefault(sid[1], []).append(line)
            assert len(groups) == SAMPLES, groups
            for group in groups.values():
                assert len(group) == 3 and '] connect:' in group[0] and '] rule matched:' in group[1] and '] closed:' in group[2], group
                assert all('gen=1' in line for line in group), group
                assert 'target=127.0.0.1' in group[0] and f'port={target}' in group[0], group
                assert 'out=DIRECT' in group[1] and 'out_id=0' in group[1], group
                assert int(re.search(r'written_bytes=(\d+)', group[2])[1]) >= len(payload) * 2, group
            with socks_tcp(running.port, target) as held:
                held.sendall(payload)
                assert exact(held, len(payload)) == payload
                assert running.call('reload', timeout_ms=5000)['result'] == 'committed'
                with socks_tcp(running.port, target) as newer:
                    newer.sendall(payload)
                    assert exact(newer, len(payload)) == payload
                wait(lambda: len(closed(log)) == SAMPLES + 1, lambda: text(log))
                assert 'gen=2' in closed(log)[-1], text(log)
            wait(lambda: len(closed(log)) == SAMPLES + 2, lambda: text(log))
            assert 'gen=1' in closed(log)[-1], text(log)
        else:
            time.sleep(.1)
            assert text(log) == before, (level, text(log))
        assert running.call('stop', timeout_ms=5000)['result'] == 'stopped'
        assert running.process.wait(timeout=5) == 0
        if level == 'silent':
            assert text(log) == ''
        ordered = sorted(samples)
        print(json.dumps({'level': level, 'samples': len(samples), 'connect_echo_close_p50_us': ordered[len(ordered) // 2],
                          'connect_echo_close_p99_us': ordered[-1]}))
    finally:
        running.close()


def main():
    with tempfile.TemporaryDirectory(prefix='ftun-proxy-events-') as directory, serving(TCP, EchoTCP, '127.0.0.1') as target:
        for level in ('info', 'warn', 'silent', 'debug'):
            run_case(sys.argv[1], Path(directory) / level, level, target.server_address[1])
        failures(sys.argv[1], Path(directory) / 'failures')
        datagrams(sys.argv[1], Path(directory) / 'udp')
    print('proxy events: unique SID, connect/rule/closed, byte counters, retained generation and quiet traffic passed')


def datagrams(binary, root):
    log = root.parent / 'udp.log'
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    running = Instance(binary, root, initial={'log': {'level': 'debug', 'output': 'file', 'file': str(log)},
        'inbounds': [{'name': 'socks', 'type': 'socks5', 'listen': f'127.0.0.1:{port}', 'udp': True}]})
    running.port = port
    assert running.call('reload', timeout_ms=5000)['result'] == 'committed'
    try:
        with serving(UDP, EchoUDP, '127.0.0.1') as target:
            for _ in range(3):
                control, stream, relay, header = socks_udp(running.port, target.server_address[1])
                try:
                    stream.sendto(header + b'datagram', relay)
                    assert stream.recv(1024).endswith(b'datagram')
                finally:
                    stream.close()
                    control.close()
        assert running.call('stop', timeout_ms=5000)['result'] == 'stopped'
        assert running.process.wait(timeout=5) == 0
        groups = {}
        for line in text(log).splitlines():
            if 'transport=udp' in line:
                sid = re.search(r'\bsid=(\d+)', line)[1]
                groups.setdefault(sid, []).append(line)
        assert len(groups) == 3, text(log)
        for lines in groups.values():
            assert len(lines) == 3 and '] connect:' in lines[0] and '] rule matched:' in lines[1] and '] closed:' in lines[2], lines
            assert all('gen=2' in line for line in lines), lines
            assert 'read_bytes=8' in lines[2] and 'written_bytes=8' in lines[2], lines
    finally:
        running.close()


def failures(binary, root):
    log = root.parent / 'failures.log'
    reserved = socket.socket()
    reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    reserved.bind(('127.0.0.1', 0))
    target = reserved.getsockname()[1]
    running = Instance(binary, root, initial={'log': {'level': 'info', 'output': 'file', 'file': str(log)}})
    server = thread = None
    try:
        for _ in range(10):
            with socket.create_connection(('127.0.0.1', running.port), timeout=3) as stream:
                stream.sendall(b'\x05\x01\x00')
                assert exact(stream, 2) == b'\x05\x00'
                stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target))
                assert exact(stream, 10)[1] != 0
        wait(lambda: '] dial failed (first):' in text(log), lambda: text(log))
        assert text(log).count('] dial failed (first):') == 1, text(log)
        assert 'errno=ECONNREFUSED' in text(log), text(log)
        reserved.close()
        server = TCP(('127.0.0.1', target), EchoTCP)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
        thread.start()
        with socks_tcp(running.port, target) as stream:
            stream.sendall(b'recovered')
            assert exact(stream, 9) == b'recovered'
        wait(lambda: '] dial recovered:' in text(log), lambda: text(log))
        recovered = next(line for line in text(log).splitlines() if '] dial recovered:' in line)
        assert 'count=10' in recovered and 'duration_ms=' in recovered and 'entity=DIRECT' in recovered, recovered
        for _ in range(10):
            with socket.create_connection(('127.0.0.1', running.port), timeout=3) as stream:
                stream.sendall(b'\x05\x00')
                while stream.recv(64):
                    pass
        wait(lambda: '] protocol failed (first):' in text(log), lambda: text(log))
        assert text(log).count('] protocol failed (first):') == 1, text(log)
        assert running.call('stop', timeout_ms=5000)['result'] == 'stopped'
        assert running.process.wait(timeout=5) == 0
        summary = [line for line in text(log).splitlines() if '] protocol failed:' in line]
        assert len(summary) == 1 and 'count=10' in summary[0], text(log)
        assert 'protocol recovered' not in text(log)
    finally:
        running.close()
        reserved.close()
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    main()

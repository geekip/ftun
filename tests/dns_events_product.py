#!/usr/bin/env python3
"""Verify DNS correlation, quiet steady traffic and real upstream state changes."""
import json
import os
from pathlib import Path
import re
import socket
import struct
import sys
import tempfile
import threading
import time

from cli_results_product import reserve_dns_sockets
from ctl_server_product import Instance, wait


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.invalid = threading.Event()
        self.done = threading.Event()
        self.queries = 0
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.done.is_set():
            try:
                wire, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            self.queries += 1
            response = wire[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
            response += wire[12:] + b'\xc0\x0c' + struct.pack('!HHIH4s', 1, 1, 60, 4, b'\xcb\x00\x71\x07')
            if self.invalid.is_set():
                response = response[:4] + b'\x00\x02' + response[6:]
            self.socket.sendto(response, peer)

    def close(self):
        self.done.set()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive()
        self.socket.close()


def query(port, ident, name=b'cli.example'):
    wire = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0)
    wire += b''.join(bytes([len(label)]) + label for label in name.split(b'.')) + b'\x00\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(2)
        stream.sendto(wire, ('127.0.0.1', port))
        response, _ = stream.recvfrom(4096)
    assert response[:2] == wire[:2] and response[3] & 15 == 0, response


def instance(binary, root, level, upstreams, cache):
    udp, tcp = reserve_dns_sockets()
    listener = udp.getsockname()[1]
    udp.close()
    tcp.close()
    log = root / 'events.log'
    initial = {
        'log': {'level': level, 'output': 'file', 'file': str(log)},
        'dns': {'enable': True, 'cache': cache, 'fake-ip': {'enable': False, 'persist': False},
                'default-server': 'events', 'servers': [
                    {'name': 'events', 'type': 'udp', 'outbound': 'DIRECT',
                     'address': [f'127.0.0.1:{upstream.port}' for upstream in upstreams]}],
                'listeners': [{'listen': f'127.0.0.1:{listener}', 'server': 'events'}]}}
    running = Instance(binary, root, initial=initial)
    return running, log, listener


def text(path):
    return path.read_text() if path.exists() else ''


def lines(path, phrase):
    return [line for line in text(path).splitlines() if '] ' + phrase + ':' in line]


def correlation_and_control(binary, root, level):
    upstream = Upstream()
    running = None
    try:
        running, log, listener = instance(binary, root, level, [upstream], True)
        if level in ('info', 'debug'):
            wait(lambda: lines(log, 'ready'), lambda: text(log))
        durations = []
        for ident in range(80):
            started = time.perf_counter_ns()
            query(listener, ident)
            durations.append(time.perf_counter_ns() - started)
            if level == 'debug':
                wait(lambda: len(lines(log, 'answer')) == ident + 1, lambda: text(log))
        ordered = sorted(durations)
        print(json.dumps({'level': level, 'samples': len(durations),
                          'dns_cache_p50_us': ordered[len(ordered) // 2] / 1000,
                          'dns_cache_p99_us': ordered[-1] / 1000}), flush=True)
        if level == 'debug':
            wait(lambda: len(lines(log, 'answer')) == 80, lambda: text(log))
            grouped = {}
            for line in text(log).splitlines():
                if '[dns   ][DEBUG]' in line:
                    match = re.search(r'\bsid=(\d+)', line)
                    assert match and int(match[1]) > 0, line
                    grouped.setdefault(match[1], []).append(line)
            assert len(grouped) == 80, grouped
            for group in grouped.values():
                assert len(group) == 3 and '] query:' in group[0] and '] answer:' in group[-1], group
                assert all('gen=1' in line for line in group), group
            assert len(lines(log, 'upstream query')) == 1
            assert len(lines(log, 'cache hit')) == 79
            query(listener, 81, b'line\n"name.example')
            wait(lambda: len(lines(log, 'answer')) == 81, lambda: text(log))
            assert 'name="line\\n\\"name.example"' in text(log), text(log)
        else:
            time.sleep(.1)
            before = text(log)
            for ident in range(90, 130):
                query(listener, ident)
            time.sleep(.1)
            assert text(log) == before, (level, text(log))
            assert not lines(log, 'query') and not lines(log, 'answer')
        assert upstream.queries == (2 if level == 'debug' else 1)

        if level == 'debug':
            running.config['log']['level'] = 'invalid-level'
            running.write()
            rejected = running.call('reload', timeout_ms=5000)
            assert rejected['result'] == 'rejected', rejected
            wait(lambda: lines(log, 'configuration rejected'), lambda: text(log))
            assert 'pointer=/log/level' in text(log) and 'field=log.level' in text(log), text(log)
            running.config['log']['level'] = level
            running.write()
            committed = running.call('reload', timeout_ms=5000)
            assert committed['result'] == 'committed', committed
            operation = committed['op_id']
            wait(lambda: any(f'op={operation} ' in line and 'result=committed' in line
                             for line in lines(log, 'result')), lambda: text(log))
            requested = lines(log, 'reload requested')
            assert any(f'op={operation} ' in line and f'uid={os.geteuid()}' in line and 'source=ipc' in line
                       for line in requested), requested
            for _ in range(10):
                assert running.call('reload', boot='ffffffffffffffff')['result'] == 'rejected'
            wait(lambda: lines(log, 'request rejected (first)'), lambda: text(log))
            assert len(lines(log, 'request rejected (first)')) == 1
            with running.connect() as stream:
                stream.sendall(b'{}\n')
                assert json.loads(stream.makefile('rb').readline())['result'] == 'invalid-request'
            wait(lambda: len(lines(log, 'request rejected (first)')) == 2, lambda: text(log))
            rejected_lines = lines(log, 'request rejected (first)')
            assert any('result=invalid-request' in line and f'uid={os.geteuid()}' in line for line in rejected_lines)
            assert any('result=boot-mismatch' in line and f'uid={os.geteuid()}' in line for line in rejected_lines)
        stopped = running.call('stop', timeout_ms=5000)
        assert stopped['result'] == 'stopped', stopped
        assert running.process.wait(timeout=5) == 0
        if level in ('info', 'debug'):
            assert lines(log, 'listener started') and lines(log, 'listener stopped'), text(log)
            assert any('result=runtime-stopped' in line for line in lines(log, 'result')), text(log)
        if level == 'silent':
            assert text(log) == ''
    finally:
        if running is not None:
            running.close()
        upstream.close()


def health(binary, root):
    primary, standby = Upstream(), Upstream()
    primary.invalid.set()
    running = None
    try:
        running, log, listener = instance(binary, root, 'info', [primary, standby], False)
        query(listener, 1)
        wait(lambda: lines(log, 'response invalid (first)'), lambda: text(log))
        assert not lines(log, 'upstream failures (first)'), text(log)
        assert running.call('status')['logs']['aggregation']['failures'] == 1
        for ident in range(2, 22):
            query(listener, ident)
        assert not lines(log, 'upstream failures (first)'), text(log)
        primary.invalid.clear()
        deadline = time.monotonic() + 8
        ident = 30
        while not lines(log, 'response valid'):
            assert time.monotonic() < deadline, text(log)
            query(listener, ident)
            ident += 1
            time.sleep(.05)
        wait(lambda: lines(log, 'group switched'), lambda: text(log))
        assert any('duration_ms=' in line and 'count=1' in line for line in lines(log, 'response valid')), text(log)
        assert not lines(log, 'upstream healthy'), text(log)
        time.sleep(.1)
        before = text(log)
        for ident in range(100, 140):
            query(listener, ident)
        time.sleep(.1)
        assert text(log) == before, text(log)
        assert running.call('stop', timeout_ms=5000)['result'] == 'stopped'
        assert running.process.wait(timeout=5) == 0
    finally:
        if running is not None:
            running.close()
        primary.close()
        standby.close()


def main():
    with tempfile.TemporaryDirectory(prefix='ftun-dns-events-') as directory:
        root = Path(directory)
        for level in ('info', 'warn', 'silent', 'debug'):
            correlation_and_control(sys.argv[1], root / level, level)
        health(sys.argv[1], root / 'health')
    print('DNS events: SID/cache/answer, quiet levels, escaped names, control actor/result and failover recovery passed')


if __name__ == '__main__':
    main()

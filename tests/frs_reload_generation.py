#!/usr/bin/env python3
"""FRS auto-update with changed rules must keep reload working and generations continuous."""
import http.server
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

P1, P2, P3, P4, P5 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
                      0x165667B19E3779F9, 0x85EBCA77C2B2AE63,
                      0x27D4EB2F165667C5)
MASK = (1 << 64) - 1


def rotl(value, bits):
    return ((value << bits) | (value >> (64 - bits))) & MASK


def xxh64_round(accumulator, lane):
    accumulator = (accumulator + lane * P2) & MASK
    return (rotl(accumulator, 31) * P1) & MASK


def xxh64(data):
    """XXH64, seed 0, as required by the FRS 1.0 header checksum."""
    length = len(data)
    offset = 0
    if length >= 32:
        lanes = [(P1 + P2) & MASK, P2, 0, (-P1) & MASK]
        while offset + 32 <= length:
            for index in range(4):
                lane = struct.unpack_from('<Q', data, offset + 8 * index)[0]
                lanes[index] = xxh64_round(lanes[index], lane)
            offset += 32
        value = (rotl(lanes[0], 1) + rotl(lanes[1], 7) + rotl(lanes[2], 12) +
                 rotl(lanes[3], 18)) & MASK
        for lane in lanes:
            value ^= xxh64_round(0, lane)
            value = (value * P1 + P4) & MASK
    else:
        value = P5
    value = (value + length) & MASK
    while offset + 8 <= length:
        value ^= xxh64_round(0, struct.unpack_from('<Q', data, offset)[0])
        value = (rotl(value, 27) * P1 + P4) & MASK
        offset += 8
    if offset + 4 <= length:
        value ^= (struct.unpack_from('<I', data, offset)[0] * P1) & MASK
        value = (rotl(value, 23) * P2 + P3) & MASK
        offset += 4
    while offset < length:
        value ^= (data[offset] * P5) & MASK
        value = (rotl(value, 11) * P1) & MASK
        offset += 1
    value ^= value >> 33
    value = (value * P2) & MASK
    value ^= value >> 29
    value = (value * P3) & MASK
    return value ^ (value >> 32)


def frs_ipv4(label, low, high):
    """Single IPv4 set container following the FRS 1.0 layout."""
    label = label.encode()
    sets_offset = 64 + 3 * 40
    strings_offset = sets_offset + 64
    ranges_offset = (strings_offset + len(label) + 7) & ~7
    total = ranges_offset + 8
    body = bytearray(total)
    struct.pack_into('<8sHHIIIQQQQQ', body, 0, b'FTUNFRS\0', 1, 0, 64, 0x1, 3,
                     total, 64, 0, 0, 0)
    sections = [(1, sets_offset, 64, 1, 64),
                (2, strings_offset, len(label), len(label), 1),
                (3, ranges_offset, 8, 1, 8)]
    for index, (kind, offset, length, count, stride) in enumerate(sections):
        struct.pack_into('<IIQQQII', body, 64 + 40 * index, kind, 1, offset,
                         length, count, stride, 0)
    struct.pack_into('<IHHQII' + 'II' * 3 + 'II' + 'Q', body, sets_offset,
                     1, 1, 0, 0, len(label), 0, 1, 1, 0, 0, 0, 0, 0, 1, 0)
    body[strings_offset:strings_offset + len(label)] = label
    struct.pack_into('<II', body, ranges_offset, low, high)
    struct.pack_into('<Q', body, 48, xxh64(bytes(body)))
    return bytes(body)


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


def main():
    binary = str(Path(sys.argv[1]).resolve())
    initial = frs_ipv4('CN', 0x01000000, 0x01FFFFFF)
    updated = frs_ipv4('CN', 0x02000000, 0x02FFFFFF)
    downloads = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            downloads.append(self.path)
            self.send_response(200)
            self.send_header('Content-Length', str(len(updated)))
            self.end_headers()
            self.wfile.write(updated)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='ftun-frs-reload-') as directory:
        root = Path(directory)
        rules = root / 'rules.frs'
        rules.write_bytes(initial)
        log_path = root / 'ftun.log'
        config = {
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache')},
            'dns': {'enable': False},
            'log': {'output': 'file', 'level': 'info', 'file': str(log_path)},
            'frs': {'path': str(rules),
                    'url': f'http://127.0.0.1:{server.server_port}/rules',
                    'auto-update': True, 'update-interval': '1s'},
            'inbounds': [{'name': 'socks', 'type': 'socks5',
                          'listen': f'127.0.0.1:{free_port()}'}],
            'rules': ['FRS-IP,CN,REJECT', 'MATCH,DIRECT'],
        }
        config_path = root / 'config.json'
        config_path.write_text(json.dumps(config))
        stderr_path = root / 'stderr.txt'
        with stderr_path.open('w+') as stderr:
            process = subprocess.Popen([binary, 'run', '-c', str(config_path), '-p', str(config_path) + '.pid'],
                                       stdout=stderr, stderr=stderr)
            try:
                log = lambda: log_path.read_text() if log_path.exists() else ''
                wait_for(process, lambda: rules.read_bytes() == updated and
                         'configuration published:' in log())
                published = re.findall(
                    r'configuration published: gen=(\d+) [^\n]*service=frs '
                    r'reason=frs-update', log())
                assert published == ['2'], published
                queried = subprocess.run([binary, 'proxy', 'status', '-p', str(config_path) + '.pid', '--json'],
                                         capture_output=True, text=True, timeout=5)
                assert queried.returncode == 0 and not queried.stderr, queried
                snapshot = json.loads(queried.stdout)
                assert snapshot['generation'] == snapshot['stats_generation'] == 2, snapshot
                assert snapshot['frs']['items'] and all(item['updated_unix_ms'] is not None
                                                        for item in snapshot['frs']['items']), snapshot
                assert all(abs(item['updated_unix_ms'] - int(time.time() * 1000)) < 10000
                           for item in snapshot['frs']['items']), snapshot
                def status():
                    result = subprocess.run([binary, 'status', '-p', str(config_path) + '.pid', '--json'],
                                            capture_output=True, text=True, timeout=5)
                    assert result.returncode == 0, result
                    return json.loads(result.stdout)
                instance = status()
                sequences = [instance['logs']['sequence']]
                for expected in ('3', '4'):
                    process.send_signal(signal.SIGHUP)
                    wait_for(process, lambda: re.search(r'configuration committed: op=\d+ gen=' + expected + r' ', log()))
                    sampled = status()
                    assert sampled['boot'] == instance['boot']
                    sequences.append(sampled['logs']['sequence'])
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=15) == 0
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
            stderr.seek(0)
            output = stderr.read()
        assert output.count('ftun: reload committed') == 2, output
        assert 'reload rejected' not in output, output
        text = log_path.read_text()
        assert '[frs   ][INFO ] rule set loaded:' in text, text
        assert '[frs   ][INFO ] rule set updated:' in text, text
        assert '[frs   ][INFO ] rule set published:' in text, text
        assert 'err=stale' not in text, text
        # 文本用本地毫秒时间，boot仅在启动输出；状态序号递增，同次reload共用op。
        line_pattern = re.compile(
            r'^\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} [+-]\d{4}\]'
            r'\[[a-z ]{6}\]\[(?:ERROR|WARN |INFO |DEBUG|TRACE)\] ')
        requested, committed = [], []
        for line in text.splitlines():
            assert line_pattern.match(line), line
            assert 'seq=' not in line, line
            if '[config]' in line and (' reload requested:' in line or ' configuration committed:' in line):
                op = re.search(r'\bop=(\d+)', line)
                assert op, line
                (requested if ' reload requested:' in line else committed).append(op.group(1))
        boots = re.findall(r'\bboot=([0-9a-f]{16})\b', text)
        assert boots == [instance['boot']], boots
        assert len(sequences) == 3 and sequences == sorted(set(sequences)), sequences
        assert len(requested) == 2 and requested == committed, (requested, committed)
        assert len(set(requested)) == 2, requested

    server.shutdown()
    assert downloads, 'FRS update was never requested'
    print('PASS FRS update with changed rules: generation 2 published, reloads 3 and 4 committed')


if __name__ == '__main__':
    main()

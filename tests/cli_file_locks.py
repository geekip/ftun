#!/usr/bin/env python3
"""Exercise cache/log lock ownership with real instances and foreign holders."""
import fcntl
import json
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def probe(port):
    with socket.create_connection(('127.0.0.1', port), timeout=.2) as stream:
        stream.sendall(b'\x05\x01\x00')
        assert stream.recv(2) == b'\x05\x00'


def wait(predicate, message):
    deadline = time.monotonic() + 10
    while not predicate():
        assert time.monotonic() < deadline, message()
        time.sleep(.01)


def lock(path):
    stream = Path(str(path) + '.lock').open('a+')
    try:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        stream.close()
        raise
    return stream


def held(path):
    try:
        stream = lock(path)
    except BlockingIOError:
        return True
    stream.close()
    return False


def escaped(path):
    return str(path).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\x0a')


def main():
    binary = str(Path(sys.argv[1]).resolve())
    processes = []
    with tempfile.TemporaryDirectory(prefix='ftun-file-locks-') as directory:
        root = Path(directory)

        def config():
            with socket.socket() as stream:
                stream.bind(('127.0.0.1', 0))
                port = stream.getsockname()[1]
            return {'base': {'state-cache': False}, 'log': {'level': 'silent'},
                    'dns': {'enable': False, 'fake-ip': {'persist': False}},
                    'inbounds': [{'name': 'socks', 'type': 'socks5',
                                  'listen': f'127.0.0.1:{port}', 'udp': False}],
                    'rules': ['MATCH,DIRECT']}, port

        def command(path):
            return [binary, 'run', '-c', str(path), '-p', str(path) + '.pid']

        def reject(name, document, conflict):
            path = root / (name + '.json')
            path.write_text(json.dumps(document))
            result = subprocess.run(command(path), capture_output=True, text=True, timeout=15)
            assert result.returncode == 1 and escaped(conflict) in result.stderr, result
            assert not Path(str(path) + '.pid').exists()

        try:
            for purpose in ('cache', 'log'):
                first = root / (purpose + ' "\\一')
                second = root / (purpose + '-next')
                document, port = config()

                def set_path(path):
                    if purpose == 'cache':
                        document['base'].update({'state-cache': True, 'cache-file': str(path)})
                    else:
                        document['log'] = {'output': 'file', 'level': 'info', 'file': str(path)}

                set_path(first)
                # 启动失败的必要结果不能被 silent 级别过滤，路径不得注入另一行。
                with lock(first):
                    reject(purpose + '-foreign', document, first)
                path = root / (purpose + '.json')
                output = root / (purpose + '.stderr')
                path.write_text(json.dumps(document))
                with output.open('wb') as stream:
                    process = subprocess.Popen(command(path), stdout=subprocess.DEVNULL, stderr=stream)
                processes.append(process)

                def ready():
                    assert process.poll() is None, output.read_text()
                    try:
                        probe(port)
                        return True
                    except (ConnectionRefusedError, TimeoutError):
                        return False

                wait(ready, output.read_text)
                assert held(first)
                reject(purpose + '-contender', document, first)
                probe(port)

                def reload(expected):
                    before = output.read_text().count('ftun: reload ')
                    path.write_text(json.dumps(document))
                    process.send_signal(signal.SIGHUP)
                    wait(lambda: output.read_text().count('ftun: reload ') > before, output.read_text)
                    assert expected in output.read_text().splitlines()[-1], output.read_text()
                    probe(port)

                # 同宿主同用途的旧 sink/新 sink 允许共享原生锁。
                if purpose == 'log':
                    document['log']['level'] = 'warn'
                reload('reload committed')
                with lock(second):
                    set_path(second)
                    reload('reload rejected')
                    assert escaped(second) in output.read_text().splitlines()[-1]
                    assert held(first)
                reload('reload committed')
                wait(lambda: not held(first), lambda: 'old path remained locked: ' + output.read_text())
                assert held(second)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=15) == 0, output.read_text()
                assert not held(second)

            # 同一宿主的日志与缓存是不同用途，不能把同路径误认为合法共享。
            document, _ = config()
            shared = root / 'same-log-and-cache'
            document['base'].update({'state-cache': True, 'cache-file': str(shared)})
            document['log'] = {'output': 'file', 'level': 'info', 'file': str(shared)}
            reject('cross-purpose', document, shared)
            assert not held(shared)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
    print('CLI file locks: conflicts, escaped paths, same-path reload, failed swap, recovery and cleanup passed')


if __name__ == '__main__':
    main()

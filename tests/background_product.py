#!/usr/bin/env python3
"""Exercise daemon handoff, native session/FDs, file logs and startup failures."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
from ctl_server_product import wait


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('faulty', type=Path)
    parser.add_argument('--real-timeout', action='store_true')
    args = parser.parse_args()
    binary, faulty = str(args.binary.resolve()), str(args.faulty.resolve())
    # 本测试接管并回收孙进程，避免环境PID1不回收后台测试进程。
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0

    def children():
        return [int(value) for value in Path(f'/proc/self/task/{os.getpid()}/children').read_text().split()]

    def reap(timeout=8, keep=()):
        deadline = time.monotonic() + timeout
        statuses = []
        while any(child not in keep for child in children()):
            child, status = os.waitpid(-1, os.WNOHANG)
            if child:
                statuses.append(os.waitstatus_to_exitcode(status))
            else:
                assert time.monotonic() < deadline, children()
                time.sleep(.01)
        return statuses

    def invoke(command, *, code=0, env=None, timeout=12, **options):
        result = subprocess.run(command, capture_output=True, env=env, timeout=timeout, **options)
        assert result.returncode == code, result
        return result

    def status(pid):
        return json.loads(invoke([binary, 'status', '-p', str(pid), '--json']).stdout)

    def stop(pid):
        invoke([binary, 'stop', '-p', str(pid)])
        wait(lambda: not pid.exists() and not pid.with_suffix('.sock').exists(), lambda: str(pid))
        assert reap() == [0]

    def probe(port):
        with socket.create_connection(('127.0.0.1', port), timeout=2) as stream:
            stream.sendall(b'\x05\x01\x00')
            assert stream.recv(2) == b'\x05\x00'

    try:
        with tempfile.TemporaryDirectory(prefix='ftun-background-') as temporary:
            root = Path(temporary)

            def fixture(name, output='stderr', level='info'):
                case = root / name
                case.mkdir()
                with socket.socket() as reserved:
                    reserved.bind(('127.0.0.1', 0))
                    port = reserved.getsockname()[1]
                path, pid, log = case / 'config.json', case / 'instance.pid', case / 'runtime.log'
                document = {'base': {'state-cache': False}, 'dns': {'enable': False},
                    'log': {'level': level, 'output': output, 'file': str(log)},
                    'inbounds': [{'name': 'local', 'type': 'socks5', 'listen': f'127.0.0.1:{port}'}],
                    'rules': ['MATCH,DIRECT']}
                path.write_text(json.dumps(document))
                return path, pid, log, port, document

            healthy = None
            if args.real_timeout:
                live_path, live_pid, live_log, live_port, live_document = fixture('healthy-during-timeout', level='silent')
                invoke([binary, 'run', '-b', '-c', str(live_path), '-p', str(live_pid)])
                healthy = (live_pid, live_port)

            faults = ('real-timeout',) if args.real_timeout else ('fork', 'setsid', 'pidfile', 'null', 'pipe', 'short', 'redirect', 'timeout')
            for fault in faults:
                path, pid, log, port, document = fixture('failure-' + fault, level='silent')
                started = time.monotonic()
                result = invoke([faulty, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1,
                    env=dict(os.environ, FTUN_TEST_BACKGROUND_FAULT=fault), timeout=75 if args.real_timeout else 12)
                elapsed = time.monotonic() - started
                assert b'ftun: ready' not in result.stderr and result.stdout == b'', result
                if fault.endswith('timeout'):
                    assert b'background startup: timeout' in result.stderr, result
                    assert (59.5 <= elapsed < 65) if args.real_timeout else (.20 <= elapsed < 5), elapsed
                wait(lambda: not pid.exists() and not pid.with_suffix('.sock').exists(), lambda: list(pid.parent.iterdir()))
                codes = reap(keep=(int(healthy[0].read_text()),) if healthy is not None else ())
                assert all(code == 1 for code in codes), codes
                with socket.socket() as held:
                    held.bind(('127.0.0.1', port))
            if args.real_timeout:
                probe(healthy[1])
                assert status(healthy[0])['state'] == 'running'
                stop(healthy[0])
                print('background: actual60000ms parent deadline, child self-cleanup and ready-instance guard cancellation passed')
                return

            for output, level, extra in [('stderr', 'info', []), ('both', 'info', []), ('file', 'info', []),
                                         ('stderr', 'silent', []), ('stderr', 'silent', ['-vv', '--no-color'])]:
                path, pid, log, port, document = fixture(f'{output}-{level}-{len(extra)}', output, level)
                result = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid), *extra])
                assert result.stdout == b'' and result.stderr.count(b'ftun: ready') == 1, result
                child = int(pid.read_text())
                assert os.getsid(child) == child
                assert [os.readlink(f'/proc/{child}/fd/{index}') for index in range(3)] == ['/dev/null'] * 3
                value = status(pid)
                assert value['pid'] == child and value['state'] == 'running'
                assert value['logs']['level'] == ('trace' if extra else level), value
                assert value['logs']['output'] == ('disabled' if level == 'silent' and not extra else 'file'), value
                if level != 'silent' or extra:
                    assert str(log).encode() in result.stderr and log.exists() and b'\x1b' not in log.read_bytes(), result
                else:
                    assert b'logging disabled' in result.stderr and not log.exists(), result
                probe(port)
                duplicate = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1)
                assert b'use -p FILE' in duplicate.stderr and int(pid.read_text()) == child, duplicate
                document['log']['output'] = 'stderr'
                path.write_text(json.dumps(document))
                invoke([binary, 'reload', '-p', str(pid)])
                assert status(pid)['logs']['output'] == value['logs']['output']
                os.kill(child, signal.SIGHUP)
                wait(lambda: status(pid)['generation'] == 3, lambda: status(pid))
                probe(port)
                stop(pid)

            path, pid, log, port, document = fixture('delayed', level='silent')
            started = time.monotonic()
            invoke([faulty, 'run', '-b', '-c', str(path), '-p', str(pid)],
                env=dict(os.environ, FTUN_TEST_BACKGROUND_FAULT='delayed'))
            assert time.monotonic() - started >= .30
            probe(port)
            stop(pid)

            # owner完全不推进时，第二次原生期限结束进程；残留入口按既有锁语义接管。
            path, pid, log, port, document = fixture('stuck', level='silent')
            result = invoke([faulty, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1,
                env=dict(os.environ, FTUN_TEST_BACKGROUND_FAULT='stuck'),
                preexec_fn=lambda: signal.signal(signal.SIGALRM, signal.SIG_IGN))
            assert b'background startup: timeout' in result.stderr
            started = time.monotonic()
            codes = reap(timeout=13)
            assert len(codes) == 1 and codes[0] != 0, codes
            assert 9 <= time.monotonic() - started < 13
            result = invoke([binary, 'status', '-p', str(pid)], code=1)
            invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)])
            probe(port)
            stop(pid)

            # 缺失的标准FD须先补齐，后续重定向不能释放PID锁。
            for closed in range(3):
                path, pid, log, port, document = fixture('closed-' + str(closed), level='silent')
                invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], preexec_fn=lambda: os.close(closed))
                assert status(pid)['state'] == 'running'
                duplicate = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1)
                assert b'use -p FILE' in duplicate.stderr
                probe(port)
                stop(pid)

            path, pid, log, port, document = fixture('degraded', level='silent')
            document['inbounds'][0]['listen'] = f'203.0.113.254:{port}'
            path.write_text(json.dumps(document))
            result = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)])
            assert b'ftun: ready (degraded: proxy waiting (io))' in result.stderr, result
            assert next(service['state'] for service in status(pid)['services'] if service['name'] == 'proxy') == 'waiting'
            stop(pid)

            path, pid, log, port, document = fixture('日志"' + chr(92), level='info')
            result = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)])
            assert result.stderr.count(b'\n') == 1 and b'\\\\' in result.stderr and b'\\"' in result.stderr, result
            probe(port)
            stop(pid)

            path, pid, log, port, document = fixture('file-denied')
            log.mkdir()
            result = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1)
            assert b'ftun: run: app prepare failed:' in result.stderr and str(log).encode() in result.stderr, result
            wait(lambda: not pid.exists() and not pid.with_suffix('.sock').exists(), lambda: list(pid.parent.iterdir()))
            assert reap() == [1]

            path, pid, log, port, document = fixture('bind-denied')
            with socket.socket() as held:
                held.bind(('127.0.0.1', port)); held.listen()
                result = invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], code=1)
                assert b'ftun: run: proxy commit failed: io' in result.stderr, result
                wait(lambda: not pid.exists() and not pid.with_suffix('.sock').exists(), lambda: list(pid.parent.iterdir()))
                assert reap() == [1]

            # 父进程输出满或关闭不拖住已就绪的数据面；独立结果writer最多2秒排空。
            for full in (False, True):
                path, pid, log, port, document = fixture('output-' + str(full), level='silent')
                read_fd, write_fd = os.pipe()
                try:
                    if full:
                        os.set_blocking(write_fd, False)
                        while True:
                            try:
                                os.write(write_fd, b'x' * 4096)
                            except BlockingIOError:
                                break
                    else:
                        os.close(read_fd)
                        read_fd = -1
                    started = time.monotonic()
                    result = subprocess.run([binary, 'run', '-b', '-c', str(path), '-p', str(pid)],
                        stdout=subprocess.DEVNULL, stderr=write_fd, timeout=8)
                    assert result.returncode == 0 and time.monotonic() - started < 5
                    probe(port)
                    stop(pid)
                finally:
                    if read_fd >= 0:
                        os.close(read_fd)
                    os.close(write_fd)

            # 前台stderr不使用默认日志路径；后台启用文件时才要求HOME。
            path, pid, log, port, document = fixture('no-home')
            del document['log']['file']
            path.write_text(json.dumps(document))
            no_home = dict(os.environ)
            no_home.pop('HOME', None)
            invoke([binary, 'check', '-c', str(path)], env=no_home)
            invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], env=no_home, code=1)
            assert not pid.exists()
            assert reap() == [1]
            document['log']['level'] = 'silent'
            path.write_text(json.dumps(document))
            invoke([binary, 'run', '-b', '-c', str(path), '-p', str(pid)], env=no_home)
            assert status(pid)['logs']['output'] == 'disabled'
            stop(pid)

            home = root / 'default-home'
            home.mkdir()
            pid = root / 'default.pid'
            result = invoke([binary, 'run', '-b', '-p', str(pid)], env=dict(os.environ, HOME=str(home)))
            assert b'created default configuration:' in result.stderr and b'ftun: ready' in result.stderr, result
            assert (home / '.ftun' / 'config.json').exists() and (home / '.ftun' / 'ftun.log').exists()
            assert status(pid)['logs']['file'] == str(home / '.ftun' / 'ftun.log')
            invoke([binary, 'reload', '-p', str(pid)])
            assert status(pid)['logs']['file'] == str(home / '.ftun' / 'ftun.log')
            stop(pid)
    finally:
        for child in children():
            os.kill(child, signal.SIGKILL)
        reap()
    print('background: native handoff/session/FDs, file-only reload, silent/verbose, ready wait, failures, slow output and default config passed')


if __name__ == '__main__':
    main()

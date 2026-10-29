#!/usr/bin/env python3
"""Check real CLI configuration, module, reload and shutdown producer events."""
import argparse
import contextlib
import json
import re
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from cli_results_product import dns_query, fixture, port, reserve_dns_sockets


def read(path):
    return path.read_text() if path.exists() else ''


def wait_for(process, predicate):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        assert process.poll() is None, f'process exited: {process.returncode}'
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('condition deadline expired')


def live(listener):
    try:
        dns_query(listener, 19)
        return True
    except (TimeoutError, ConnectionError, OSError):
        return False


def config(directory, name, level, upstream, proxy, listener, proxy_port=None):
    value = {'base': {'state-cache': False},
             'log': {'file': str(directory / (name + '.log'))},
             'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                     'default-server': 'direct',
                     'servers': [{'name': 'direct', 'type': 'udp',
                                  'address': [f'127.0.0.1:{upstream}'], 'outbound': 'DIRECT'}],
                     'listeners': [{'listen': f'127.0.0.1:{listener}', 'server': 'direct'}]}}
    if level is not None:
        value['log']['level'] = level
    if proxy:
        if proxy_port is None:
            proxy_port = port(socket.SOCK_STREAM)
        value['inbounds'] = [{'name': 'events', 'type': 'socks5',
                              'listen': f'127.0.0.1:{proxy_port}', 'udp': False}]
        value['rules'] = ['MATCH,DIRECT']
    return value


def ordered(text, markers):
    position = 0
    for marker in markers:
        found = text.find(marker, position)
        assert found >= 0, (marker, text)
        position = found + len(marker)


def run_case(binary, directory, level, upstream, proxy):
    with contextlib.ExitStack() as leases:
        reservations = list(reserve_dns_sockets())
        for sock in reservations:
            leases.enter_context(sock)
        sock = leases.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.bind(('127.0.0.1', 0))
        reservations.append(sock)
        run_reserved_case(binary, directory, level, upstream, proxy, reservations)


def run_reserved_case(binary, directory, level, upstream, proxy, reservations):
    name = level or 'default'
    path = directory / (name + '.json')
    log = directory / (name + '.log')
    stderr = directory / (name + '.stderr')
    listener = reservations[0].getsockname()[1]
    proxy_port = reservations[2].getsockname()[1]
    value = config(directory, name, level, upstream, proxy, listener, proxy_port)
    path.write_text(json.dumps(value))
    with stderr.open('wb') as errors:
        for sock in reservations:
            sock.close()
        process = subprocess.Popen([str(binary), 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=errors)
        try:
            wait_for(process, lambda: live(listener))
            if level == 'info':
                wait_for(process, lambda: 'event=running ' in read(log))
                ordered(read(log), ['event=starting ', 'event=config.read ',
                                    'event=config.parsed ', 'event=config.validated ',
                                    'event=config.compiled ', 'event=module.selected ',
                                    'event=module.preparing ', 'event=module.prepared ',
                                    'event=module.active ', 'event=running '])
                if proxy:
                    assert 'event=module.selected module=proxy generation=1 reason=required' in read(log)
                else:
                    assert 'event=module.disabled module=proxy generation=1 reason=not-built' in read(log)
                initial = read(log)
                for ident in range(20, 40):
                    dns_query(listener, ident)
                time.sleep(0.1)
                assert read(log) == initial, 'ordinary queries generated lifecycle spam'
            else:
                assert read(log) == '', (level, read(log))

            path.write_text('{')
            process.send_signal(signal.SIGHUP)
            wait_for(process, lambda: 'ftun: reload rejected' in read(stderr))
            assert live(listener), 'rejected reload stopped existing listener'
            if level != 'silent':
                wait_for(process, lambda: 'event=reload.rejected ' in read(log))
                assert 'event=config.failed module=app generation=2 reason=parse' in read(log)
                assert 'event=running module=app generation=2 ' not in read(log)
            else:
                assert not log.exists(), 'silent created a log file'

            if level == 'info':
                path.unlink()
                process.send_signal(signal.SIGHUP)
                wait_for(process, lambda: read(stderr).count('ftun: reload rejected') == 2)
                wait_for(process, lambda: 'event=config.failed module=app generation=2 reason=read ' in read(log))
                text = read(log)
                read_line = next(line for line in text.splitlines() if 'event=config.read ' in line)
                failed_line = next(line for line in text.splitlines()
                                   if 'event=config.failed ' in line and 'reason=read ' in line)
                assert re.search(r'stage=([0-9]+)', read_line).group(1) == \
                    re.search(r'stage=([0-9]+)', failed_line).group(1), failed_line
                assert live(listener)
                value['log']['level'] = 'silent'
                path.write_text(json.dumps(value))
                process.send_signal(signal.SIGHUP)
                wait_for(process, lambda: read(stderr).count('ftun: reload committed') == 1)
                previous = read(log)
                assert live(listener)
                value['log']['level'] = 'info'
                replacement = directory / 'replacement.log'
                value['log']['file'] = str(replacement)
                path.write_text(json.dumps(value))
                process.send_signal(signal.SIGHUP)
                wait_for(process, lambda: read(stderr).count('ftun: reload committed') == 2)
                wait_for(process, lambda: 'event=reload.committed module=app generation=3 ' in read(replacement))
                assert read(log) == previous, 'retired sink received new events'
                log = replacement
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=10) == 0, read(stderr)
            if level == 'info':
                ordered(read(log), ['event=reload.committed ', 'event=stopping ',
                                    'event=module.quiesced ', 'event=module.drained ',
                                    'event=module.stopped ', 'event=runtime.stopped '])
                assert 'event=module.stopped module=dns generation=3 ' in read(log)
                assert 'event=runtime.stopped module=app generation=3 reason=log-draining' in read(log).splitlines()[-1]
            assert 'configuration OK' not in read(stderr)
        except BaseException:
            print(json.dumps({'level': name, 'exit': process.poll(),
                              'dns_port': listener, 'proxy_port': proxy_port,
                              'stderr': read(stderr), 'log': read(log)}), file=sys.stderr, flush=True)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def failure_cases(binary, directory, upstream, proxy):
    for phase, body in [('parse', '{'), ('validate', '{"log":{"level":"bad"}}'),
                        ('paths', '{"dns":{"enable":false},"log":{"file":"~someone/x"}}')]:
        path = directory / ('bad-' + phase + '.json')
        path.write_text(body)
        completed = subprocess.run([str(binary), 'run', '-c', str(path)], capture_output=True, timeout=8)
        assert completed.returncode != 0
        assert ('ftun: configuration ' + phase + ': invalid').encode() in completed.stderr, completed.stderr
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
        occupied.bind(('127.0.0.1', 0))
        value = config(directory, 'occupied', 'info', upstream, proxy, occupied.getsockname()[1])
        path = directory / 'occupied.json'
        path.write_text(json.dumps(value))
        completed = subprocess.run([str(binary), 'run', '-c', str(path)], capture_output=True, timeout=10)
        assert completed.returncode != 0, 'occupied listener unexpectedly started'
        text = read(directory / 'occupied.log')
        assert 'event=module.failed module=dns ' in text, text
        assert 'event=rollback ' in text and 'event=running ' not in text, text
        assert 'event=module.active module=dns ' not in text, text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ftun', required=True, type=Path)
    parser.add_argument('--proxy', action='store_true')
    args = parser.parse_args()
    stopped = threading.Event()
    with tempfile.TemporaryDirectory(prefix='ftun-events-') as temp, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        udp.bind(('127.0.0.1', 0))
        tcp.bind(('127.0.0.1', 0))
        tcp.listen()
        worker = threading.Thread(target=fixture, args=(udp, tcp, stopped))
        worker.start()
        try:
            for level in ('info', 'warn', 'silent', None):
                run_case(args.ftun, Path(temp), level, udp.getsockname()[1], args.proxy)
            failure_cases(args.ftun, Path(temp), udp.getsockname()[1], args.proxy)
        finally:
            stopped.set()
            worker.join(timeout=2)
            assert not worker.is_alive()
    print('Lifecycle configuration, module and reload events OK')


if __name__ == '__main__':
    main()

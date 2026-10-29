#!/usr/bin/env python3
"""日志轮转与 SIGUSR1：真实进程。大小超限时按 max-files 轮转；外部移走日志文件后
SIGUSR1 让之后的日志落在新建的文件上，进程不受影响。"""
import json
from pathlib import Path
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time


def free_port():
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        return reserve.getsockname()[1]


def wait_for(predicate, seconds=10, what='condition'):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f'timeout waiting for {what}')


def main(binary):
    with tempfile.TemporaryDirectory(prefix='ftun-logrot-') as directory:
        root = Path(directory)
        log = root / 'ftun.log'
        config = {
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache')},
            'dns': {'enable': False},
            # 最小的合法上限，保留 2 个文件：用 reload 事件产生足够的日志量。
            'log': {'level': 'info', 'file': str(log), 'max-size': 65536, 'max-files': 2},
            'inbounds': [{'name': 'in', 'type': 'socks5', 'listen': f'127.0.0.1:{free_port()}'}],
            'rules': ['MATCH,DIRECT'],
        }
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        process = subprocess.Popen([binary, 'run', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wait_for(lambda: log.exists() and log.stat().st_size > 0, what='first log line')
            # 反复 reload 产生日志，直到发生轮转（ftun.log.1 出现）。
            reloads = 0
            while not (root / 'ftun.log.1').exists() and reloads < 200:
                process.send_signal(signal.SIGHUP)
                reloads += 1
                time.sleep(0.05)
            wait_for(lambda: (root / 'ftun.log.1').exists(), what='rotation')
            assert process.poll() is None
            assert log.stat().st_size <= 65536
            assert not (root / 'ftun.log.2').exists(), 'max-files=2 keeps one rotated file'
            # 外部 logrotate：移走文件，SIGUSR1 之后新日志落在新文件。
            moved = root / 'moved.log'
            os.rename(log, moved)
            process.send_signal(signal.SIGUSR1)
            time.sleep(0.5)
            process.send_signal(signal.SIGHUP)
            wait_for(lambda: log.exists() and log.stat().st_size > 0, what='new file after SIGUSR1')
            assert process.poll() is None
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=15) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    print('Log rotation product: size rotation, max-files and SIGUSR1 reopen passed')


if __name__ == '__main__':
    main(sys.argv[1])

#!/usr/bin/env python3
"""心跳看门狗与服务管理器通知：真实进程，空闲时仍按期确认心跳，READY/WATCHDOG/STOPPING 报文与退出码。"""
import json
import os
from pathlib import Path
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


def drain(server, messages):
    while True:
        try:
            messages.append(server.recv(64).decode())
        except BlockingIOError:
            return


def main(binary):
    with tempfile.TemporaryDirectory(prefix='ftun-watchdog-') as directory:
        root = Path(directory)
        notify_path = root / 'notify.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(str(notify_path))
        server.setblocking(False)
        config = {
            # 1s 的判定期限、333ms 一次心跳：空闲的 owner 必须被唤醒并确认，否则 1s 后就会被终止。
            'base': {'state-cache': False, 'cache-file': str(root / 'ftun.cache'),
                     'watchdog': '1s'},
            'dns': {'enable': False},
            'log': {'level': 'warn', 'file': str(root / 'ftun.log')},
            'inbounds': [{'name': 'in', 'type': 'socks5', 'listen': f'127.0.0.1:{free_port()}'}],
            'rules': ['MATCH,DIRECT'],
        }
        config_path = root / 'config.json'
        config_path.write_text(json.dumps(config))
        environment = dict(os.environ, NOTIFY_SOCKET=str(notify_path), WATCHDOG_USEC='600000')
        process = subprocess.Popen([binary, 'run', '-c', str(config_path)], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # WATCHDOG_PID 未设置时按全进程处理；先跑 4 秒，空闲期间不得被看门狗终止。
        messages = []
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            assert process.poll() is None, f'ftun exited early: {process.returncode}'
            drain(server, messages)
            time.sleep(0.05)
        drain(server, messages)
        assert messages and messages[0] == 'READY=1', messages
        pings = messages.count('WATCHDOG=1')
        assert pings >= 5, (pings, messages)
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0, process.returncode
        drain(server, messages)
        assert 'STOPPING=1' in messages, messages
        stderr = process.stderr.read().decode()
        assert 'watchdog' not in stderr, stderr

        # 退出码：用法错误为 2，启动期配置错误为 1。
        usage = subprocess.run([binary, 'bogus-command'], capture_output=True)
        assert usage.returncode == 2, usage.returncode
        bad = root / 'bad.json'
        bad.write_text('{"base":{"watchdog":"5ms"}}')
        invalid = subprocess.run([binary, 'run', '-c', str(bad)], capture_output=True)
        assert invalid.returncode == 1, invalid.returncode
    print('Watchdog product: idle heartbeat, notify messages, exit codes passed')


if __name__ == '__main__':
    main(sys.argv[1])

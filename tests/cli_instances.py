#!/usr/bin/env python3
"""Verify PID locks, stale identities and cleanup using real CLI processes."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()

    def document():
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        return {'base': {'state-cache': False}, 'log': {'level': 'silent'},
                'dns': {'enable': False},
                'inbounds': [{'name': 'instance', 'type': 'socks5',
                              'listen': f'127.0.0.1:{port}', 'udp': False}],
                'rules': ['MATCH,DIRECT']}, port

    def ready(process, pidfile, port, output):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert process.poll() is None, output.read_text(errors='replace')
            if pidfile.exists() and pidfile.read_text() == f'{process.pid}\n':
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1) as stream:
                        stream.sendall(b'\x05\x01\x00')
                        if stream.recv(2) == b'\x05\x00':
                            return
                except (ConnectionRefusedError, TimeoutError):
                    pass
            time.sleep(0.01)
        raise AssertionError('instance not ready: ' + output.read_text(errors='replace'))

    def stop(process):
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=15) == 0

    with tempfile.TemporaryDirectory(prefix='ftun-instances-') as directory:
        root = Path(directory)
        processes = []

        def launch(path, pidfile, *, default=False, environment=None, preexec=None):
            output = path.with_suffix('.stderr')
            command = [str(binary), 'run', '-c', str(path)]
            if not default:
                command += ['-p', str(pidfile)]
            with output.open('wb') as stream:
                process = subprocess.Popen(command, stderr=stream, stdout=subprocess.DEVNULL,
                                           env=environment, preexec_fn=preexec)
            processes.append(process)
            return process, output

        try:
            config, port = document()
            path, pidfile = root / '配置 文件.json', root / '实例 一.pid'
            path.write_text(json.dumps(config))
            # 活着的其他 PID 不构成身份；没有锁的文件可安全接管。
            pidfile.write_text(f'{os.getpid()}\n')
            process, output = launch(path, pidfile)
            ready(process, pidfile, port, output)
            assert stat.S_IMODE(pidfile.stat().st_mode) == 0o600
            second = subprocess.run([str(binary), 'run', '-c', str(path), '-p', str(pidfile)],
                                    capture_output=True, text=True, timeout=10)
            assert second.returncode == 1 and 'another instance is running' in second.stderr, second
            assert str(process.pid) in second.stderr and 'use -p FILE' in second.stderr
            assert pidfile.read_text() == f'{process.pid}\n'

            config2, port2 = document()
            path2, pidfile2 = root / 'two.json', root / 'two.pid'
            path2.write_text(json.dumps(config2))
            process2, output2 = launch(path2, pidfile2)
            ready(process2, pidfile2, port2, output2)
            stop(process2)
            assert not pidfile2.exists() and process.poll() is None
            # 外部替换后的路径不属于退出实例。
            previous = root / 'previous.pid'
            pidfile.rename(previous)
            pidfile.write_text('123456\n')
            stop(process)
            assert pidfile.read_text() == '123456\n' and previous.exists()
            pidfile.unlink()
            previous.unlink()

            process, output = launch(path, pidfile)
            ready(process, pidfile, port, output)
            process.kill()
            process.wait(timeout=5)
            assert pidfile.exists(), 'forced termination must leave a stale PID file'
            process, output = launch(path, pidfile)
            ready(process, pidfile, port, output)
            stop(process)
            assert not pidfile.exists()

            # 持锁者尚未写入有效 PID 时，只能报告未知，不能打印虚假的 PID 0。
            with pidfile.open('w') as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                busy = subprocess.run([str(binary), 'run', '-c', str(path), '-p', str(pidfile)],
                                      capture_output=True, text=True, timeout=10)
                assert busy.returncode == 1 and 'pid unknown' in busy.stderr, busy.stderr
            pidfile.unlink()

            # preflight 通过后因日志目录不可用失败，也必须撤销已接管的 PID 文件。
            obstacle = root / 'not-a-directory'
            obstacle.write_text('obstacle')
            broken = dict(config, log={'output': 'file', 'level': 'info', 'file': str(obstacle / 'log')})
            bad = root / 'broken.json'
            bad.write_text(json.dumps(broken))
            pidfile.write_text('123456\n')
            failed = subprocess.run([str(binary), 'run', '-c', str(bad), '-p', str(pidfile)],
                                    capture_output=True, text=True, timeout=10)
            assert failed.returncode == 1 and not pidfile.exists(), failed.stderr

            # 普通用户的默认目录在 HOME 下创建；不操作宿主默认 /run 路径。
            home = root / 'home'
            home.mkdir()
            default_config, default_port = document()
            default_path = home / 'run.json'
            default_path.write_text(json.dumps(default_config))
            environment = dict(os.environ, HOME=str(home))
            preexec = None
            if os.geteuid() == 0:
                for item in (root, home, default_path):
                    os.chown(item, 65534, 65534)

                def drop_privileges():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)

                preexec = drop_privileges
            default_pidfile = home / '.ftun/ftun.pid'
            process, output = launch(default_path, default_pidfile, default=True,
                                     environment=environment, preexec=preexec)
            ready(process, default_pidfile, default_port, output)
            assert stat.S_IMODE(default_pidfile.parent.stat().st_mode) == 0o700
            assert stat.S_IMODE(default_pidfile.stat().st_mode) == 0o600
            endpoint = default_pidfile.with_suffix('.sock')
            query = ('import socket,json,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(3); '
                     's.connect(sys.argv[1]); s.sendall(b\'{"op":"status"}\\n\'); '
                     'r=json.loads(s.makefile("rb").readline(65537)); '
                     'assert r["result"]=="ok"; print(r["pid"])')
            # 普通用户实例既接纳同UID，也接纳root；不靠目录权限替代系统凭据判断。
            for identity in (None, preexec) if preexec is not None else (None,):
                result = subprocess.run([sys.executable, '-c', query, str(endpoint)],
                                        preexec_fn=identity, capture_output=True, text=True, timeout=5)
                assert result.returncode == 0 and result.stdout.strip() == str(process.pid), result
            # 同UID命令默认定位以及显式数字PID匹配默认端点，都取得真实RPC终态。
            for locator in ([], [str(process.pid)]):
                done = subprocess.run([str(binary), 'reload', *locator, '--json'],
                                      env=environment, preexec_fn=preexec,
                                      capture_output=True, text=True, timeout=5)
                assert done.returncode == 0 and not done.stderr, done
                assert json.loads(done.stdout)['result'] == 'committed', done.stdout
            done = subprocess.run([str(binary), 'stop', '--json'],
                                  env=environment, preexec_fn=preexec,
                                  capture_output=True, text=True, timeout=5)
            assert done.returncode == 0 and json.loads(done.stdout)['result'] == 'stopped', done
            assert process.wait(timeout=1) == 0
            assert not default_pidfile.exists()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
    print('CLI instances: locks, stale/live PID, multi-instance, forced exit, cleanup and unprivileged defaults passed')


if __name__ == '__main__':
    main()

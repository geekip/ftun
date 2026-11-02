#!/usr/bin/env python3
"""Exercise the local control server through real Unix streams and CLI processes."""
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def response(stream):
    data = b''
    while not data.endswith(b'\n'):
        part = stream.recv(65536)
        assert part, 'control stream closed before its terminal response'
        data += part
        assert len(data) <= 65536, len(data)
    return json.loads(data)


def wait(predicate, diagnostic):
    deadline = time.monotonic() + 8
    while not predicate():
        assert time.monotonic() < deadline, diagnostic()
        time.sleep(.01)


class Instance:
    def __init__(self, binary, root, *, long_path=False, initial=None, env=None, stderr=None, extra_args=()):
        self.root = root
        root.mkdir()
        self.path, self.pid, self.endpoint = root / 'config.json', root / 'run.pid', root / 'run.sock'
        if long_path:
            parent = root
            for i in range(14):
                parent = parent / ('"\\' * 100 + str(i))
                parent.mkdir()
            self.path = parent / 'config.json'
        self.output = root / 'stderr'
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            self.port = reserved.getsockname()[1]
        self.config = {'base': {'state-cache': False}, 'log': {'level': 'silent'},
                       'dns': {'enable': False, 'fake-ip': {'persist': False}},
                       'inbounds': [{'name': 'socks', 'type': 'socks5',
                                     'listen': f'127.0.0.1:{self.port}', 'udp': False}],
                       'rules': ['MATCH,DIRECT']}
        if initial is not None:
            self.config.update(initial)
        self.write()
        with self.output.open('wb') as output:
            self.process = subprocess.Popen([binary, 'run', '-c', str(self.path), '-p', str(self.pid), *extra_args],
                                            stdout=subprocess.DEVNULL, stderr=output if stderr is None else stderr, env=env)
        wait(lambda: self.endpoint.exists() or self.process.poll() is not None, self.output.read_text)
        assert self.process.poll() is None, self.output.read_text()
        try:
            state = self.call('status')
        except (OSError, AssertionError) as error:
            self.close()
            raise AssertionError(f'initial control status failed: {error}\n{self.output.read_text()}') from error
        assert state['result'] == 'ok' and state['state'] == 'running', state
        self.boot = state['boot']
        assert state['generation'] == 1 and state['pid'] == self.process.pid
        assert state['config'] == str(self.path.resolve()), state['config']
        assert self.endpoint.stat().st_mode & 0o777 == 0o600

    def write(self):
        self.path.write_text(json.dumps(self.config))

    def connect(self, request=None):
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(8)
        stream.connect(str(self.endpoint))
        if request is not None:
            stream.sendall(json.dumps(request).encode() + b'\n')
        return stream

    def call(self, op, **fields):
        with self.connect(dict(op=op, **fields)) as stream:
            return response(stream)

    def probe(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=1) as stream:
            stream.sendall(b'\x05\x01\x00')
            assert stream.recv(2) == b'\x05\x00'

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def blocked_reload(self, name, timeout=5000):
        fifo = self.root / name
        os.mkfifo(fifo)
        self.config['base'].update({'state-cache': True, 'cache-file': str(fifo)})
        self.write()
        stream = self.connect({'op': 'reload', 'timeout_ms': timeout})
        wait(lambda: self.call('status')['reload_pending'], self.output.read_text)
        # .lock存在表示准备Worker已开始，但仍需等真正打开FIFO才可解除阻塞。
        wait(lambda: Path(str(fifo) + '.lock').exists(), self.output.read_text)
        return fifo, stream

    def release_fifo(self, fifo):
        # 阻塞的reader已执行open，短暂写端只用于使它继续做原有普通文件检查。
        descriptor = os.open(fifo, os.O_WRONLY)
        os.close(descriptor)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    instances = []
    with tempfile.TemporaryDirectory(prefix='ftun-ctl-') as directory:
        root = Path(directory)
        try:
            app = Instance(binary, root / 'main')
            instances.append(app)
            app.probe()
            assert app.call('status', boot=app.boot)['generation'] == 1
            wrong = '0' * 16 if app.boot != '0' * 16 else '1' * 16
            mismatch = app.call('stop', boot=wrong)
            assert mismatch['result'] == 'rejected' and mismatch['status'] == 'boot-mismatch', mismatch
            assert app.process.poll() is None
            for payload in (b'{}\n', b'{"op":"stop","op":"status"}\n',
                            b'{"op":"status","extra":1}\n', b'{"op":"status\\u0000"}\n',
                            b'{"op":"status"}\x00\n', b'x' * 4097 + b'\n',
                            b'{"op":"status"}\n{}\n'):
                with app.connect() as stream:
                    stream.sendall(payload)
                    assert response(stream)['result'] == 'invalid-request', payload
            with app.connect() as stream:
                for part in (b'{"op":', b'"status"', b'}\r\n'):
                    stream.sendall(part)
                    time.sleep(.01)
                assert response(stream)['result'] == 'ok'
            app.config['log']['level'] = 'silent'
            app.write()
            committed = app.call('reload')
            assert committed['result'] == 'committed' and committed['generation'] == 2, committed
            app.path.write_text('{"unknown":true}')
            rejected = app.call('reload')
            assert rejected['result'] == 'rejected' and rejected['generation'] == 2, rejected
            app.config['dns']['fake-ip']['persist'] = True
            app.write()
            restart = app.call('reload')
            assert restart['result'] == 'restart-required' and restart['generation'] == 2, restart
            app.config['dns']['fake-ip']['persist'] = False
            app.write()
            app.probe()
            # 未读请求占满8槽时，第9条连接必须被立即拒绝；业务仍可运行。
            held = [app.connect() for _ in range(8)]
            try:
                for stream in held:
                    stream.sendall(b'{')
                with app.connect() as overflow:
                    busy = response(overflow)
                assert busy['result'] == 'busy', busy
                app.probe()
            finally:
                for stream in held:
                    stream.close()
            time.sleep(.05)
            assert app.call('status')['result'] == 'ok'
            # 读取期限从接纳起固定，零散字节不能延长期限。
            with app.connect() as stream:
                start = time.monotonic()
                stream.sendall(b'{')
                time.sleep(2.5)
                stream.sendall(b'"op":')
                assert response(stream)['result'] == 'timeout'
                assert 4.5 < time.monotonic() - start < 7.5
            app.probe()
            if os.geteuid() == 0:
                os.chmod(root, 0o755)
                os.chmod(app.root, 0o755)
                os.chmod(app.endpoint, 0o666)

                def nobody():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)

                code = ('import socket,json,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); '
                        'print(s.recv(4096).decode())')
                denied = subprocess.run([sys.executable, '-c', code, str(app.endpoint)],
                                        preexec_fn=nobody, capture_output=True, text=True, timeout=5)
                assert denied.returncode == 0, denied.stderr
                assert json.loads(denied.stdout)['result'] == 'permission-denied', denied.stdout
                os.chmod(app.endpoint, 0o600)
            fifo, first = app.blocked_reload('cache-one')
            second = app.connect({'op': 'reload', 'timeout_ms': 5000})
            wait(lambda: app.call('status')['control']['merged'] >= 1, app.output.read_text)
            app.release_fifo(fifo)
            with first, second:
                a, b = response(first), response(second)
            assert a['result'] == b['result'] == 'committed' and a['op_id'] == b['op_id'], (a, b)
            assert not a['merged'] and b['merged'] and a['generation'] == b['generation'] == 3
            fifo, expired = app.blocked_reload('cache-two', timeout=100)
            with expired:
                timeout = response(expired)
            assert timeout['result'] == 'timeout'
            disconnected = app.connect({'op': 'reload', 'timeout_ms': 5000})
            disconnected.close()
            survivor = app.connect({'op': 'reload', 'timeout_ms': 5000})
            wait(lambda: app.call('status')['control']['merged'] >= 3, app.output.read_text)
            app.release_fifo(fifo)
            with survivor:
                terminal = response(survivor)
            assert terminal['result'] == 'committed' and terminal['generation'] == 4, terminal
            app.probe()
            stopped = app.call('stop')
            assert stopped['result'] == 'stopped' and stopped['generation'] == 4, stopped
            assert app.process.wait(timeout=5) == 0, app.output.read_text()
            assert not app.endpoint.exists() and not app.pid.exists()
            # 普通文件不能作为残留socket删除；启动失败仍须归还PID锁并说明路径。
            app.endpoint.write_text('foreign')
            collision = subprocess.run([binary, 'run', '-c', str(app.path), '-p', str(app.pid)],
                                       capture_output=True, text=True, timeout=8)
            assert collision.returncode == 1 and str(app.endpoint) in collision.stderr, collision
            assert app.endpoint.read_text() == 'foreign' and not app.pid.exists()
            app.endpoint.unlink()
            app = Instance(binary, root / 'accepted')
            instances.append(app)
            assert app.call('stop', timeout_ms=0)['result'] == 'accepted'
            assert app.process.wait(timeout=5) == 0, app.output.read_text()
            app = Instance(binary, root / 'stale')
            instances.append(app)
            previous_boot = app.boot
            app.process.kill()
            app.process.wait(timeout=5)
            assert app.pid.exists() and app.endpoint.exists()
            with app.output.open('ab') as output:
                app.process = subprocess.Popen([binary, 'run', '-c', str(app.path), '-p', str(app.pid)],
                                               stdout=subprocess.DEVNULL, stderr=output)

            def recovered():
                assert app.process.poll() is None, app.output.read_text()
                if app.pid.read_text() != f'{app.process.pid}\n':
                    return False
                try:
                    state = app.call('status')
                except (FileNotFoundError, ConnectionRefusedError):
                    return False
                app.boot = state['boot']
                return state['result'] == 'ok'

            wait(recovered, app.output.read_text)
            assert app.boot != previous_boot
            assert app.call('stop', boot=previous_boot)['status'] == 'boot-mismatch'
            assert app.call('stop')['result'] == 'stopped'
            assert app.process.wait(timeout=5) == 0, app.output.read_text()
            app = Instance(binary, root / 'timeout')
            instances.append(app)
            _, blocked = app.blocked_reload('blocked-worker')
            with blocked:
                stopped = app.call('stop', timeout_ms=50)
                assert stopped['result'] == 'timeout', stopped
            assert app.process.wait(timeout=5) == 1, app.output.read_text()
            assert not app.endpoint.exists()
        finally:
            for app in instances:
                app.close()
    print('Control server: native auth, boot guard, framing, slots, deadlines, merge, disconnect and true stop outcomes passed')


if __name__ == '__main__':
    main()

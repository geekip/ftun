#!/usr/bin/env python3
"""Verify terminal CLI control results against live instances and framed peers."""
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from ctl_server_product import Instance, response, wait


def invoke(binary, args, code, result=None, **options):
    done = subprocess.run([binary, *args], capture_output=True, text=True, timeout=8, **options)
    assert done.returncode == code, (args, done.returncode, done.stdout, done.stderr)
    if '--json' in args:
        assert not done.stderr, done.stderr
        value = json.loads(done.stdout)
        assert isinstance(value, dict)
        if result is not None:
            assert value['result'] == result, value
        return value
    assert not done.stdout and done.stderr, (done.stdout, done.stderr)
    if result is not None:
        assert result in done.stderr, done.stderr
    return done.stderr


def peer_case(binary, root, replies, code, result, operation="reload"):
    pidfile = root / 'peer.pid'
    endpoint = root / 'peer.sock'
    requests, errors = [], []
    with pidfile.open('w') as locked, socket.socket(socket.AF_UNIX) as listener:
        locked.write(str(os.getpid()) + '\n')
        locked.flush()
        fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        listener.bind(str(endpoint))
        listener.listen()
        listener.settimeout(3)

        def serve():
            try:
                for reply in replies:
                    with listener.accept()[0] as stream:
                        stream.settimeout(3)
                        requests.append(response(stream))
                        if reply == 'hold':
                            time.sleep(1.2)
                        elif reply is not None:
                            payload = reply if isinstance(reply, bytes) else json.dumps(reply).encode() + b'\n'
                            # 逐字节发送验证短读拼接；非ASCII/整数原文也应保留。
                            for byte in payload:
                                stream.sendall(bytes([byte]))
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            value = invoke(binary, [operation, '-p', str(pidfile), '--timeout', '1', '--json'], code, result)
        finally:
            worker.join(timeout=4)
            endpoint.unlink()
        assert not errors and not worker.is_alive(), errors
        return value, requests


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-cli-ctl-') as directory:
        root = Path(directory)
        app = Instance(binary, root / 'live')
        try:
            locator = ['-p', str(app.pid)]
            first = invoke(binary, ['reload', *locator, '--json'], 0, 'committed')
            assert first['generation'] == 2 and first['previous_generation'] == 1 and first['op_id'] > 0
            app.path.write_text('{"unknown":true}')
            rejected = invoke(binary, ['reload', *locator, '--json'], 1, 'rejected')
            assert rejected['generation'] == 2 and rejected['stage'] > 0
            app.config['dns']['fake-ip']['persist'] = True
            app.write()
            invoke(binary, ['reload', *locator], 1, 'restart-required')
            app.config['dns']['fake-ip']['persist'] = False
            app.write()
            accepted = invoke(binary, ['reload', *locator, '--no-wait', '--json'], 0, 'accepted')
            wait(lambda: app.call('status')['generation'] == 3, app.output.read_text)
            assert accepted['op_id'] > first['op_id']
            # 请求已递交后到期，退出5而实例及旧代仍然可用。
            fifo, pending = app.blocked_reload('pending')
            try:
                unknown = invoke(binary, ['reload', *locator, '--timeout', '1', '--json'], 5, 'timeout')
                assert unknown.get('merged') is True or unknown.get('via') == 'socket', unknown
                app.probe()
            finally:
                app.config['base'] = {'state-cache': False}
                app.write()
                app.release_fifo(fifo)
                assert response(pending)['result'] == 'committed'
                pending.close()
            wait(lambda: app.call('status')['generation'] == 5, app.output.read_text)
            app.config['base'] = {'state-cache': False}
            app.write()
            # 预拒绝发生在客户端send之前，不能越过busy改发信号。
            held = [app.connect() for _ in range(8)]
            try:
                for stream in held:
                    stream.sendall(b'{')
                invoke(binary, ['reload', *locator, '--json'], 1, 'busy')
            finally:
                for stream in held:
                    stream.close()
            app.probe()
            if os.geteuid() == 0:
                os.chmod(root, 0o755)
                os.chmod(app.root, 0o755)
                os.chmod(app.pid, 0o644)
                os.chmod(app.endpoint, 0o666)
                def nobody():
                    os.setgroups([])
                    os.setgid(65534)
                    os.setuid(65534)
                invoke(binary, ['reload', *locator, '--json'], 1, 'permission-denied', preexec_fn=nobody)
                os.chmod(app.pid, 0o600)
                os.chmod(app.endpoint, 0o600)
            invoke(binary, ['reload', *locator], 0, 'committed')
            stopped = invoke(binary, ['stop', *locator, '--json'], 0, 'stopped')
            # 等待命令期间父进程没有poll/reap，僵尸也必须被认定为已退出。
            assert stopped['pid'] == app.process.pid
            assert app.process.wait(timeout=1) == 0
            assert not app.pid.exists() and not app.endpoint.exists()
            invoke(binary, ['stop', *locator, '--json'], 1, 'not-running')
            app.pid.write_text(str(os.getpid()))  # 未持锁的残留不是运行实例。
            invoke(binary, ['reload', *locator, '--json'], 1, 'not-running')
        finally:
            app.close()
        nowait = Instance(binary, root / 'nowait')
        try:
            invoke(binary, ['stop', '-p', str(nowait.pid), '--no-wait', '--json'], 0, 'accepted')
            assert nowait.process.wait(timeout=5) == 0
        finally:
            nowait.close()
        # 显式数字PID无匹配端点才使用一次信号；reload不能伪报提交成功。
        script = 'import signal,time; signal.signal(signal.SIGHUP,lambda *_:None); print("ready",flush=True); time.sleep(20)'
        with subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, text=True) as child:
            assert child.stdout.readline().strip() == 'ready'
            pid = str(child.pid)
            value = invoke(binary, ['reload', pid, '--json'], 5, 'accepted')
            assert value['via'] == 'signal' and value['terminal'] is False
            invoke(binary, ['stop', pid, '--timeout', '2'], 0, 'process exited')
            assert child.wait(timeout=1) == -signal.SIGTERM
        script = 'import signal,time; signal.signal(signal.SIGTERM,lambda *_:None); print("ready",flush=True); time.sleep(20)'
        with subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE, text=True) as child:
            try:
                assert child.stdout.readline().strip() == 'ready'
                invoke(binary, ['stop', str(child.pid), '--timeout', '1', '--json'], 5, 'timeout')
                invoke(binary, ['stop', str(child.pid), '--no-wait', '--json'], 5, 'accepted')
                assert child.poll() is None
            finally:
                child.kill()
        invoke(binary, ['stop', '2147483647', '--json'], 1, 'failed')
        identity = {'result': 'ok', 'pid': os.getpid(), 'boot': '1234567890abcdef'}
        value, requests = peer_case(binary, root, [dict(identity, pid=os.getpid()+1)], 1, 'rejected')
        assert len(requests) == 1 and requests[0]['op'] == 'status'
        peer_case(binary, root, [b'{}\n'], 1, 'failed')
        for bad in (None, b'{}\n', b'{"result":"committed","result":"rejected"}\n',
                    b'x' * 65536, 'hold'):
            value, requests = peer_case(binary, root, [identity, bad], 5, None)
            assert requests[1]['boot'] == identity['boot'] and requests[1]['timeout_ms'] <= 1000
        for reply, code, expected in (
            (dict(identity, result='committed', boot='ffffffffffffffff'), 5, 'failed'),
            (dict(identity, result='ok'), 5, 'failed'),
            (dict(identity, result='invalid-request'), 2, 'invalid-request'),
            (dict(identity, result='rejected', boot='ffffffffffffffff', status='boot-mismatch'), 1, 'rejected')):
            peer_case(binary, root, [identity, reply], code, expected)
        peer_case(binary, root, [identity, dict(identity, result='stopped')], 5, 'timeout', operation='stop')
        # 断开的输出管道不得触发SIGPIPE或卡死；此失败不能伪报成功。
        reader, writer = os.pipe()
        os.close(reader)
        try:
            done = subprocess.run([binary, 'stop', '-p', str(root/'missing.pid'), '--json'],
                                  stdout=writer, stderr=subprocess.PIPE, timeout=3)
            assert done.returncode == 1, done
        finally:
            os.close(writer)
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        try:
            while True:
                os.write(writer, b'x' * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(writer, True)
        try:
            done = subprocess.run([binary, 'stop', '-p', str(root/'missing.pid'), '--json'],
                                  stdout=writer, stderr=subprocess.PIPE, timeout=3)
            assert done.returncode == 1, done
        finally:
            os.close(reader)
            os.close(writer)
        terminal = dict(identity, result='committed', op_id=18446744073709551615, generation=7)
        value, requests = peer_case(binary, root, [identity, terminal], 0, 'committed')
        assert value['op_id'] == 18446744073709551615  # JSON原始整数不经double重印。
        peer_case(binary, root, [identity, dict(terminal, result='merged', merged=True)], 0, 'merged')
        print('CLI control terminal, no-wait, identity, deadline, framing and signal cases passed')


if __name__ == '__main__':
    main()

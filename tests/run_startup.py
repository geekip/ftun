#!/usr/bin/env python3
"""Verify first-run files, silent ready/degraded results and CLI verbosity."""
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from ctl_server_product import Instance, wait


def stop(binary, process, pid):
    result = subprocess.run([binary, 'stop', '-p', str(pid)], capture_output=True, timeout=15)
    assert result.returncode == 0, result
    assert process.wait(timeout=12) == 0
    assert not pid.exists() and not pid.with_suffix('.sock').exists()


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-startup-') as directory:
        root = Path(directory)
        home = root / 'home'
        home.mkdir()
        env = dict(os.environ, HOME=str(home))
        default = home / '.ftun' / 'config.json'
        pid, output = root / 'default.pid', root / 'default.stderr'
        result = subprocess.run([binary, 'check'], env=env, capture_output=True, timeout=8)
        assert result.returncode == 1 and not default.parent.exists(), result
        result = subprocess.run([binary, 'run', '-c', str(default), '-p', str(pid)],
                                env=env, capture_output=True, timeout=8)
        assert result.returncode == 1 and not default.parent.exists() and not pid.exists(), result
        with output.open('wb') as sink:
            process = subprocess.Popen([binary, 'run', '-p', str(pid)], env=env, stderr=sink,
                                       stdout=subprocess.DEVNULL, umask=0)
        try:
            wait(lambda: b'ftun: ready' in output.read_bytes() or process.poll() is not None,
                 output.read_text)
            assert process.poll() is None, output.read_text()
            contents = default.read_bytes()
            assert json.loads(contents) == {'dns': {'enable': False}, 'inbounds': [
                {'name': 'local', 'type': 'socks5', 'listen': '127.0.0.1:1080'}],
                'rules': ['MATCH,DIRECT']}
            assert stat.S_IMODE(default.stat().st_mode) == 0o600
            assert stat.S_IMODE(default.parent.stat().st_mode) == 0o700
            assert output.read_text().index('created default configuration:') < output.read_text().index('ftun: ready')
            stop(binary, process, pid)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        # 已有无效文件和悬空链接均保留，不把缺失/错误配置替换成默认值。
        default.write_text('{broken')
        result = subprocess.run([binary, 'run', '-p', str(pid)], env=env, capture_output=True, timeout=8)
        assert result.returncode == 1 and default.read_text() == '{broken', result
        default.unlink()
        default.symlink_to('absent.json')
        result = subprocess.run([binary, 'run', '-p', str(pid)], env=env, capture_output=True, timeout=8)
        assert result.returncode == 1 and default.is_symlink() and not default.exists(), result
        assert not list(default.parent.glob('.ftun.tmp.*')), list(default.parent.iterdir())
        no_home = dict(env)
        no_home.pop('HOME')
        result = subprocess.run([binary, 'run', '-p', str(pid)], env=no_home, capture_output=True, timeout=8)
        assert result.returncode == 1 and not pid.exists(), result

        for option, level in [([], 'silent'), (['-v'], 'debug'), (['-vv'], 'trace')]:
            app = Instance(binary, root / level, extra_args=option)
            try:
                wait(lambda: 'ftun: ready\n' in app.output.read_text(), app.output.read_text)
                app.probe()
                assert app.call('status')['logs']['level'] == level
                app.config['log']['level'] = 'error'
                app.write()
                assert app.call('reload')['result'] == 'committed'
                assert app.call('status')['logs']['level'] == ('error' if level == 'silent' else level)
                stop(binary, app.process, app.pid)
                assert app.output.read_text().count('ftun: ready') == 1
            finally:
                app.close()

        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            app = Instance(binary, root / 'waiting', initial={'inbounds': [
                {'name': 'blocked', 'type': 'socks5', 'listen': f'203.0.113.254:{occupied.getsockname()[1]}'}]})
            try:
                wait(lambda: 'ftun: ready (degraded:' in app.output.read_text(), app.output.read_text)
                assert 'proxy waiting (io)' in app.output.read_text(), app.output.read_text()
                stop(binary, app.process, app.pid)
            finally:
                app.close()

        app = Instance(binary, root / 'frs-waiting', initial={
            'frs': {'path': str(root / 'absent.frs'), 'auto-update': True,
                    'url': 'http://127.0.0.1:1/rules.frs'},
            'rules': ['FRS-IP,CN,DIRECT', 'MATCH,DIRECT']})
        try:
            wait(lambda: 'ftun: ready (degraded:' in app.output.read_text(), app.output.read_text)
            assert 'frs not-ready (' in app.output.read_text(), app.output.read_text()
            stop(binary, app.process, app.pid)
        finally:
            app.close()

        # 无特权用户不能创建默认配置，不能留下文件、PID或默认目录。
        if os.geteuid() == 0:
            root.chmod(0o755)
            denied_home = root / 'denied-home'
            denied_home.mkdir(mode=0o555)
            result = subprocess.run([binary, 'run', '-p', str(pid)], capture_output=True,
                env=dict(env, HOME=str(denied_home)), user=65534, group=65534, extra_groups=[], timeout=8)
            assert result.returncode == 1 and not (denied_home / '.ftun').exists(), result

        modules = json.loads(subprocess.run([binary, 'version', '--modules', '--json'],
            capture_output=True, check=True, timeout=8).stdout)['modules']
        if os.geteuid() == 0 and 'tun' in modules:
            denied = root / 'tun-denied'
            denied.mkdir(mode=0o777)
            denied.chmod(0o777)
            config = denied / 'config.json'
            config.write_text(json.dumps({'base': {'state-cache': False}, 'dns': {'enable': False},
                'log': {'level': 'silent'}, 'tun': {'interface': 'ftundenied',
                    'ipv4': {'address': '172.19.0.1/30'}, 'auto-route': False},
                'inbounds': [{'type': 'tun', 'name': 'tun', 'tcp': True, 'udp': False, 'dns-hijack': False}],
                'rules': ['MATCH,DIRECT']}))
            denied_pid = denied / 'run.pid'
            result = subprocess.run([binary, 'run', '-c', str(config), '-p', str(denied_pid)],
                capture_output=True, user=65534, group=65534, extra_groups=[], timeout=12)
            assert result.returncode == 1 and b'ftun: run: tun commit failed: rejected' in result.stderr, result
            assert b'ftun: ready' not in result.stderr and not denied_pid.exists(), result
            assert not denied_pid.with_suffix('.sock').exists(), result

        # 文件sink准备失败给出模块/阶段/原因和物理路径，撤销实例入口。
        config = root / 'file-failure.json'
        (root / 'missing').write_text('parent is a regular file')
        log = root / 'missing' / 'runtime.log'
        config.write_text(json.dumps({'base': {'state-cache': False}, 'dns': {'enable': False},
            'log': {'level': 'error', 'output': 'file', 'file': str(log)},
            'inbounds': [{'name': 'local', 'type': 'socks5', 'listen': '127.0.0.1:0'}],
            'rules': ['MATCH,DIRECT']}))
        # 本用例需要合法固定端口，端口资源在进程启动前释放。
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            document = json.loads(config.read_text())
            document['inbounds'][0]['listen'] = f'127.0.0.1:{reserved.getsockname()[1]}'
        config.write_text(json.dumps(document))
        result = subprocess.run([binary, 'run', '-c', str(config), '-p', str(pid)],
                                capture_output=True, timeout=12)
        assert result.returncode == 1, result
        assert b'ftun: run: app prepare failed: io' in result.stderr, result
        assert str(log).encode() in result.stderr and b'ftun: ready' not in result.stderr, result
        assert not pid.exists() and not pid.with_suffix('.sock').exists(), result
        # silent启动阶段同样必须输出错误，且不能依赖普通logger存在。
        document['log'] = {'level': 'silent'}
        document['base'] = {'state-cache': True, 'cache-file': str(log)}
        config.write_text(json.dumps(document))
        result = subprocess.run([binary, 'run', '-c', str(config), '-p', str(pid)],
                                capture_output=True, timeout=12)
        assert result.returncode == 1 and b'ftun: run: app prepare failed: io' in result.stderr, result
        assert str(log).encode() in result.stderr and b'ftun: ready' not in result.stderr, result
        assert not pid.exists() and not pid.with_suffix('.sock').exists(), result
    print('run startup: default files, read-only check, no-clobber, silent ready, verbosity/reload, degraded and failure passed')


if __name__ == '__main__':
    main()

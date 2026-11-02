#!/usr/bin/env python3
"""Real check/reload diagnostics, read-only inspection and owned first-error results."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from ctl_server_product import Instance


def main():
    binary, fixture = (str(Path(value).resolve()) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix='ftun-config-errors-') as directory:
        root = Path(directory)
        path = root / 'config.json'

        def check(document, *, json_output=True, env=None):
            path.write_text(document if isinstance(document, str) else json.dumps(document, ensure_ascii=False))
            args = [binary, 'check', '-c', str(path)] + (['--json'] if json_output else [])
            return subprocess.run(args, capture_output=True, timeout=8, env=env)

        cases = [
            ('{"x":}', 'parse', '', '<root>'),
            ('{"dns":{"enable":false,"enable":true}}', 'parse', '/dns/enable', 'dns.enable'),
            ({'a~/b': 1}, 'parse', '/a~0~1b', '["a~/b"]'),
            ({'outbounds': [{'type': 'socks5', 'name': 'a', 'server': 'a:1'},
                            {'type': 'socks5', 'name': 'b', 'server': 'b:1'},
                            {'type': 'socks5', 'name': 'c'}]}, 'parse', '/outbounds/2/server', 'outbounds[2].server'),
            ({'dns': {'servers': [{'type': 'udp', 'name': 'a', 'address': ['1.1.1.1']},
                                 {'type': 'udp', 'name': 'b', 'address': ['bad_domain:53']}]}},
             'validate', '/dns/servers/1/address/0', 'dns.servers[1].address[0]'),
            ({'base': {'cache-file': '~someone/state'}}, 'paths', '/base/cache-file', 'base.cache-file'),
            ({'log': {'file': '~someone/log'}}, 'paths', '/log/file', 'log.file'),
            ({'outbounds': [{'type': 'select', 'name': 'g', 'outbounds': ['DIRECT', 'missing'], 'default': 'DIRECT'}]},
             'validate', '/outbounds/0/outbounds/1', 'outbounds[0].outbounds[1]'),
            ({'rules': ['MATCH,DIRECT', 'MATCH,missing']}, 'validate', '/rules/1', 'rules[1]'),
            ({'log': {'level': 'bad'}, 'dns': {'fake-ip': {'range': 'bad'}}}, 'validate', '/log/level', 'log.level'),
            ({'frs': {'path': str(root / 'missing.frs')}, 'rules': ['FRS-IP,CN,DIRECT']},
             'attachments', '/frs/path', 'frs.path'),
        ]
        for document, phase, pointer, field in cases:
            before = set(root.rglob('*'))
            result = check(document)
            assert result.returncode == 1 and result.stderr == b'', result
            value = json.loads(result.stdout)
            assert value['result'] == 'failed' and value['phase'] == phase, value
            assert value['pointer'] == pointer and value['field'] == field, value
            assert value['message'] and not value['truncated'], value
            assert set(root.rglob('*')) <= before | {path}, list(root.rglob('*'))
            text = check(document, json_output=False)
            assert text.returncode == 1 and text.stdout == b'', text
            assert field.encode() in text.stderr and phase.encode() in text.stderr, text

        # 语法位置、UTF-8输入与路径截断的机器输出始终是完整UTF-8 JSON。
        result = check('{"x":}')
        assert json.loads(result.stdout)['offset'] == 5, result
        path.write_bytes(b'{"\xff":1}')
        result = subprocess.run([binary, 'check', '-c', str(path), '--json'], capture_output=True, timeout=8)
        assert result.returncode == 1 and json.loads(result.stdout)['pointer'] == '', result
        long_key = '中' * 1500
        result = check({long_key: {}})
        value = json.loads(result.stdout)
        assert value['truncated'] and len(result.stdout) < 16384, value
        assert value['field'].endswith('"]') and '中' in value['field'], value

        # 默认路径检查不创建目录/文件；HOME缺失要求显式路径。
        home = root / 'home'
        env = dict(os.environ, HOME=str(home))
        result = subprocess.run([binary, 'check', '--json'], capture_output=True, env=env, timeout=8)
        assert result.returncode == 1 and json.loads(result.stdout)['phase'] == 'read' and not home.exists(), result
        (home / '.ftun').mkdir(parents=True)
        default = home / '.ftun' / 'config.json'
        default.write_text('{"dns":{"enable":false}}')
        result = subprocess.run([binary, 'check', '--json'], capture_output=True, env=env, timeout=8)
        value = json.loads(result.stdout)
        assert result.returncode == 0 and value['modules'] == ['core'] and not value['startup_only'], value
        env.pop('HOME')
        result = subprocess.run([binary, 'check', '--json'], capture_output=True, env=env, timeout=8)
        assert result.returncode == 1 and 'use -c FILE' in json.loads(result.stdout)['message'], result
        result = check({'dns': {'enable': False}}, env=env)
        assert result.returncode == 1 and json.loads(result.stdout)['pointer'] == '/base/cache-file', result
        assert check({'dns': {'enable': False}, 'base': {'cache-file': str(root / 'cache')},
                      'log': {'file': str(root / 'log')}}, env=env).returncode == 0

        # 已占端口和不可用持久化父目录不影响只读检查；不取得锁或创建身份。
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            document = {'base': {'cache-file': str(root / 'absent' / 'cache')},
                        'log': {'output': 'file', 'file': str(root / 'absent' / 'log')},
                        'dns': {'enable': False}, 'inbounds': [
                            {'type': 'socks5', 'name': 'local', 'listen': f'127.0.0.1:{port}'}],
                        'rules': ['MATCH,DIRECT']}
            result = check(document)
            value = json.loads(result.stdout)
            assert result.returncode == 0 and value['listeners'] == 1 and value['rules'] == 1, value
            assert value['modules'] == ['core', 'proxy'] and not (root / 'absent').exists(), value
            assert 'port permissions and availability' in value['startup_only'], value
            text = check(document, json_output=False)
            assert text.returncode == 0 and b'FRS sets: 0' in text.stdout and text.stderr == b'', text

        # check不发起缺失FRS下载，运行时才可验证远端可达性。
        with socket.socket() as remote:
            remote.bind(('127.0.0.1', 0)); remote.listen(); remote.settimeout(.1)
            result = check({'frs': {'path': str(root / 'absent.frs'), 'auto-update': True,
                                   'url': f'http://127.0.0.1:{remote.getsockname()[1]}/rules.frs'},
                            'rules': ['FRS-IP,CN,DIRECT']})
            assert result.returncode == 1 and json.loads(result.stdout)['phase'] == 'attachments', result
            try:
                connection, _ = remote.accept()
            except socket.timeout:
                pass
            else:
                connection.close()
                raise AssertionError('check attempted an FRS download')

        rules = root / 'rules.frs'
        subprocess.run([fixture, '--write', str(rules)], check=True, capture_output=True, timeout=8)
        result = check({'frs': {'path': str(rules)}, 'rules': ['FRS-IP,CN,DIRECT']})
        value = json.loads(result.stdout)
        assert result.returncode == 0 and value['frs_sets'] > 0 and 'frs' in value['modules'], value
        result = check({'frs': {'path': str(rules)}, 'rules': ['MATCH,DIRECT', 'FRS-IP,missing,DIRECT']})
        value = json.loads(result.stdout)
        assert result.returncode == 1 and value['phase'] == 'attachments' and value['pointer'] == '/rules/1', value
        path.write_text('{"frs":{"path":"broken.frs"},"rules":["FRS-IP,CN,DIRECT"]}')
        (root / 'broken.frs').write_bytes(b'not an FRS file')
        result = subprocess.run([binary, 'check', '-c', str(path), '--json'], capture_output=True, timeout=8)
        assert result.returncode == 1 and json.loads(result.stdout)['pointer'] == '/frs/path', result

        app = Instance(binary, root / 'instance')
        try:
            original = copy.deepcopy(app.config)
            for document, phase, pointer, field in cases[:10]:
                app.path.write_text(document if isinstance(document, str) else json.dumps(document))
                result = app.call('reload')
                assert result['result'] == 'rejected' and result['generation'] == 1, result
                assert (result['phase'], result['pointer'], result['field']) == (phase, pointer, field), result
                app.probe()
            app.config = original; app.write()
            result = app.call('reload')
            assert result['result'] == 'committed' and result['generation'] == 2 and 'field' not in result, result
            app.config['inbounds'][0]['listen'] = '127.0.0.1:1'; app.write()
            result = app.call('reload')
            assert result['result'] == 'restart-required' and result['pointer'] == '/inbounds/0/listen', result
            assert result['generation'] == 2 and app.call('status')['generation'] == 2, result
            app.probe()
            app.config = copy.deepcopy(original); app.config['outbounds'] = [{'type': 'socks5', 'name': 'bad'}]; app.write()
            result = subprocess.run([binary, 'reload', '-p', str(app.pid)], capture_output=True, timeout=8)
            assert result.returncode == 1 and b'outbounds[0].server' in result.stderr and result.stdout == b'', result
            app.path.unlink()
            result = app.call('reload')
            assert result['result'] == 'rejected' and result['phase'] == 'read' and result['pointer'] == '', result
            assert result['file'] == str(app.path), result
        finally:
            app.close()
    print('configuration diagnostics: parse/paths/validate/attachments/restart, read-only summary and reload passed')


if __name__ == '__main__':
    main()

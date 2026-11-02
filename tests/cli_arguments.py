#!/usr/bin/env python3
"""Exercise command grammar, output channels and module trimming on the binary."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--modules', required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    modules = args.modules.split(',')
    count = 0

    with tempfile.TemporaryDirectory(prefix='ftun-cli-arguments-') as directory:
        work = Path(directory)

        def run(command, code, stdout=None, stderr=None):
            nonlocal count
            result = subprocess.run([str(binary), *command], cwd=work,
                                    capture_output=True, text=True, timeout=5)
            assert result.returncode == code, (command, result.returncode, result.stdout, result.stderr)
            if stdout is not None:
                assert stdout in result.stdout, (command, result.stdout)
            if stderr is not None:
                assert stderr in result.stderr, (command, result.stderr)
            if code == 0:
                assert not result.stderr, (command, result.stderr)
            if code == 2:
                assert not result.stdout and result.stderr, (command, result.stdout, result.stderr)
            count += 1
            return result

        run([], 2, stderr='Usage:')
        for command in (['help'], ['--help'], ['-h']):
            help_text = run(command, 0, stdout='Usage:').stdout
            assert 'ftun mesh' not in help_text and 'ftun fakeip' not in help_text
            for module in ('dns', 'proxy'):
                assert (f'ftun {module} ' in help_text) == (module in modules), help_text
        for selector in ('-h', '--help', 'help'):
            run(['help', selector], 0, stdout='ftun help [COMMAND [ACTION]]')
        for command in ('run', 'check', 'stop', 'reload', 'status', 'version'):
            for suffix in ('-h', '--help'):
                run([command, suffix], 0, stdout=f'ftun {command}')
            run(['help', command], 0, stdout=f'ftun {command}')
            run([command, 'help'], 2)
            run([command, '--unknown'], 2)
            run([command, '--help', '--help'], 2)
            run([command, '-hh'], 2)
        for command in ('dns', 'proxy'):
            if command not in modules:
                run([command, 'status'], 1, stderr='not built in this binary')
                run(['help', command], 1, stderr='not built in this binary')
                result = run([command, 'status', '--json'], 1)
                assert not result.stderr and json.loads(result.stdout)['result'] == 'failed'
                run([command, 'status', '--json', '--json'], 2)
                continue
            for suffix in ('help', '-h', '--help'):
                run([command, suffix], 0, stdout=f'ftun {command} status')
            run(['help', command], 0, stdout=f'ftun {command} status')
            run(['help', command, 'status'], 0)
            run([command, 'status', '--json', '-p', 'pid 文件', '-h'], 0)
            run([command, 'status', '123', '--json', '-h'], 0)
            for tail in ([], ['unknown'], ['help', 'extra'], ['status', 'help'],
                         ['status', '123', '-p', 'instance.pid'], ['status', '--timeout', '2']):
                run([command, *tail], 2)
        for options in (['-bv', '-c', '配置 文件.json', '-p', '进程.pid'],
                        ['-v', '--verbose', '--no-color'], ['-vv', '--background'],
                        ['--config=file', '--pidfile=pid', '--no-color']):
            run(['run', *options, '-h'], 0)
        run(['check', '--config=配置.json', '--json', '-h'], 0)
        for command in ('stop', 'reload', 'status'):
            for pid in ('2', '0002', '2147483647'):
                run([command, pid, '--json', '-h'], 0)
                run([command, '--json', pid, '-h'], 0)
            for pid in ('0', '1', '-1', '+2', ' 2', '2 ', '2x', '2.0', '',
                        '2147483648', '999999999999999999999999999999'):
                run([command, '--', pid], 2)
            run([command, '123', '-p', 'pid'], 2, stderr='PID and -p')
            run([command, '-p', 'pid', '123'], 2, stderr='PID and -p')
            run([command, '123', '456'], 2)
            run([command, '--pidfile=pid', '--json', '-h'], 0)
        for command in ('stop', 'reload'):
            for timeout in ('1', '3600', '0002'):
                run([command, '123', '--timeout', timeout, '--no-wait', '-h'], 0)
            for timeout in ('0', '3601', '-1', '1.5', 'nan', '1x', '+1', '', '99999999999999'):
                run([command, '--timeout', timeout], 2)
            run([command, '--timeout=2', '--timeout', '3'], 2)
            run([command, '--no-wait', '--no-wait'], 2)
        for command in (['fakeip', 'init'], ['help', 'fakeip'], ['unknown'], ['mesh'], ['help', 'unknown'], ['help', 'run', 'extra'],
                        ['help', 'dns', 'status', 'extra'],
                        ['run', '-vvv'], ['run', '-c', 'one', '--config=two'],
                        ['run', '-bb'], ['run', '--no-color', '--no-color'],
                        ['run', '--config='], ['check', 'config.json'], ['check', '-c'],
                        ['check', '-c', 'x', '--json', '--json'], ['version', '--modules', '--modules'],
                        ['version', '--json=yes'], ['version', '--config', 'x'],
                        ['status', '--timeout', '1'], ['run', '--json'], ['check', '-b']):
            run(command, 2)
        plain = run(['version'], 0).stdout
        assert plain.startswith('FTUN ') and len(plain.splitlines()) == 1
        assert run(['--version'], 0).stdout == plain
        basic = json.loads(run(['version', '--json'], 0).stdout)
        assert basic == {'result': 'ok', 'version': plain.strip().split()[1]}
        extended = json.loads(run(['version', '--modules', '--json'], 0).stdout)
        assert extended['modules'] == modules and extended['result'] == 'ok'
        assert extended['source'] and extended['target']
        text = run(['version', '--modules'], 0).stdout
        assert 'source: ' + extended['source'] in text
        assert 'target: ' + extended['target'] in text
        assert 'capabilities: ' + args.modules in text
        assert not list(work.iterdir()), 'help/version/invalid arguments must not create files'
    print(f'CLI argument contract: {count} cases; modules={args.modules}')


if __name__ == '__main__':
    main()

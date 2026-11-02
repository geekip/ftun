#!/usr/bin/env python3
"""Exercise actual async stderr/file/both sinks, local time, journald and PTY color."""
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import re
import tempfile
import sys
from ctl_server_product import Instance, wait


STAMP = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} ([+-]\d{4})\]')
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def read_pty(descriptor):
    result = bytearray()
    while True:
        try:
            chunk = os.read(descriptor, 65536)
        except BlockingIOError:
            break
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break  # Linux PTY slave closed: terminal EOF.
        if not chunk:
            break
        result.extend(chunk)
    return result.decode().replace('\r\n', '\n')


def scenario(binary, root, output, *, tty=False, journal=False, no_color=False,
             zone='CST-8', offset='+0800', silent=False, cli_no_color=False):
    log = root.parent / (root.name + '.log')
    config = {'file': str(log)}
    if output is not None:
        config['output'] = output
    if silent:
        config['level'] = 'silent'
    env = dict(os.environ, TZ=zone)
    env.pop('JOURNAL_STREAM', None)
    env.pop('NO_COLOR', None)
    if journal:
        env['JOURNAL_STREAM'] = '1:2'
    if no_color:
        env['NO_COLOR'] = ''  # Presence disables color, including an empty value.
    with ExitStack() as stack:
        master = slave = None
        if tty:
            master, slave = os.openpty()
            stack.callback(os.close, master)
            os.set_blocking(master, False)
        app = Instance(binary, root, initial={'log': config}, env=env, stderr=slave,
                       extra_args=['--no-color'] if cli_no_color else ())
        if slave is not None:
            os.close(slave)
        try:
            captured = read_pty(master) if tty else ''
            state = app.call('status')
            assert state['logs']['level'] == ('silent' if silent else 'info'), state
            assert state['logs']['output'] == ('disabled' if silent else output or 'stderr'), state
            if not silent:
                assert state['logs']['sequence'] >= state['logs']['accepted'] > 0, state
            if cli_no_color:
                assert app.call('reload', boot=app.boot, timeout_ms=3000)['result'] == 'committed'
                if tty:
                    captured += read_pty(master)
            result = app.call('stop', boot=app.boot, timeout_ms=3000)
            assert result['result'] == 'stopped', result
            assert app.process.wait(timeout=5) == 0, app.output.read_text()
            errors = captured + read_pty(master) if tty else app.output.read_text()
            assert errors.count('ftun: ready\n') == 1, errors
            errors = errors.replace('ftun: ready\n', '')
            file = log.read_text() if log.exists() else ''
            if silent:
                assert not errors and not file and not log.exists(), (errors, file)
                return
            file_enabled = output in ('file', 'both')
            error_enabled = output != 'file'
            assert bool(file) == file_enabled and bool(errors) == error_enabled, (output, errors, file)
            assert log.exists() == file_enabled
            assert Path(str(log) + '.lock').exists() == file_enabled
            assert '\x1b' not in file, file
            if file_enabled:
                assert STAMP.match(file).group(1) == offset, file
            if error_enabled:
                assert bool(ANSI.search(errors)) == (tty and not no_color and not cli_no_color), errors
                plain = ANSI.sub('', errors)
                if journal:
                    assert plain.startswith('[app   ][INFO ] starting:'), plain
                    assert not STAMP.search(plain), plain
                else:
                    assert STAMP.match(plain).group(1) == offset, plain
                assert plain.count(' boot=') == 1 and 'seq=' not in plain, plain
                if tty and not no_color and not cli_no_color:
                    assert '[\x1b[32mINFO \x1b[0m]' in errors, errors
            if file_enabled and error_enabled:
                plain = ANSI.sub('', errors)
                if journal:
                    file = '\n'.join(STAMP.sub('', line) for line in file.splitlines()) + '\n'
                assert plain == file, (plain, file)
        finally:
            app.close()


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-log-pipeline-') as directory:
        root = Path(directory)
        cases = [
            (None, {}),
            ('file', {}),
            ('both', {}),
            ('both', {'journal': True}),
            ('stderr', {'tty': True}),
            ('both', {'tty': True, 'journal': True}),
            ('stderr', {'tty': True, 'no_color': True}),
            ('file', {'tty': True}),
            ('stderr', {'tty': True, 'cli_no_color': True}),
            ('stderr', {'zone': 'IST-5:30', 'offset': '+0530'}),
            ('stderr', {'zone': ':/ftun-missing-zoneinfo', 'offset': '+0000'}),
            ('both', {'silent': True}),
        ]
        for index, (output, options) in enumerate(cases):
            scenario(binary, root / str(index), output, **options)
    print('log pipeline: default info/stderr, all sinks, local zones, journald, PTY color and silent passed')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Exercise durable identity publication, refusal and injected startup failures."""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from ctl_server_product import Instance, wait
from fakeip_cidr import configuration, free_port, query, stop


FILES = {'identity', 'reservations', 'mappings', 'lock'}


def contents(directory):
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


def main():
    binary, faulty = [str(Path(arg).resolve()) for arg in sys.argv[1:]]
    with tempfile.TemporaryDirectory(prefix='ftun-fakeip-startup-') as temporary:
        root = Path(temporary)
        cache = root / 'new-parent' / 'state.cache'
        directory = Path(str(cache) + '.fakeip')
        value = configuration('198.18.9.77/24', cache, free_port(), persist=True)
        value['log']['level'] = 'warn'
        path = root / 'check.json'
        path.write_text(json.dumps(value))
        result = subprocess.run([binary, 'check', '-c', str(path), '--json'], capture_output=True, timeout=8)
        assert result.returncode == 0 and not cache.parent.exists(), result
        assert 'FakeIP state will be created on first run' in json.loads(result.stdout)['startup_only'], result
        app = Instance(binary, root / 'first', initial=value)
        try:
            wait(lambda: 'identity created:' in app.output.read_text(), app.output.read_text)
            text = app.output.read_text()
            assert re.search(r'\[fakeip\]\[WARN \] identity created:.*range=198\.18\.9\.77/24 uuid=[0-9a-f]{8} path=', text), text
            assert str(directory) in text, text
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            assert set(p.name for p in directory.iterdir()) == FILES
            assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in directory.iterdir())
            identity = (directory / 'identity').read_bytes()
            assert identity[:4] == b'FTFI' and identity[14] & 0xf0 == 0x40 and identity[16] & 0xc0 == 0x80
            listener = int(app.config['dns']['listeners'][0]['listen'].rsplit(':', 1)[1])
            assert query(listener, 'remember') == '198.18.9.1'
            assert app.call('reload')['result'] == 'committed'
            assert app.output.read_text().count('identity created:') == 1
            stop(app)
            template = app.config
        finally:
            app.close()
        app = Instance(binary, root / 'restart', initial=template)
        try:
            assert (directory / 'identity').read_bytes() == identity
            assert query(listener, 'remember') == '198.18.9.1'
            assert 'identity created:' not in app.output.read_text()
            stop(app)
        finally:
            app.close()
        assert not list(cache.parent.glob('.ftun.fakeip.*'))
        baseline = root / 'baseline'
        shutil.copytree(directory, baseline)

        def reject(name, change, expected=3):
            cache_path = root / name
            state = Path(str(cache_path) + '.fakeip')
            shutil.copytree(baseline, state)
            change(state)
            before = contents(state)
            document = json.loads(json.dumps(template))
            document['base']['cache-file'] = str(cache_path)
            cfg, pid = root / (name + '.json'), root / (name + '.pid')
            cfg.write_text(json.dumps(document))
            result = subprocess.run([binary, 'run', '-c', str(cfg), '-p', str(pid)], capture_output=True, timeout=12)
            assert result.returncode == expected, result
            assert b'ftun: ready' not in result.stderr and b'ftun: run: fakeip commit failed:' in result.stderr, result
            assert str(state).encode() in result.stderr and contents(state) == before, result
            assert not pid.exists() and not pid.with_suffix('.sock').exists()

        for name in sorted(FILES):
            reject('missing-' + name, lambda directory, name=name: (directory / name).unlink())
        for name in sorted(FILES - {'lock'}):
            reject('corrupt-' + name, lambda directory, name=name: (directory / name).write_bytes(b'broken'))
        lock_cache = root / 'locked'
        lock_dir = Path(str(lock_cache) + '.fakeip')
        shutil.copytree(baseline, lock_dir)
        with (lock_dir / 'lock').open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            config = json.loads(json.dumps(template))
            config['base']['cache-file'] = str(lock_cache)
            path.write_text(json.dumps(config))
            before = contents(lock_dir)
            result = subprocess.run([binary, 'run', '-c', str(path), '-p', str(root / 'locked.pid')], capture_output=True, timeout=12)
            assert result.returncode == 1 and b'fakeip commit failed: again' in result.stderr, result
            assert contents(lock_dir) == before

        # 缺失目录以外的目录项均拒绝；悬空链接不能被解释为首次创建。
        for kind in ('file', 'symlink', 'empty'):
            config = json.loads(json.dumps(template))
            cache_path = root / ('wrong-' + kind)
            state = Path(str(cache_path) + '.fakeip')
            if kind == 'file':
                state.write_bytes(b'keep')
            elif kind == 'symlink':
                state.symlink_to('absent')
            else:
                state.mkdir()
            config['base']['cache-file'] = str(cache_path)
            path.write_text(json.dumps(config))
            result = subprocess.run([binary, 'run', '-c', str(path), '-p', str(root / 'wrong.pid')], capture_output=True, timeout=12)
            assert result.returncode == 3 and b'fakeip commit failed: state-corrupt' in result.stderr, result
            assert (state.is_symlink() if kind == 'symlink' else state.exists())
            if kind == 'empty':
                assert not list(state.iterdir())

        for fault in ('random', 'identity', 'reservations', 'mappings', 'lock', 'temp-synced', 'renamed', 'dir-synced', 'occupied'):
            cache_path = root / ('fault-' + fault)
            state = Path(str(cache_path) + '.fakeip')
            document = json.loads(json.dumps(template))
            document['base']['cache-file'] = str(cache_path)
            document['log']['level'] = 'silent'
            path.write_text(json.dumps(document))
            pid = root / ('fault-' + fault + '.pid')
            result = subprocess.run([faulty, 'run', '-c', str(path), '-p', str(pid)], capture_output=True,
                env=dict(os.environ, FTUN_TEST_FAKEIP_FAULT=fault), timeout=12)
            assert result.returncode == 1 and b'ftun: run: fakeip commit failed:' in result.stderr, (fault, result)
            assert b'ftun: ready' not in result.stderr and str(state).encode() in result.stderr, (fault, result)
            assert not list(root.glob('.ftun.fakeip.*')) and not pid.exists() and not pid.with_suffix('.sock').exists()
            if fault in ('renamed', 'dir-synced'):
                assert set(p.name for p in state.iterdir()) == FILES
                original = (state / 'identity').read_bytes()
                app = Instance(binary, root / ('resume-' + fault), initial=document)
                try:
                    assert (state / 'identity').read_bytes() == original
                    stop(app)
                finally:
                    app.close()
            elif fault == 'occupied':
                assert state.is_dir() and not list(state.iterdir())
            else:
                assert not state.exists(), fault
        result = subprocess.run([binary, 'fakeip', 'init', '-c', str(path)], capture_output=True, timeout=8)
        assert result.returncode == 2 and b'unknown command' in result.stderr, result
    print('FakeIP startup: first creation, warning, readonly check, identity/mapping restart, corruption/lock refusal and 9 failure boundaries passed')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""无HOME环境下验证真实CLI和三份服务样例的路径说明。"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = str(Path(sys.argv[1]).resolve())
    project = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env.pop('HOME', None)
    with tempfile.TemporaryDirectory(prefix='ftun-service-paths-') as directory:
        config = Path(directory) / 'config.json'
        unused = {'base': {'state-cache': False}, 'dns': {'enable': False}}

        def check(document, expected, field=None):
            config.write_text(json.dumps(document))
            done = subprocess.run([binary, 'check', '-c', str(config), '--json'],
                                  env=env, capture_output=True, text=True, timeout=5)
            assert done.returncode == expected, (document, done)
            if field:
                assert field in done.stdout, done

        check(unused, 0)
        check(dict(unused, base={'state-cache': True}), 1, '/base/cache-file')
        check(dict(unused, log={'output': 'file'}), 1, '/log/file')
        for path in ('systemd/ftun.service', 'openwrt/ftun.procd', 'padavan/ftun.sh'):
            source = (project / 'packaging' / path).read_text()
            example, = [json.loads(line[2:]) for line in source.splitlines() if line.startswith('# {')]
            assert Path(example['base']['cache-file']).is_absolute()
            assert Path(example['log']['file']).is_absolute()
            check(dict(example, dns={'enable': False}), 0)
        assert sorted(p.name for p in config.parent.iterdir()) == ['config.json']
    print('No-HOME CLI paths and systemd/OpenWrt/Padavan examples passed')


if __name__ == '__main__':
    main()

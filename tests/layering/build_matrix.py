#!/usr/bin/env python3
"""构建并检查已有业务的裁剪组合，不改变宿主网络。"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

MODULES = ['PROXY', 'DNS', 'FAKEIP', 'TUN', 'FRS']
PROFILES = {
    'core-layer': set(), 'dns-only': {'DNS'}, 'proxy-socket': {'PROXY'},
    'builtin': set(MODULES), 'proxy-tun': {'PROXY', 'TUN'},
    'builtin-no-tun': {'PROXY', 'DNS', 'FAKEIP', 'FRS'},
}

def run(command):
    result = subprocess.run([str(c) for c in command], text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(' '.join(map(str, command)) + '\n' + result.stdout + result.stderr)
    return result.stdout

def main():
    parser = argparse.ArgumentParser()
    for name in ['source', 'build', 'cmake', 'compiler', 'generator']:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    root = Path(args.source).resolve()
    for profile, enabled in PROFILES.items():
        build = Path(args.build) / profile
        flags = [f'-DFTUN_MODULE_{m}=' + ('BUILTIN' if m in enabled else 'OFF') for m in MODULES]
        configure = [args.cmake, '-S', root, '-B', build, '-G', args.generator,
            '-DCMAKE_C_COMPILER=' + args.compiler, '-DCMAKE_BUILD_TYPE=Debug',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DBUILD_TESTING=ON']
        run(configure + flags)
        run([args.cmake, '--build', build, '--target', 'ftun', 'ftun-build-modules-test', '--parallel', '4'])
        if profile == 'dns-only':
            run([args.cmake, '--build', build, '--parallel', '4'])
        run([build / 'ftun-build-modules-test'])
        manifest = dict(line.split('=', 1) for line in (build / 'ftun-build-modules.txt').read_text().splitlines())
        for module in MODULES:
            assert manifest[module.lower()] == ('BUILTIN' if module in enabled else 'OFF'), profile
        symbols = run(['nm', '--defined-only', build / 'ftun'])
        if 'PROXY' not in enabled:
            assert ' ftun_proxy_' not in symbols and ' ftun_runtime_prepare' not in symbols, profile
            assert ' wolfSSL_' not in symbols, profile
            assert 'socks5' not in symbols.lower(), profile
        if 'TUN' not in enabled:
            assert ' ftun_packet_port_open' not in symbols and ' ftun_lwip_' not in symbols, profile
        run([sys.executable, root / 'tests/layering/include_policy.py', root,
            build / 'compile_commands.json', build / 'ftun-build-targets.txt'])
        config = build / 'matrix.json'
        config.write_text(json.dumps({'dns': {'enable': False}}))
        run([build / 'ftun', 'check', '-c', config])
        print(profile + ': passed', flush=True)
    # 原生kqueue只在Darwin编译；Linux不能选择伪后端通过编译检查。
    build = Path(args.build) / 'kqueue-compile'
    result = subprocess.run([args.cmake, '-S', root, '-B', build,
        '-DFTUN_POLLER_BACKEND=kqueue'], capture_output=True, text=True)
    assert result.returncode and 'unavailable on Linux' in result.stderr
    print('Linux kqueue override: rejected', flush=True)
    invalid = Path(args.build) / 'invalid'
    result = subprocess.run([args.cmake, '-S', root, '-B', invalid,
        '-DFTUN_MODULE_PROXY=OFF', '-DFTUN_MODULE_DNS=OFF', '-DFTUN_MODULE_FAKEIP=BUILTIN'], capture_output=True, text=True)
    assert result.returncode and 'requires' in result.stderr
    print('invalid dependency: rejected')

if __name__ == '__main__':
    main()

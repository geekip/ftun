#!/usr/bin/env python3
"""检查真实编译目标的源码归属和头文件可见性。"""
import argparse
import json
from pathlib import Path
import re
import shlex

LOWER = {'util': set(), 'platform': {'util'}, 'core': {'platform', 'util'}}
LIBS = {'buffer', 'transport', 'resolver', 'tls', 'tun', 'http', 'crypto'}

def owner(path):
    parts = Path(path).parts
    return '/'.join(parts[:2]) if parts[0] == 'libs' else parts[0]

def target(layer):
    return 'ftun_' + layer.replace('libs/', 'lib_')

def allowed(layer, dependency):
    if layer == dependency or layer == 'app':
        return True
    if layer in LOWER:
        return dependency in LOWER[layer]
    return dependency in {'core', 'platform', 'util'} or dependency.startswith('libs/')

def check_include(layer, header):
    if layer != 'platform' and re.match(r'platform/(linux|posix|bsd|darwin|windows)/', header):
        return False
    return allowed(layer, owner(header))

def direct_thread_api(layer, source):
    return layer != 'platform' and bool(re.search(
        r'#\s*include\s*<pthread\.h>|\bpthread_\w+', source))

def direct_atomic_api(layer, source):
    return layer != 'platform' and bool(re.search(
        r'#\s*include\s*<stdatomic\.h>|\b_Atomic\b|\batomic_\w+', source))

def direct_system_header(layer, source):
    return layer != 'platform' and bool(re.search(
        r'#\s*include\s*<(?:windows\.h|winsock2\.h|ws2tcpip\.h|io\.h|pthread\.h|stdatomic\.h|time\.h|sys/[^>]+|unistd\.h|fcntl\.h|signal\.h|poll\.h|sched\.h|pwd\.h|(?:arpa|net|netinet|linux)/[^>]+)>', source))

def audit(root, database):
    errors, seen, graph = [], set(), {}
    for entry in database:
        path = Path(entry['file']).resolve()
        if not path.is_relative_to(root / 'src'):
            continue
        arguments = entry.get('arguments') or shlex.split(entry['command'])
        match = re.search(r'CMakeFiles/([^/]+)\.dir/', ' '.join(arguments))
        if match is None:
            errors.append(f'unknown compile target: {path}')
            continue
        actual = match[1]
        if actual != 'ftun' and not actual.startswith(('ftun_core', 'ftun_util', 'ftun_platform', 'ftun_lib_', 'ftun_app', 'ftun_proxy', 'ftun_dns')):
            continue  # 测试夹具单独编译 main 等入口。
        relative = path.relative_to(root / 'src')
        layer = owner(relative)
        expected = 'ftun' if str(relative) == 'app/main.c' else target(layer)
        for config_layer in ['app', 'dns', 'proxy']:
            if relative.as_posix().startswith(config_layer + '/config/'):
                expected = 'ftun_' + config_layer + '_config'
        if relative.as_posix().startswith('proxy/protocol/'):
            expected = 'ftun_proxy_protocol'
        if relative.as_posix().startswith('libs/tun/config/'):
            expected = 'ftun_lib_tun_config'
        if actual != expected:
            errors.append(f'{relative}: compiled by {actual}, expected {expected}')
        seen.add(relative.as_posix())
        graph.setdefault(layer, set())
        if (layer != 'app' or actual == 'ftun_app_config') and any(arg == '-I' + str(root / 'src') for arg in arguments):
            errors.append(f'{actual}: unrestricted src include path')
    for path in sorted((root / 'src').rglob('*')):
        if path.suffix not in {'.c', '.h'}:
            continue
        relative = path.relative_to(root / 'src')
        layer = owner(relative)
        if direct_system_header(layer, path.read_text()):
            errors.append(f'{relative}: native OS and atomic headers belong to platform')
        if direct_thread_api(layer, path.read_text()):
            errors.append(f'{relative}: native thread API belongs to platform/thread')
        if direct_atomic_api(layer, path.read_text()):
            errors.append(f'{relative}: native atomic API belongs to platform/atomic')
        if layer == 'core' and re.search(r'\bFTUN_BUILD_MODULE_\w+', path.read_text()):
            errors.append(f'{relative}: host module capabilities do not belong to Core')
        for number, header in enumerate(re.findall(r'^\s*#\s*include\s+"([^"]+)"', path.read_text(), re.M), 1):
            if not (root / 'src' / header).is_file():
                if header.startswith('ftun/') or '/' not in header:
                    continue
                errors.append(f'{relative}: missing internal include {header}')
                continue
            dependency = owner(header)
            if not check_include(layer, header):
                errors.append(f'{relative}: forbidden {header}')
            if dependency != layer:
                graph.setdefault(layer, set()).add(dependency)
    def visit(layer, trail):
        if layer in trail:
            errors.append('layer cycle: ' + ' -> '.join((*trail, layer)))
            return
        for dependency in graph.get(layer, ()):
            visit(dependency, (*trail, layer))
    for layer in graph:
        visit(layer, ())
    return errors, seen

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('commands', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--self-test', choices=['illegal-include', 'illegal-source'])
    args = parser.parse_args()
    root = args.root.resolve()
    errors, seen = audit(root, json.loads(args.commands.read_text()))
    if args.self_test == 'illegal-include':
        for layer in ['core', 'libs/tun', 'dns', 'proxy', 'app']:
            assert not check_include(layer, 'platform/linux/route.h')
            assert not check_include(layer, 'platform/posix/error.h')
            assert not check_include(layer, 'platform/bsd/poller.h')
            assert not check_include(layer, 'platform/windows/thread_types.h')
            assert not check_include(layer, 'platform/darwin/process.h')
            assert check_include(layer, 'platform/route.h')
        assert not check_include('core', 'proxy/runtime.h')
        assert not check_include('dns', 'proxy/runtime.h')
        assert not check_include('platform', 'core/limits.h')
        assert direct_thread_api('core', '#include <pthread.h>')
        assert direct_thread_api('libs/tls', 'pthread_mutex_lock(&mutex);')
        assert direct_thread_api('app', 'pthread_mutex_trylock(&mutex);')
        assert direct_atomic_api('app', '_Atomic uint64_t request;')
        assert not direct_atomic_api('app', 'ftun_atomic_load(&request);')
        assert not direct_thread_api('platform', 'pthread_mutex_lock(&mutex);')
        assert direct_system_header('core', '#include <windows.h>')
        assert direct_system_header('proxy', '#include <winsock2.h>')
        assert direct_system_header('core', '#include <sys/stat.h>')
        assert direct_system_header('core', '#include <stdatomic.h>')
        assert not direct_system_header('core', '#include <stdint.h>')
        assert direct_system_header('dns', '#include <sys/socket.h>')
        assert direct_system_header('proxy', '#include <netinet/in.h>')
        assert not direct_system_header('platform', '#include <sys/stat.h>')
    if args.self_test == 'illegal-source':
        assert target(owner('core/context.c')) != 'ftun_proxy'
        mutated = json.loads(args.commands.read_text())
        entry = next(e for e in mutated if '/src/core/context.c' in e['file'])
        entry['command'] = entry['command'].replace('ftun_core.dir', 'ftun_proxy.dir')
        detected, _ = audit(root, mutated)
        assert any('expected ftun_core' in error for error in detected)
    manifest = dict(line.split('=', 1) for line in args.manifest.read_text().splitlines())
    assert manifest['core'] == 'ftun_core' and manifest['app'] == 'ftun_app'
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'layer boundaries: ok ({len(seen)} compiled product sources)')

if __name__ == '__main__':
    main()

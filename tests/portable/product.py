#!/usr/bin/env python3
"""各原生平台及QEMU/Wine共用的真实CLI、IPv4/IPv6、DNS和代理冒烟。"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fakeip_cidr import configuration as fakeip_configuration, query as fakeip_query
from ipv6_product import (TCP, TCP6, UDP, UDP6, DNS, EchoTCP, EchoUDP,
                          serving, socks, datagram, connect_http, exact)


def wait_for(predicate, process, log, timeout=20):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert process.poll() is None, log.read_text(errors='replace')
        assert time.monotonic() < deadline, log.read_text(errors='replace')
        time.sleep(.02)


def listening(address):
    try:
        with socket.create_connection(address, timeout=.1):
            return True
    except (ConnectionRefusedError, TimeoutError):
        return False


def free_port(host):
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as reserve:
        reserve.bind((host, 0))
        return reserve.getsockname()[1]


def query(address, tcp, kind):
    name = b'\x04dual\x04test\0'
    wire = b'\x12\x34' + struct.pack('!HHHHH', 0x100, 1, 0, 0, 0) + name + struct.pack('!HH', kind, 1)
    if tcp:
        with socket.create_connection(address, timeout=5) as channel:
            channel.sendall(struct.pack('!H', len(wire)) + wire)
            answer = exact(channel, struct.unpack('!H', exact(channel, 2))[0])
    else:
        family = socket.AF_INET6 if ':' in address[0] else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as channel:
            channel.settimeout(5)
            channel.sendto(wire, address)
            answer, _ = channel.recvfrom(4096)
    expected = socket.inet_pton(socket.AF_INET6 if kind == 28 else socket.AF_INET, '::1' if kind == 28 else '127.0.0.1')
    assert answer[:2] == b'\x12\x34' and answer[3] & 15 == 0 and answer.endswith(expected), answer.hex()


def persistent_fakeip(runner, binary, host_binary):
    with tempfile.TemporaryDirectory(prefix='ftun-portable-fakeip-') as directory:
        root = Path(directory)
        listener = free_port('127.0.0.1')
        config = fakeip_configuration('198.18.11.97/24', Path('state.cache'), listener, persist=True)
        config['log']['level'] = 'warn'
        config['inbounds'] = [{'type': 'socks5', 'name': 'local', 'listen': f'127.0.0.1:{free_port("127.0.0.1")}'}]
        config['rules'] = ['MATCH,DIRECT']
        (root / 'config.json').write_text(json.dumps(config))
        state = root / 'state.cache.fakeip'
        original = None
        for index in range(2):
            log = root / f'run-{index}.log'
            with log.open('wb') as output:
                process = subprocess.Popen(runner + [host_binary, 'run', '-c', 'config.json', '-p', 'instance.pid'],
                    cwd=root, stdout=output, stderr=output)
                try:
                    wait_for(lambda: 'ftun: ready' in log.read_text(errors='replace'), process, log)
                    text = log.read_text(errors='replace')
                    identity = (state / 'identity').read_bytes()
                    if original is None:
                        original = identity
                        assert text.count('identity created:') == 1, text
                    else:
                        assert identity == original and 'identity created:' not in text, text
                    assert fakeip_query(listener, 'persistent') == '198.18.11.1'
                    pid = re.search(r'process-id: (\d+)', text).group(1)
                    subprocess.run(runner + [binary, 'stop', pid], cwd=root, check=True, timeout=30)
                    assert process.wait(timeout=20) == 0, log.read_text(errors='replace')
                    assert not (root / 'instance.pid').exists()
                except BaseException:
                    print(log.read_text(errors='replace'), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
        (state / 'identity').write_bytes(b'broken')
        with (root / 'rejected.log').open('wb') as output:
            result = subprocess.run(runner + [binary, 'run', '-c', 'config.json', '-p', 'instance.pid'],
                cwd=root, stdout=output, stderr=output, timeout=30)
        assert result.returncode == 3 and 'fakeip commit failed: state-corrupt' in (root / 'rejected.log').read_text()
        assert (state / 'identity').read_bytes() == b'broken' and not (root / 'instance.pid').exists()
        assert not list(root.glob('.ftun.fakeip.*'))
    print('portable FakeIP: automatic identity creation, mapping/UUID restart and corruption refusal passed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('--runner', default='[]', help='JSON argv prefix, e.g. ["qemu-arm"]')
    args = parser.parse_args()
    runner = json.loads(args.runner)
    build = args.build.resolve()
    suffix = '.exe' if (build / 'ftun.exe').is_file() else ''
    binary = str(build / ('ftun' + suffix))
    host_binary = str(build / ('ftun-platform-test' + suffix))
    version = subprocess.check_output(runner + [binary, 'version', '--modules'], text=True, timeout=60)
    assert 'FTUN 1.1.0' in version and 'proxy,dns,fakeip' in version, version
    with tempfile.TemporaryDirectory(prefix='ftun-portable-check-') as directory:
        path = Path(directory) / 'config.json'
        for document, pointer in [({'dns': {'enable': False}}, None),
                                  ({'outbounds': [{'type': 'socks5', 'name': 'a'}]}, '/outbounds/0/server'),
                                  ({'dns': {'servers': [{'type': 'udp', 'name': 'up', 'address': ['bad_domain:53']}]}},
                                   '/dns/servers/0/address/0')]:
            path.write_text(json.dumps(document))
            # 普通文件由最终可执行程序验证；Windows另用Win32 CreatePipe宿主验证管道。
            with (Path(directory) / 'result.json').open('wb') as output:
                result = subprocess.run(runner + [binary, 'check', '-c', path.name, '--json'],
                                        cwd=directory, stdout=output, stderr=subprocess.PIPE, timeout=60)
            value = json.loads((Path(directory) / 'result.json').read_text())
            if suffix:
                piped = subprocess.run(runner + [host_binary, 'cli-pipe', 'check', '-c', path.name, '--json'],
                                       cwd=directory, capture_output=True, text=True, timeout=60)
                assert piped.returncode == result.returncode and json.loads(piped.stdout) == value, piped
            if pointer is None:
                assert result.returncode == 0 and value['result'] == 'ok' and value['modules'] == ['core'], value
                assert value['listeners'] == value['rules'] == value['frs_sets'] == 0, value
            else:
                assert result.returncode == 1 and value['pointer'] == pointer and value['message'], value
        assert sorted(item.name for item in Path(directory).iterdir()) == ['config.json', 'result.json']
    subprocess.run(runner + [host_binary], check=True, timeout=60)
    if suffix:
        subprocess.run(runner + [str(build / 'ftun-wepoll-test.exe'), '--creation-failures'], check=True, timeout=60)
        subprocess.run(runner + [str(build / 'ftun-wepoll-test.exe')], check=True, timeout=60)
        if (build / 'ftun-wintun-test.exe').exists():
            subprocess.run(runner + [str(build / 'ftun-wintun-test.exe')], check=True, timeout=60)
            with tempfile.TemporaryDirectory(prefix='ftun-dll-path-') as directory:
                isolated = Path(directory) / 'isolated'
                isolated.mkdir()
                test = isolated / 'ftun-wintun-test.exe'
                shutil.copyfile(build / test.name, test)
                shutil.copyfile(build / 'wintun.dll', Path(directory) / 'wintun.dll')
                subprocess.run(runner + [str(test), 'missing-dll'], cwd=directory, check=True, timeout=60)
            with tempfile.TemporaryDirectory(prefix='ftun-wintun-config-') as directory:
                path = Path(directory) / 'config.json'
                config = {'base': {'state-cache': False, 'ipv6': True}, 'dns': {'enable': False},
                          'tun': {'interface': 'ftun-check', 'mtu': 1500,
                                  'ipv4': {'address': '172.31.255.1/30'},
                                  'ipv6': {'address': 'fd00:ffff::1/126'}, 'auto-route': False},
                          'inbounds': [{'name': 'tun', 'type': 'tun', 'dns-hijack': False}],
                          'rules': ['MATCH,DIRECT']}
                path.write_text(json.dumps(config))
                # 相对配置路径适用于原生 Windows 和 Wine。
                subprocess.run(runner + [binary, 'check', '-c', path.name], cwd=directory, check=True, timeout=60)
                config['tun']['auto-route'] = True
                path.write_text(json.dumps(config))
                with (Path(directory) / 'error.txt').open('wb') as error_output:
                    rejected = subprocess.run(runner + [binary, 'check', '-c', path.name], cwd=directory,
                                              stdout=subprocess.PIPE, stderr=error_output, timeout=60)
                assert rejected.returncode != 0 and 'unsupported' in (Path(directory) / 'error.txt').read_text(), rejected
                piped = subprocess.run(runner + [host_binary, 'cli-pipe', 'check', '-c', path.name], cwd=directory,
                                       capture_output=True, text=True, timeout=60)
                assert piped.returncode == 1 and 'unsupported' in piped.stdout, piped

        if suffix:
            with tempfile.TemporaryDirectory(prefix='ftun-background-unsupported-') as background_directory:
                error_path = Path(background_directory) / 'error.txt'
                with error_path.open('wb') as output:
                    rejected = subprocess.run(runner + [binary, 'run', '-b'], cwd=background_directory,
                        stdout=subprocess.DEVNULL, stderr=output, timeout=60)
                assert rejected.returncode == 1 and 'unsupported' in error_path.read_text(), rejected

        with subprocess.Popen(runner + [host_binary, 'pipe'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as pipe:
            try:
                assert pipe.wait(timeout=20) == 0, pipe.stderr.read().decode(errors='replace')
            finally:
                if pipe.poll() is None:
                    pipe.kill()
                    pipe.wait()
    tls_binary = str(build / ('ftun-platform-tls-test' + suffix))
    subprocess.run(runner + [tls_binary], cwd=Path(__file__).resolve().parents[2], check=True, timeout=60)
    # 配置使用cwd相对路径，Windows/Wine无需将Unix绝对路径当成Windows路径。
    with tempfile.TemporaryDirectory(prefix='ftun-portable-') as directory, ExitStack() as stack:
        root = Path(directory)
        upstream = stack.enter_context(serving(UDP, DNS, '127.0.0.1'))
        echo4 = stack.enter_context(serving(TCP, EchoTCP, '127.0.0.1'))
        echo6 = stack.enter_context(serving(TCP6, EchoTCP, '::1'))
        udp4 = stack.enter_context(serving(UDP, EchoUDP, '127.0.0.1'))
        udp6 = stack.enter_context(serving(UDP6, EchoUDP, '::1'))
        proxy_ports = [free_port('127.0.0.1'), free_port('::1')]
        dns_port = free_port('127.0.0.1')
        config = {
            'base': {'ipv6': True, 'state-cache': False},
            'log': {'level': 'debug'},
            'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                    'bootstrap': [f'127.0.0.1:{upstream.server_address[1]}'],
                    'listeners': [{'listen': f'127.0.0.1:{dns_port}', 'server': 'real'}],
                    'default-server': 'real', 'servers': [{'name': 'real', 'type': 'udp',
                        'address': [f'127.0.0.1:{upstream.server_address[1]}'], 'outbound': 'DIRECT'}]},
            'inbounds': [{'name': f'in{i}', 'type': 'mixed', 'listen': listen, 'udp': True}
                         for i, listen in enumerate([f'127.0.0.1:{proxy_ports[0]}', f'[::1]:{proxy_ports[1]}'])],
            'rules': ['MATCH,DIRECT']}
        path, log = root / 'config.json', root / 'run.log'
        path.write_text(json.dumps(config), encoding='utf-8')
        subprocess.run(runner + [binary, 'check', '-c', 'config.json'], cwd=root, check=True, timeout=60)
        with log.open('w') as output:
            process = subprocess.Popen(runner + [host_binary, 'run', '-c', 'config.json', '-p', 'instance.pid'], cwd=root,
                                       stdout=output, stderr=output)
            try:
                clients = [('127.0.0.1', proxy_ports[0]), ('::1', proxy_ports[1])]
                wait_for(lambda: all(listening(c) for c in clients), process, log)
                text = log.read_text(errors='replace')
                pid = re.search(r'process-id: (\d+)', text).group(1)
                for client in clients:
                    socks(client, '127.0.0.1', echo4.server_address[1])
                    socks(client, '::1', echo6.server_address[1])
                    socks(client, 'dual.test', echo4.server_address[1], domain=True)
                    datagram(client, '127.0.0.1', udp4.server_address[1])
                    datagram(client, '::1', udp6.server_address[1])
                    connect_http(client, echo6.server_address[1])
                for tcp in (False, True):
                    for kind in (1, 28):
                        query(('127.0.0.1', dns_port), tcp, kind)
                # 无效重载保持旧代可用，然后提交拒绝规则验证代次切换。
                path.write_text('{', encoding='utf-8')
                result = subprocess.run(runner + [binary, 'reload', pid], cwd=root, timeout=30)
                assert result.returncode == 5, result.returncode
                wait_for(lambda: 'reload rejected' in log.read_text(errors='replace'), process, log)
                socks(clients[0], '127.0.0.1', echo4.server_address[1])
                config['rules'] = ['MATCH,REJECT']
                path.write_text(json.dumps(config), encoding='utf-8')
                result = subprocess.run(runner + [binary, 'reload', pid], cwd=root, timeout=30)
                assert result.returncode == 5, result.returncode
                wait_for(lambda: 'reload committed' in log.read_text(errors='replace'), process, log)
                socks(clients[0], '127.0.0.1', echo4.server_address[1], denied=True)
                subprocess.run(runner + [binary, 'stop', pid], cwd=root, check=True, timeout=30)
                assert process.wait(timeout=20) == 0, log.read_text(errors='replace')
            except BaseException:
                print(log.read_text(errors='replace'), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    persistent_fakeip(runner, binary, host_binary)
    print('portable product: IPv4/IPv6 TCP/UDP, SOCKS5/HTTP, DNS A/AAAA UDP/TCP, reload/stop passed')


if __name__ == '__main__':
    main()

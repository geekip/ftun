#!/usr/bin/env python3
"""离线代理域名不能阻断启动/重载；解析恢复、请求取消仍受同一期限约束。"""
from contextlib import ExitStack
from pathlib import Path
import errno
import json
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import time

from control_dns_production import SOCKS, serving as proxy_server
from dns_failover_product import ask, free_ports
from ipv6_product import TCP, TCP6, UDP, EchoTCP, serving, socks, exact


class Bootstrap(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        self.server.queries.append(query)
        if self.server.mode == 'silent':
            return
        kind = struct.unpack('!H', query[-4:-2])[0]
        ready = self.server.mode == 'ready'
        family = 28 if self.server.ipv6_proxy else 1
        address = (socket.inet_pton(socket.AF_INET6, '::1') if family == 28
                   else socket.inet_aton('127.0.0.1')) if ready and kind == family else b''
        flags = 0x8180 if ready else 0x8183
        response = query[:2] + struct.pack('!HHHHH', flags, 1, int(bool(address)), 0, 0) + query[12:]
        if address:
            response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(address)) + address
        sock.sendto(response, self.client_address)


def wait(process, predicate, log, seconds=3):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert process.poll() is None, log.read_text()
        assert time.monotonic() < deadline, log.read_text()
        time.sleep(.01)


def query_dns(port, ident, tcp):
    if not tcp:
        return ask(port, ident)
    wire = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + b'\x07example\x03com\0\0\1\0\1'
    started = time.monotonic()
    with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
        client.sendall(struct.pack('!H', len(wire)) + wire)
        size = struct.unpack('!H', exact(client, 2))[0]
        return exact(client, size), time.monotonic() - started


def run(binary, ipv6, transport, ipv6_proxy=False):
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix='ftun-egress-') as directory:
        root = Path(directory)
        bootstrap = stack.enter_context(serving(UDP, Bootstrap, '127.0.0.1'))
        bootstrap.mode = 'offline'
        bootstrap.ipv6_proxy = ipv6_proxy
        if ipv6_proxy:
            proxy = stack.enter_context(serving(TCP6, SOCKS, '::1'))
            proxy.mode, proxy.auth, proxy.targets, proxy.errors = 'ok', False, [], []
        else:
            proxy = stack.enter_context(proxy_server(SOCKS))
        echo = stack.enter_context(serving(TCP, EchoTCP, '127.0.0.1'))
        # 入站使用TCP，必须预留TCP端口；UDP空闲不能证明同号TCP空闲。
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            inbound = reserve.getsockname()[1]
            _, _, listener = free_ports()
        nodes = [{'name': f'proxy{i}', 'type': 'socks5', 'udp': True,
                  'server': f'proxy{i}.test:{proxy.server_address[1]}'} for i in range(8)]
        config = {'base': {'ipv6': ipv6, 'state-cache': False},
                  'log': {'level': 'debug', 'file': str(root / 'run.log')},
                  'inbounds': [{'name': 'in', 'type': 'socks5', 'udp': False, 'listen': f'127.0.0.1:{inbound}'}],
                  'outbounds': nodes, 'rules': ['MATCH,DIRECT'],
                  'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                          'bootstrap': [f'127.0.0.1:{bootstrap.server_address[1]}'],
                          'default-server': 'dns0',
                          'listeners': [{'listen': f'127.0.0.1:{listener}', 'server': 'dns0'}],
                          'servers': [{'name': f'dns{i}', 'type': transport, 'outbound': f'proxy{i}',
                                       'address': ['127.0.0.1:53']} for i in range(8)]}}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        checked = subprocess.run([binary, 'check', '-c', str(path)], capture_output=True, timeout=3)
        assert checked.returncode == 0, checked.stderr
        log = root / 'run.log'
        with (root / 'stderr').open('w') as output:
            started = time.monotonic()
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=output, stderr=output)
            try:
                def listening():
                    try:
                        with socket.create_connection(('127.0.0.1', inbound), timeout=.1):
                            return True
                    except ConnectionRefusedError:
                        return False
                wait(process, listening, log)
                assert time.monotonic() - started < 2
                assert not bootstrap.queries, 'configuration preparation performed DNS I/O'
                # 无关SOCKS直连业务不被域名出口故障牵连。
                socks(('127.0.0.1', inbound), '127.0.0.1', echo.server_address[1])
                response, _ = query_dns(listener, 1, transport == "tcp")
                assert response[3] & 15 == 2, response  # SERVFAIL
                assert bootstrap.queries and not proxy.targets
                bootstrap.mode = 'ready'
                # 新请求自动恢复，不重启、不重载，不依赖后台重试。
                deadline = time.monotonic() + 6
                while True:
                    response, _ = query_dns(listener, 2, transport == "tcp")
                    if response[3] & 15 == 0:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.05)  # 等待DNS既有健康退避到期。
                assert response[-4:] == socket.inet_aton('127.0.0.1')
                assert proxy.targets == [(3 if transport == 'udp' else 1, 53)]
                assert not proxy.errors, proxy.errors
                # 多节点reload不能逐个同步等待解析；旧缓存不可复用至新代。
                bootstrap.mode = 'silent'
                before = len(bootstrap.queries)
                config['log']['level'] = 'info'
                path.write_text(json.dumps(config))
                process.send_signal(signal.SIGHUP)
                wait(process, lambda: 'event=reload.committed ' in log.read_text(), log, seconds=3)
                assert len(bootstrap.queries) == before
                # 留一个真实在途解析，SIGTERM必须取消并排空，不能等五秒超时。
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    wire = struct.pack('!HHHHHH', 9, 0x100, 1, 0, 0, 0) + b'\x04stop\x04test\0\0\1\0\1'
                    client.sendto(wire, ('127.0.0.1', listener))
                wait(process, lambda: len(bootstrap.queries) > before, log)
                stopped = time.monotonic()
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=3) == 0, log.read_text()
                assert time.monotonic() - stopped < 2
                assert 'AddressSanitizer' not in log.read_text() and 'runtime error:' not in log.read_text()
            except BaseException:
                print(f"inbound={inbound}, listener={listener}, proxy={proxy.server_address}, bootstrap queries={len(bootstrap.queries)}, targets={proxy.targets}, proxy errors={proxy.errors}", file=sys.stderr)
                print(log.read_text() if log.exists() else '', file=sys.stderr)
                print((root / 'stderr').read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def main():
    binary = str(Path(sys.argv[1]).resolve())
    for ipv6 in (False, True):
        for transport in ('udp', 'tcp'):
            run(binary, ipv6, transport)
    try:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(('::1', 0))
    except OSError as error:
        if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            print('SKIP: IPv6 loopback is unavailable for the AAAA-only proxy case')
            return 77
        raise
    run(binary, True, 'tcp', ipv6_proxy=True)
    print('PASS offline startup, SERVFAIL, automatic request recovery, dual query, reload and cancellation')


if __name__ == '__main__':
    raise SystemExit(main())

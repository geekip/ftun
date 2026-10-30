#!/usr/bin/env python3
"""真实DNS并发：同节点解析合并、TTL换IP、失败退避及恢复。"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
import json
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from control_dns_production import SOCKS, serving as proxy_server
from dns_failover_product import free_ports
from ipv6_product import UDP, serving


class Bootstrap(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        kind = struct.unpack('!H', wire[-4:-2])[0]
        self.server.queries.append(kind)
        if not self.server.gate.wait(4):
            return
        offline = self.server.offline
        address = socket.inet_aton(self.server.address) if kind == 1 and not offline else b''
        response = wire[:2] + struct.pack('!HHHHH', 0x8183 if offline else 0x8180,
                                          1, int(bool(address)), 0, 0) + wire[12:]
        if address:
            response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 2, len(address)) + address
        self.server.replied = time.monotonic()
        sock.sendto(response, self.client_address)


def wait(process, condition, log, timeout=4):
    deadline = time.monotonic() + timeout
    while not condition():
        assert process.poll() is None, log.read_text()
        assert time.monotonic() < deadline, log.read_text()
        time.sleep(.01)


def query(port, ident):
    name = f'query{ident}'.encode()
    wire = struct.pack('!HHHHHH', ident, 0x100, 1, 0, 0, 0) + bytes([len(name)]) + name + b'\4test\0\0\1\0\1'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(wire, ('127.0.0.1', port))
        reply, _ = client.recvfrom(4096)
        assert reply[:2] == wire[:2], reply
        return reply


def run(binary, ipv6):
    count = 24
    with ExitStack() as stack, tempfile.TemporaryDirectory(prefix='ftun-cache-') as directory:
        root = Path(directory)
        bootstrap = stack.enter_context(serving(UDP, Bootstrap, '127.0.0.1'))
        bootstrap.gate = threading.Event()
        bootstrap.offline = False
        bootstrap.address = '127.0.0.1'
        first = stack.enter_context(proxy_server(SOCKS))
        second = stack.enter_context(proxy_server(SOCKS, host='127.0.0.2', port=first.server_address[1]))
        _, _, listener = free_ports()
        config = {'base': {'ipv6': ipv6, 'state-cache': False},
                  'log': {'level': 'debug', 'file': str(root / 'run.log')},
                  'outbounds': [{'name': 'proxy', 'type': 'socks5', 'udp': True,
                                 'server': f'proxy.test:{first.server_address[1]}'}],
                  'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                          'bootstrap': [f'127.0.0.1:{bootstrap.server_address[1]}'],
                          'default-server': 'upstream',
                          'listeners': [{'listen': f'127.0.0.1:{listener}', 'server': 'upstream'}],
                          'servers': [{'name': 'upstream', 'type': 'udp',
                                       'address': ['127.0.0.1:53'], 'outbound': 'proxy'}]}}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        log = root / 'run.log'
        with (root / 'stderr').open('w') as output:
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=output, stderr=output)
            try:
                wait(process, lambda: log.exists() and 'event=running ' in log.read_text(), log)
                assert not bootstrap.queries
                families = 2 if ipv6 else 1
                def burst(start, expected, block=False):
                    if block:
                        before = len(bootstrap.queries)
                        bootstrap.gate.clear()
                    with ThreadPoolExecutor(max_workers=count) as pool:
                        futures = [pool.submit(query, listener, start + i) for i in range(count)]
                        if block:
                            wait(process, lambda: len(bootstrap.queries) >= before + families, log)
                            time.sleep(.1)
                            assert len(bootstrap.queries) == before + families, bootstrap.queries
                            bootstrap.gate.set()
                        for future in futures:
                            reply = future.result()
                            assert reply[3] & 15 == expected, reply
                burst(1, 0, block=True)
                assert len(bootstrap.queries) == families
                assert len(first.targets) == count and not second.targets
                bootstrap.address = '127.0.0.2'
                reply = query(listener, 100)
                assert reply[3] & 15 == 0 and len(bootstrap.queries) == families
                assert len(first.targets) == count + 1
                # 无新请求时不主动刷新；到期后的新请求不再使用旧IP。
                time.sleep(max(0, bootstrap.replied + 2.1 - time.monotonic()))
                assert len(bootstrap.queries) == families
                burst(200, 0, block=True)
                assert len(bootstrap.queries) == families * 2
                assert len(second.targets) == count and len(first.targets) == count + 1
                time.sleep(max(0, bootstrap.replied + 2.1 - time.monotonic()))
                bootstrap.offline = True
                burst(300, 2, block=True)
                before = len(bootstrap.queries)
                burst(400, 2)
                assert len(bootstrap.queries) == before == families * 3
                bootstrap.offline = False
                time.sleep(1.25)
                assert query(listener, 500)[3] & 15 == 0
                assert len(bootstrap.queries) == before + families
                assert not first.errors and not second.errors
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=4) == 0, log.read_text()
                assert 'AddressSanitizer' not in log.read_text() and 'runtime error:' not in log.read_text()
                print(f'PASS ipv6={ipv6}: bursts={count}, bootstrap_queries={len(bootstrap.queries)}, TTL switch and fail-closed recovery')
            except BaseException:
                print(f'bootstrap={bootstrap.queries}, first={first.targets}, second={second.targets}', file=sys.stderr)
                print(log.read_text() if log.exists() else '', file=sys.stderr)
                print((root / 'stderr').read_text(), file=sys.stderr)
                raise
            finally:
                bootstrap.gate.set()
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    for dual in (False, True):
        run(str(Path(sys.argv[1]).resolve()), dual)

#!/usr/bin/env python3
"""在私有网络/挂载命名空间验证双栈TUN、路由保护和TCP/UDP收发。"""
from pathlib import Path
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from resilience import lib

SERVER = r'''
import json,socket,socketserver,threading,time
class TCP(socketserver.ThreadingTCPServer):
 daemon_threads=True
 allow_reuse_address=True
class TCP6(TCP): address_family=socket.AF_INET6
class UDP(socketserver.ThreadingUDPServer): daemon_threads=True
class UDP6(UDP): address_family=socket.AF_INET6
class E(socketserver.BaseRequestHandler):
 def handle(self):
  while b:=self.request.recv(65536): self.request.sendall(b)
class D(socketserver.BaseRequestHandler):
 def handle(self): self.request[1].sendto(self.request[0],self.client_address)
servers=[TCP(('198.51.100.2',0),E),UDP(('198.51.100.2',0),D),TCP6(('fd00:feed::2',0),E),UDP6(('fd00:feed::2',0),D)]
for s in servers: threading.Thread(target=s.serve_forever,daemon=True).start()
print(json.dumps([s.server_address[1] for s in servers]),flush=True)
while True: time.sleep(60)
'''


def sh(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def echo(host, tcp, udp):
    with socket.create_connection((host, tcp), timeout=5) as client:
        payload = bytes(range(256)) * 1024
        # 收发交替，不把两端接收窗口都堵住。
        for start in range(0, len(payload), 8192):
            block = payload[start:start + 8192]
            client.sendall(block)
            received = bytearray()
            while len(received) < len(block):
                data = client.recv(len(block) - len(received))
                assert data
                received.extend(data)
            assert received == block
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        for payload in (b'', b'udp-tun', bytes(range(256)) * 5):
            client.sendto(payload, (host, udp))
            assert client.recv(65535) == payload


def main():
    binary = str(Path(sys.argv[1]).resolve())
    if not Path('/dev/net/tun').exists() or any(shutil.which(command) is None for command in ('ip', 'mount', 'unshare')):
        print('SKIP: TUN, ip, mount and unshare are required')
        return 77
    lib.isolate([str(Path(__file__).resolve()), binary])
    sh('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    sh('ip', 'link', 'set', 'lo', 'up')
    sh('ip', 'netns', 'add', 'peer6')
    sh('ip', 'link', 'add', 'phys6', 'type', 'veth', 'peer', 'name', 'peer6if')
    sh('ip', 'link', 'set', 'peer6if', 'netns', 'peer6')
    sh('ip', 'link', 'set', 'phys6', 'up')
    sh('ip', 'addr', 'add', '198.51.100.1/24', 'dev', 'phys6')
    sh('ip', '-6', 'addr', 'add', 'fd00:feed::1/64', 'dev', 'phys6', 'nodad')
    sh('ip', 'netns', 'exec', 'peer6', 'ip', 'link', 'set', 'lo', 'up')
    sh('ip', 'netns', 'exec', 'peer6', 'ip', 'link', 'set', 'peer6if', 'up')
    sh('ip', 'netns', 'exec', 'peer6', 'ip', 'addr', 'add', '198.51.100.2/24', 'dev', 'peer6if')
    sh('ip', 'netns', 'exec', 'peer6', 'ip', '-6', 'addr', 'add', 'fd00:feed::2/64', 'dev', 'peer6if', 'nodad')
    sh('sysctl', '-q', '-w', 'net.ipv4.conf.all.rp_filter=0')
    sh('sysctl', '-q', '-w', 'net.ipv4.conf.default.rp_filter=0')
    peer = subprocess.Popen(['ip', 'netns', 'exec', 'peer6', sys.executable, '-u', '-c', SERVER],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([peer.stdout], [], [], 5)[0], 'echo server did not start'
        ports = json.loads(peer.stdout.readline())
        with tempfile.TemporaryDirectory(prefix='ftun-tun6-') as directory:
            root = Path(directory)
            path, log = root / 'config.json', root / 'run.log'
            path.write_text(json.dumps({'base': {'ipv6': True, 'state-cache': False},
                'log': {'level': 'debug'}, 'dns': {'enable': False},
                'tun': {'interface': 'ftun6', 'mtu': 1500,
                        'ipv4': {'address': '10.77.0.1/30'}, 'ipv6': {'address': 'fd00:77::1/126'},
                        'auto-route': True, 'strict-route': True, 'route-table': 41000, 'rule-priority': 11000},
                'inbounds': [{'name': 'tun', 'type': 'tun', 'dns-hijack': False}],
                'rules': ['MATCH,DIRECT']}))
            with log.open('w') as output:
                process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=output, stderr=output)
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        assert process.poll() is None, log.read_text()
                        routes = subprocess.run(['ip', '-6', 'route', 'show', 'table', '41000'], capture_output=True, text=True)
                        if 'default dev ftun6' in routes.stdout:
                            break
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.01)
                    echo('fd00:feed::2', ports[2], ports[3])
                    echo('198.51.100.2', ports[0], ports[1])
                    print(sh('ip', '-6', 'addr', 'show', 'dev', 'ftun6'))
                    print(sh('ip', '-6', 'rule', 'show'))
                    print(sh('ip', '-6', 'route', 'show', 'table', '41000'))
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=8) == 0, log.read_text()
                    assert 'lookup 41000' not in sh('ip', '-6', 'rule', 'show')
                    assert not sh('ip', '-6', 'route', 'show', 'table', 'all').count('table 41000')
                    assert 'AddressSanitizer' not in log.read_text() and 'runtime error:' not in log.read_text()
                except BaseException:
                    print(log.read_text(), file=sys.stderr)
                    print(subprocess.run(['ip', '-6', 'rule', 'show'], capture_output=True, text=True).stdout, file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
    finally:
        peer.terminate()
        peer.wait(timeout=5)
        sh('ip', 'netns', 'delete', 'peer6')
    print('IPv6 TUN: dual-stack addresses/routes, marked underlay, 256KiB TCP, UDP and shutdown cleanup passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

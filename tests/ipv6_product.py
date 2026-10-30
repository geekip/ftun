#!/usr/bin/env python3
"""IPv4/IPv6真实回环：Socket入站、出站、DNS A/AAAA及固定前缀规则。"""
from contextlib import contextmanager, ExitStack
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
import threading
import time


def exact(client, count):
    data = bytearray()
    while len(data) < count:
        part = client.recv(count - len(data))
        assert part, (len(data), count)
        data.extend(part)
    return bytes(data)


def endpoint(host, port):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    return bytes([4 if family == socket.AF_INET6 else 1]) + socket.inet_pton(family, host) + struct.pack('!H', port)


def read_endpoint(client):
    kind = exact(client, 1)[0]
    family, length = (socket.AF_INET6, 16) if kind == 4 else (socket.AF_INET, 4)
    assert kind in (1, 4), kind
    return socket.inet_ntop(family, exact(client, length)), struct.unpack('!H', exact(client, 2))[0]


class TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class TCP6(TCP):
    address_family = socket.AF_INET6


class UDP(socketserver.ThreadingUDPServer):
    daemon_threads = True


class UDP6(UDP):
    address_family = socket.AF_INET6


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, client = self.request
        client.sendto(data, self.client_address)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        wire, client = self.request
        cursor, labels = 12, []
        while wire[cursor]:
            size = wire[cursor]
            labels.append(wire[cursor + 1:cursor + 1 + size].decode())
            cursor += size + 1
        name = '.'.join(labels)
        kind = struct.unpack('!H', wire[cursor + 1:cursor + 3])[0]
        self.server.queries.append((name, kind))
        address = b''
        if kind == 1 and name != 'v6-only.test':
            address = socket.inet_pton(socket.AF_INET, '127.0.0.1')
        if kind == 28 and name != 'v4-only.test':
            address = socket.inet_pton(socket.AF_INET6, '::1')
        response = wire[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(address)), 0, 0) + wire[12:]
        if address:
            response += b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(address)) + address
        client.sendto(response, self.client_address)


@contextmanager
def serving(server_type, handler, host):
    server = server_type((host, 0), handler)
    server.queries = []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@contextmanager
def app(binary, host, dns=None, outbound=None, rules=None, dns_listener=0, listen_host=None):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family) as reserve:
        reserve.bind((host, 0))
        port = reserve.getsockname()[1]
    bind_host = listen_host or host
    listen = f'[{bind_host}]:{port}' if ':' in bind_host else f'{bind_host}:{port}'
    config = {'base': {'ipv6': True, 'state-cache': False}, 'log': {'level': 'debug'},
              'dns': {'enable': dns is not None, 'cache': False, 'fake-ip': {'enable': False}},
              'inbounds': [{'name': 'in', 'type': 'mixed', 'listen': listen, 'udp': True}],
              'rules': rules or ['MATCH,proxy' if outbound else 'MATCH,DIRECT']}
    if dns:
        bootstrap = f'[::1]:{dns.server_address[1]}'
        upstream = f'v6-only.test:{dns.server_address[1]}'
        config['dns'].update({'bootstrap': [bootstrap], 'default-server': 'real',
                             'servers': [{'name': 'real', 'type': 'udp', 'address': [upstream], 'outbound': 'DIRECT'}]})
        if dns_listener:
            config['dns']['listeners'] = [{'listen': f'[::]:{dns_listener}', 'server': 'real'}]
    if outbound:
        config['outbounds'] = [{'name': 'proxy', 'type': 'socks5', 'server': outbound, 'udp': True}]
    with tempfile.TemporaryDirectory(prefix='ftun-ipv6-') as directory:
        root = Path(directory)
        path, log = root / 'config.json', root / 'run.log'
        path.write_text(json.dumps(config))
        with log.open('w') as output:
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 5
                while True:
                    assert process.poll() is None, log.read_text()
                    try:
                        with socket.create_connection((host, port), timeout=1):
                            pass
                        if dns_listener:
                            with socket.create_connection(('::1', dns_listener), timeout=1):
                                pass
                        break
                    except ConnectionRefusedError:
                        assert time.monotonic() < deadline, log.read_text()
                        time.sleep(.01)
                yield host, port
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=5) == 0, log.read_text()
                assert 'AddressSanitizer' not in log.read_text() and 'runtime error:' not in log.read_text()
            except BaseException:
                print(log.read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def socks(client_address, host, port, udp=False, domain=False, denied=False):
    client = socket.create_connection(client_address, timeout=3)
    client.sendall(b'\5\1\0')
    assert exact(client, 2) == b'\5\0'
    target = bytes([3, len(host)]) + host.encode() + struct.pack('!H', port) if domain else endpoint(host, port)
    client.sendall(bytes([5, 3 if udp else 1, 0]) + target)
    reply = exact(client, 3)
    bound = read_endpoint(client)
    if denied:
        assert reply[1] == 2, reply
        client.close()
        return
    assert reply == b'\5\0\0', reply
    if udp:
        return client, bound
    with client:
        payload = b'IPv6-data-' * 8192
        client.sendall(payload)
        assert exact(client, len(payload)) == payload


def datagram(client_address, target_host, target_port):
    request_host = '::' if ':' in client_address[0] else '0.0.0.0'
    client, bound = socks(client_address, request_host, 0, udp=True)
    family = socket.AF_INET6 if ':' in bound[0] else socket.AF_INET
    with client, socket.socket(family, socket.SOCK_DGRAM) as channel:
        channel.settimeout(3)
        for payload in (b'', b'udp6', b'6' * 1400):
            wire = b'\0\0\0' + endpoint(target_host, target_port) + payload
            channel.sendto(wire, bound)
            response, _ = channel.recvfrom(65535)
            assert response == wire, (len(response), len(wire))


def connect_http(client_address, target_port):
    with socket.create_connection(client_address, timeout=3) as client:
        authority = f'[::1]:{target_port}'
        client.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode())
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            response.extend(exact(client, 1))
        assert response.startswith(b'HTTP/1.1 200'), response
        client.sendall(b'CONNECT6')
        assert exact(client, 8) == b'CONNECT6'


def main():
    binary = str(Path(sys.argv[1]).resolve())
    try:
        with socket.socket(socket.AF_INET6) as check:
            check.bind(('::1', 0))
    except OSError as error:
        if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            print('SKIP: IPv6 loopback is unavailable')
            return 77
        raise
    with ExitStack() as stack:
        tcp4 = stack.enter_context(serving(TCP, EchoTCP, '127.0.0.1'))
        tcp6 = stack.enter_context(serving(TCP6, EchoTCP, '::1'))
        udp6 = stack.enter_context(serving(UDP6, EchoUDP, '::1'))
        dns = stack.enter_context(serving(UDP6, DNS, '::1'))
        for host in ('127.0.0.1', '::1'):
            direct = stack.enter_context(app(binary, host, dns=dns))
            socks(direct, '::1', tcp6.server_address[1])
            socks(direct, '127.0.0.1', tcp4.server_address[1])
            connect_http(direct, tcp6.server_address[1])
            datagram(direct, '::1', udp6.server_address[1])
            socks(direct, 'v6-only.test', tcp6.server_address[1], domain=True)
            socks(direct, 'v4-only.test', tcp4.server_address[1], domain=True)
        with socket.socket(socket.AF_INET6) as reserve:
            reserve.bind(('::', 0))
            listener_port = reserve.getsockname()[1]
        stack.enter_context(app(binary, '::1', dns=dns, dns_listener=listener_port))
        query = b'\x46\x54\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07v6-only\x04test\x00\x00\x1c\x00\x01'
        for family, transport in ((family, transport) for family in (socket.AF_INET, socket.AF_INET6)
                                  for transport in (socket.SOCK_DGRAM, socket.SOCK_STREAM)):
            with socket.socket(family, transport) as client:
                client.settimeout(3)
                client.connect(('::1' if family == socket.AF_INET6 else '127.0.0.1', listener_port))
                if transport == socket.SOCK_DGRAM:
                    client.send(query)
                    response = client.recv(4096)
                else:
                    client.sendall(struct.pack('!H', len(query)) + query)
                    response = exact(client, struct.unpack('!H', exact(client, 2))[0])
                assert response[:2] == query[:2] and struct.unpack('!H', response[6:8])[0] == 1, response
                assert response.endswith(socket.inet_pton(socket.AF_INET6, '::1')), response
        wildcard = stack.enter_context(app(binary, '::1', dns=dns, listen_host='::'))
        for peer in (wildcard, ('127.0.0.1', wildcard[1])):
            socks(peer, '::1', tcp6.server_address[1])
            datagram(peer, '::1', udp6.server_address[1])
        middle = stack.enter_context(app(binary, '::1'))
        for node in (f'[::1]:{middle[1]}', f'node6.test:{middle[1]}'):
            proxy = stack.enter_context(app(binary, '::1', dns=dns, outbound=node))
            socks(proxy, '::1', tcp6.server_address[1])
            connect_http(proxy, tcp6.server_address[1])
            datagram(proxy, '::1', udp6.server_address[1])
        blocked = stack.enter_context(app(binary, '::1', dns=dns,
            rules=['IP-CIDR,::1/128,REJECT', 'MATCH,DIRECT']))
        socks(blocked, '::1', tcp6.server_address[1], denied=True)
        socks(blocked, 'v6-only.test', tcp6.server_address[1], domain=True, denied=True)
        for domain in ('v6-only.test', 'v4-only.test', 'node6.test'):
            assert (domain, 1) in dns.queries and (domain, 28) in dns.queries, dns.queries
    print('IPv6 product: TCP/UDP, HTTP CONNECT, IPv4 compatibility, AAAA-only names, IPv6 SOCKS nodes and CIDR denial passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

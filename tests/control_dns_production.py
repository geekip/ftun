"""Local DNS DIRECT/SOCKS5 paths used by the real HTTP control client."""
from contextlib import ExitStack, contextmanager
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

from http_fetch_production import HTTP, BODY, serving as serving_http
from inbound_adapter_product import receive


class TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UDP(socketserver.ThreadingUDPServer):
    daemon_threads = True


def answer(server, wire):
    assert len(wire) >= 17 and wire[-4:] == b'\0\1\0\1', wire
    labels, cursor = [], 12
    while wire[cursor]:
        length = wire[cursor]
        cursor += 1
        labels.append(wire[cursor:cursor + length].decode())
        cursor += length
    name = '.'.join(labels)
    server.queries.append(name)
    if server.mode == 'slow':
        time.sleep(0.35)
    if server.mode == 'empty':
        return b''
    if server.mode == 'large':
        return b'x' * 8192
    flags = 0x8183 if server.mode in ('negative', 'negative-a') else 0x8380 if server.mode == 'truncated' else 0x8180
    count = 0 if server.mode in ('negative', 'truncated') else 1
    query_id = struct.unpack('!H', wire[:2])[0] ^ (1 if server.mode == 'wrong-id' else 0)
    header = struct.pack('!HHHHHH', query_id, flags, 1, count, 0, 0)
    records = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01' if count else b''
    return header + wire[12:] + records


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            wire, sock = self.request
            sock.sendto(answer(self.server, wire), self.client_address)
        except BaseException as error:
            self.server.errors.append(error)


class DNSTCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2)
            size = struct.unpack('!H', receive(self.request, 2))[0]
            wire = answer(self.server, receive(self.request, size))
            frame = struct.pack('!H', len(wire)) + wire
            for offset in range(0, len(frame), 3):
                self.request.sendall(frame[offset:offset + 3])
        except (ConnectionError, TimeoutError):
            pass
        except BaseException as error:
            self.server.errors.append(error)


class SOCKS(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(2)
        try:
            greeting = receive(client, 3)
            assert greeting == (b'\5\1\2' if self.server.auth else b'\5\1\0'), greeting
            client.sendall(b'\5' + greeting[2:])
            if self.server.auth:
                assert receive(client, 2) == b'\1\4'
                assert receive(client, 4) == b'user'
                assert receive(client, 1) == b'\4'
                assert receive(client, 4) == b'pass'
                client.sendall(b'\1\1' if self.server.mode == 'bad-auth' else b'\1\0')
                if self.server.mode == 'bad-auth':
                    return
            header = receive(client, 4)
            assert header[:1] == b'\5' and header[2:] == b'\0\1', header
            target = receive(client, 6)
            assert socket.inet_ntoa(target[:4]) == '127.0.0.1'
            self.server.targets.append((header[1], struct.unpack('!H', target[4:])[0]))
            if header[1] == 1:
                client.sendall(b'\5\0\0\1' + b'\0' * 6)
                size = struct.unpack('!H', receive(client, 2))[0]
                wire = answer(self.server, receive(client, size))
                frame = struct.pack('!H', len(wire)) + wire
                for offset in range(0, len(frame), 2):
                    client.sendall(frame[offset:offset + 2])
            else:
                assert header[1] == 3
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                    relay.bind(('127.0.0.1', 0))
                    relay.settimeout(2)
                    # 零地址必须规范化为代理端点 IP，不能当作独立解析目标。
                    client.sendall(b'\5\0\0\1' + b'\0' * 4 + struct.pack('!H', relay.getsockname()[1]))
                    wire, peer = relay.recvfrom(65536)
                    assert wire[:4] == b'\0\0\0\1' and wire[4:10] == target, wire[:10]
                    response = answer(self.server, wire[10:])
                    prefix = wire[:10]
                    if self.server.mode == 'wrong-source':
                        prefix = prefix[:8] + b'\0\1'
                    if self.server.mode == 'fragment':
                        prefix = b'\0\0\1' + prefix[3:]
                    relay.sendto(prefix + response, peer)
                    assert client.recv(1) == b''
        except (ConnectionError, TimeoutError):
            pass
        except BaseException as error:
            self.server.errors.append(error)


@contextmanager
def serving(handler, mode='ok', auth=False):
    server = (UDP if handler is DNSUDP else TCP)(('127.0.0.1', 0), handler)
    server.mode, server.auth = mode, auth
    server.queries, server.targets, server.errors = [], [], []
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        assert not server.errors, server.errors


def endpoint(server, host='127.0.0.1'):
    return f'{host}:{server.server_address[1]}'


def fetch(binary, http, mode, upstream='', proxy='', bootstrap='', auth=False,
          expected='ok', timeout=1500, path='/body', allow=True, host=None):
    host = host or ('localhost' if mode == 'system' else 'download.test')
    url = f'http://{host}:{http.server_address[1]}{path}'
    started = time.monotonic()
    result = subprocess.run([binary, url, mode, upstream, proxy, bootstrap,
                             str(int(auth)), str(timeout), str(int(allow))], capture_output=True, timeout=4)
    elapsed = time.monotonic() - started
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    header, body = result.stdout.split(b'\n', 1)
    values = dict(item.split(b'=') for item in header.split())
    assert int(values[b'resolvers']) > 0, header
    if expected == 'ok':
        assert int(values[b'paths']) > 0, header
    assert values[b'status'].decode() == expected, (header, result.stderr)
    assert body == (BODY if expected == 'ok' else b''), body
    assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr
    if expected == 'timeout':
        assert elapsed < 1.2, elapsed
    return values


def main():
    binary = sys.argv[1]
    with ExitStack() as stack:
        http = stack.enter_context(serving_http(HTTP))
        bootstrap = stack.enter_context(serving(DNSUDP))
        udp = stack.enter_context(serving(DNSUDP))
        tcp = stack.enter_context(serving(DNSTCP))
        values = fetch(binary, http, 'system')
        assert values[b'system'] == b'1' and values[b'resolvers'] == b'1'
        values = fetch(binary, http, 'system', allow=False, expected='rejected')
        assert values[b'system'] == b'0' and values[b'paths'] == b'0'
        values = fetch(binary, http, 'system', allow=False, host='127.0.0.1')
        assert values[b'system'] == b'0'
        values = fetch(binary, http, 'udp', endpoint(udp, 'resolver.test'), allow=False, expected='rejected')
        assert values[b'system'] == b'0' and values[b'paths'] == b'0'
        fetch(binary, http, 'udp', endpoint(udp), allow=False)
        udp.queries.clear()
        fetch(binary, http, 'bootstrap', bootstrap=endpoint(bootstrap))
        for mode, server in [('udp', udp), ('tcp', tcp)]:
            fetch(binary, http, mode, endpoint(server), path='/redirect')
            assert server.queries == ['download.test', 'download.test']
            server.queries.clear()
            fetch(binary, http, mode, endpoint(server, 'resolver.test'), bootstrap=endpoint(bootstrap))
            assert server.queries == ['download.test']
            for auth in (False, True):
                proxy = stack.enter_context(serving(SOCKS, auth=auth))
                bootstrap.queries.clear()
                fetch(binary, http, mode, endpoint(server, 'resolver.test'),
                      endpoint(proxy, 'proxy.test'), endpoint(bootstrap), auth)
                assert bootstrap.queries == ['resolver.test', 'proxy.test']
                assert proxy.queries == ['download.test']
                assert proxy.targets == [(1 if mode == 'tcp' else 3, server.server_address[1])]
        negative = stack.enter_context(serving(DNSUDP, 'negative'))
        bootstrap.queries.clear()
        fetch(binary, http, 'bootstrap', bootstrap=endpoint(negative) + ',' + endpoint(bootstrap))
        assert negative.queries == ['download.test'] and bootstrap.queries == ['download.test']
        bootstrap.queries.clear()
        fetch(binary, http, 'udp', endpoint(negative), bootstrap=endpoint(bootstrap), expected='resolve')
        assert not bootstrap.queries
        for handler, mode in [(DNSUDP, 'udp'), (DNSTCP, 'tcp')]:
            for failure, expected in [('wrong-id', 'protocol'), ('large', 'limit'), ('negative-a', 'resolve'),
                                      ('truncated', 'resolve'), ('slow', 'timeout')]:
                server = stack.enter_context(serving(handler, failure))
                fetch(binary, http, mode, endpoint(server), expected=expected,
                      timeout=100 if failure == 'slow' else 1500)
        empty = stack.enter_context(serving(DNSUDP, 'empty'))
        fetch(binary, http, 'udp', endpoint(empty), expected='eof')
        for failure, expected, auth in [('wrong-source', 'rejected', False),
                                        ('fragment', 'unsupported', False), ('bad-auth', 'rejected', True)]:
            proxy = stack.enter_context(serving(SOCKS, failure, auth))
            fetch(binary, http, 'udp', endpoint(udp), endpoint(proxy), auth=auth, expected=expected)
        slow_bootstrap = stack.enter_context(serving(DNSUDP, 'slow'))
        fetch(binary, http, 'udp', endpoint(udp, 'resolver.test'), bootstrap=endpoint(slow_bootstrap),
              expected='timeout', timeout=100)
        print('control DNS production: system/bootstrap/named, TCP/UDP/SOCKS5, identity, deadlines, failures and budgets passed')


if __name__ == '__main__':
    main()

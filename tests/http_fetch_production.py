#!/usr/bin/env python3
"""Real HTTP/TLS/SOCKS5 over the control Path adapter, using local peers only."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from inbound_adapter_product import receive

BODY = b'control\x00channel\xffresponse'


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Server6(Server):
    address_family = socket.AF_INET6


class HTTP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            header = b''
            while b'\r\n\r\n' not in header and len(header) < 8192:
                data = self.request.recv(1024)
                if not data:
                    return
                header += data
            path = header.split(b' ')[1]
            self.server.requests.append(header)
            body = BODY
            status = b'200 OK'
            extra = b'ETag: "control-test"\r\n'
            if path == b'/redirect':
                status, body, extra = b'302 Found', b'', b'Location: /body\r\n'
            elif path == b'/last-location':
                status, body, extra = b'302 Found', b'', b'Location: /body\r\n'
            elif path == b'/etag':
                assert b'If-None-Match: "control-test"\r\n' in header
                status, body = b'304 Not Modified', b''
            elif path == b'/large':
                body = b'x' * 8192
            elif path == b'/slow':
                time.sleep(2)
            elif path == b'/malformed':
                self.request.sendall(b'bad response\r\n\r\n')
                return
            wire = b'HTTP/1.1 ' + status + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'Connection: close\r\n\r\n' + body
            if path == b'/last-length':
                wire = b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
            elif path == b'/last-location':
                wire = b'HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: /body\r\n\r\n'
            elif path == b'/chunked':
                chunks = b'3\r\n' + body[:3] + b'\r\n' + format(len(body) - 3, 'x').encode() + b'\r\n' + body[3:] + b'\r\n0\r\n\r\n'
                wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' + chunks
            for offset in range(0, len(wire), 3):
                self.request.sendall(wire[offset:offset + 3])
            if isinstance(self.request, ssl.SSLSocket):
                # 正常 TLS 关闭必须发送 close_notify；裸 TCP EOF 单独属于错误。
                self.request.unwrap()
        except (ConnectionError, TimeoutError, ssl.SSLError):
            pass


class SOCKS(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(3)
        try:
            greeting = receive(client, 3)
            method = 2 if self.server.auth else 0
            assert greeting == bytes([5, 1, method]), greeting
            client.sendall(bytes([5, method]))
            if method == 2:
                first = receive(client, 2)
                assert first[0] == 1
                username = receive(client, first[1])
                password = receive(client, receive(client, 1)[0])
                assert (username, password) == (b'user', b'pass')
                client.sendall(b'\x01\x00')
            header = receive(client, 4)
            assert header[:3] == b'\x05\x01\x00' and header[3] in (1, 4)
            family, size = (socket.AF_INET6, 16) if header[3] == 4 else (socket.AF_INET, 4)
            target = socket.inet_ntop(family, receive(client, size)), struct.unpack('!H', receive(client, 2))[0]
            assert target[0] in ('127.0.0.1', '::1'), target
            with socket.create_connection(target, timeout=3) as peer:
                for byte in b'\x05\x00\x00\x01\x7f\0\0\x01\x12\x34':
                    client.sendall(bytes([byte]))
                self.server.connections += 1
                while True:
                    ready, _, _ = select.select([client, peer], [], [], 3)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(4096)
                        if not data:
                            return
                        (peer if source is client else client).sendall(data)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            pass


@contextmanager
def serving(handler, context=None, auth=False, host='127.0.0.1'):
    server = (Server6 if ':' in host else Server)((host, 0), handler)
    server.auth = auth
    server.connections = 0
    server.requests = []
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def fetch(binary, url, proxy=0, auth=False, ca='', expected=200, body=BODY, tls=False):
    result = subprocess.run([binary, url, str(proxy), str(int(auth)), str(ca)],
                            capture_output=True, timeout=7)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    header, payload = result.stdout.split(b'\n', 1)
    values = dict(field.split(b'=') for field in header.split())
    if expected is None:
        assert values[b'status'] != b'0' and payload == b'', result.stdout
    else:
        assert values == {b'status': b'0', b'http': str(expected).encode(),
                          b'tls': str(int(tls)).encode(), b'length': str(len(body)).encode()}, result.stdout
        assert payload == body, payload
    assert b'AddressSanitizer' not in result.stderr and b'runtime error:' not in result.stderr


def certificates(root, ipv6=True, san=None, common_name="localhost"):
    def run(*args):
        result = subprocess.run(['openssl', *args], cwd=root, capture_output=True)
        assert result.returncode == 0, result.stderr
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Control Test CA', '-keyout', 'ca.key', '-out', 'ca.pem')
    run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', f'/CN={common_name}', '-keyout', 'server.key', '-out', 'server.csr')
    if san is None:
        san = 'DNS:localhost' + (',IP:::1' if ipv6 else '')
    (root / 'extensions').write_text(('subjectAltName=' + san + '\n' if san else '') + 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    run('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1', '-extfile', 'extensions', '-out', 'server.pem')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / 'server.pem', root / 'server.key')
    return context


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-http-channel-') as directory, ExitStack() as stack:
        root = Path(directory)
        context = certificates(root)
        names = []
        context.set_servername_callback(lambda _, name, __: names.append(name))
        plain = stack.enter_context(serving(HTTP))
        secure = stack.enter_context(serving(HTTP, context))
        proxies = [stack.enter_context(serving(SOCKS, auth=auth)) for auth in (False, True)]
        http = f'http://127.0.0.1:{plain.server_address[1]}'
        https = f'https://localhost:{secure.server_address[1]}'
        ca = root / 'ca.pem'
        for suffix in ('/body', '/redirect', '/last-length', '/last-location', '/chunked'):
            fetch(binary, http + suffix)
        fetch(binary, http + '/etag', expected=304, body=b'')
        for suffix in ('/large', '/slow', '/malformed'):
            fetch(binary, http + suffix, expected=None)
        fetch(binary, https + '/body', ca=ca, tls=True)
        fetch(binary, https + '/redirect', ca=ca, tls=True)
        fetch(binary, https + '/last-length', ca=ca, tls=True)
        fetch(binary, https + '/last-location', ca=ca, tls=True)
        fetch(binary, https + '/chunked', ca=ca, tls=True)
        fetch(binary, https + '/body', expected=None)
        fetch(binary, f'https://127.0.0.1:{secure.server_address[1]}/body', ca=ca, expected=None)
        for auth, proxy in zip((False, True), proxies):
            port = proxy.server_address[1]
            fetch(binary, http + '/body', port, auth)
            fetch(binary, https + '/body', port, auth, ca, tls=True)
            assert proxy.connections == 2
        assert names.count('localhost') >= 5, names
        print('PASS control HTTP Path: partial bytes, redirects, ETag/304, limits, timeout, TLS CA/hostname/SNI, SOCKS5 noauth/auth, resource recovery')


if __name__ == '__main__':
    main()

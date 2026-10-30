#!/usr/bin/env python3
"""IPv6 HTTP 控制出口：直连、SOCKS、TLS IP 证书校验与重定向。"""
from contextlib import ExitStack
from pathlib import Path
import errno
import socket
import sys
import tempfile
from http_fetch_production import HTTP, SOCKS, certificates, fetch, serving


def main():
    binary = str(Path(sys.argv[1]).resolve())
    try:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(('::1', 0))
    except OSError as error:
        if error.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            print('SKIP: IPv6 loopback is unavailable')
            return 77
        raise
    with tempfile.TemporaryDirectory(prefix='ftun-http6-') as directory, ExitStack() as stack:
        root = Path(directory)
        context = certificates(root)
        plain = stack.enter_context(serving(HTTP, host='::1'))
        secure = stack.enter_context(serving(HTTP, context, host='::1'))
        proxy = stack.enter_context(serving(SOCKS, auth=True))
        for port, auth in ((0, False), (proxy.server_address[1], True)):
            for suffix in ('/body', '/redirect'):
                fetch(binary, f'http://[::1]:{plain.server_address[1]}{suffix}', port, auth)
                fetch(binary, f'https://[::1]:{secure.server_address[1]}{suffix}', port, auth, root / 'ca.pem', tls=True)
        fetch(binary, f'https://[::1]:{secure.server_address[1]}/body', expected=None)
        invalid = root / 'invalid'
        invalid.mkdir()
        wrong = stack.enter_context(serving(HTTP, certificates(invalid, ipv6=False), host='::1'))
        fetch(binary, f'https://[::1]:{wrong.server_address[1]}/body', ca=invalid / 'ca.pem', expected=None)
        assert proxy.connections == 6
        assert all(f'Host: [::1]:{plain.server_address[1]}\r\n'.encode() in request for request in plain.requests)
    print('IPv6 HTTP/TLS: direct and authenticated SOCKS, IP certificate, bracketed Host and redirects passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

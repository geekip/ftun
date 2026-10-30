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
        fetch(binary, f'https://[0:0:0:0:0:0:0:1]:{secure.server_address[1]}/body', ca=root / 'ca.pem', tls=True)
        # 同样的数值文本只有iPAddress类型SAN可接受；CN和dNSName不可冒充。
        for index, (host, san, cn, accepted) in enumerate((
                ('127.0.0.1', 'IP:127.0.0.1', 'localhost', True),
                ('127.0.0.1', 'IP:127.0.0.2', '127.0.0.1', False),
                ('127.0.0.1', 'DNS:127.0.0.1', '127.0.0.1', False),
                ('127.0.0.1', '', '127.0.0.1', False),
                ('::1', 'DNS:::1', '::1', False),
                ('::1', 'IP:::2', '::1', False))):
            case = root / f'identity{index}'
            case.mkdir()
            server = stack.enter_context(serving(HTTP,
                certificates(case, san=san, common_name=cn), host=host))
            target = f'[{host}]' if ':' in host else host
            fetch(binary, f'https://{target}:{server.server_address[1]}/body',
                  ca=case / 'ca.pem', expected=200 if accepted else None, tls=accepted)
        assert proxy.connections == 6
        assert all(f'Host: [::1]:{plain.server_address[1]}\r\n'.encode() in request for request in plain.requests)
    print('IPv6 HTTP/TLS: direct and authenticated SOCKS, IP certificate, bracketed Host and redirects passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

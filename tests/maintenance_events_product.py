#!/usr/bin/env python3
"""Verify real FRS validation/TLS faults and URL-Test state transitions."""
import http.server
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from ctl_server_product import Instance, wait
from frs_reload_generation import frs_ipv4
from http_fetch_production import certificates, serving, HTTP


def output(log):
    return log.read_text() if log.exists() else ''


def main():
    with tempfile.TemporaryDirectory(prefix='ftun-maintenance-events-') as directory:
        root = Path(directory)
        body = [b'invalid rule set']
        code = [503]
        rules_code = [200]

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                result = rules_code[0] if self.path == '/rules' else code[0]
                content = body[0] if self.path == '/rules' and result != 304 else b''
                if result == 304:
                    assert self.headers.get('If-None-Match') == '"rules-v1"', self.headers
                self.send_response(result)
                if self.path == '/rules':
                    self.send_header('ETag', '"rules-v1"')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02})
        thread.start()
        log = root / 'maintenance.log'
        app = None
        try:
            app = Instance(sys.argv[1], root / 'run', initial={
                'dns': {'enable': False},
                'log': {'level': 'debug', 'output': 'file', 'file': str(log)},
                'frs': {'path': str(root / 'rules.frs'), 'url': f'http://127.0.0.1:{server.server_port}/rules',
                        'auto-update': True, 'update-interval': '1s'},
                'rules': ['FRS-IP,CN,REJECT', 'MATCH,auto'],
                'outbounds': [{'name': 'auto', 'type': 'url-test', 'outbounds': ['DIRECT'], 'default': 'DIRECT',
                              'url': f'http://127.0.0.1:{server.server_port}/probe', 'interval': '1s',
                              'timeout': '1s', 'expected-status': 204, 'lazy': False}]})
            wait(lambda: 'verify failed (first):' in output(log) and 'url-test failed (first):' in output(log), lambda: output(log))
            assert 'phase=verify' in output(log) and 'http_status=503' in output(log), output(log)
            body[0] = frs_ipv4('CN', 0x01000000, 0x01FFFFFF)
            code[0] = 204
            wait(lambda: 'rule set published:' in output(log) and 'url-test recovered:' in output(log), lambda: output(log))
            wait(lambda: 'rule set recovered:' in output(log), lambda: output(log))
            assert 'url-test result:' in output(log) and 'group=auto' in output(log), output(log)
            assert 'download progress:' in output(log) and 'complete=1' in output(log), output(log)
            generation = app.call('status')['generation']
            published = output(log).count('rule set published:')
            for response in (200, 304):
                failures = output(log).count('download failed (first):')
                recoveries = output(log).count('rule set recovered:')
                rules_code[0] = 503
                wait(lambda: output(log).count('download failed (first):') == failures + 1, lambda: output(log))
                rules_code[0] = response
                wait(lambda: output(log).count('rule set recovered:') == recoveries + 1, lambda: output(log))
                assert app.call('status')['generation'] == generation, output(log)
                assert output(log).count('rule set published:') == published, output(log)
            assert app.call('stop', timeout_ms=5000)['result'] == 'stopped'
            assert app.process.wait(timeout=5) == 0
        finally:
            if app is not None:
                app.close()
            server.shutdown()
            server.server_close()
            thread.join()

        certs = root / 'certs'
        certs.mkdir()
        context = certificates(certs, ipv6=False)
        with serving(HTTP, context) as secure:
            log = root / 'tls.log'
            app = Instance(sys.argv[1], root / 'tls', initial={
                'dns': {'enable': False},
                'log': {'level': 'info', 'output': 'file', 'file': str(log)},
                'frs': {'path': str(root / 'tls.frs'), 'url': f'https://127.0.0.1:{secure.server_address[1]}/body',
                        'auto-update': True, 'update-interval': '1s'},
                'rules': ['FRS-IP,CN,REJECT', 'MATCH,DIRECT']},
                env=dict(os.environ, SSL_CERT_FILE=str(certs / 'ca.pem')))
            try:
                wait(lambda: 'download failed (first):' in output(log), lambda: output(log))
                line = next(line for line in output(log).splitlines() if 'download failed (first):' in line)
                assert re.search(r'tls_code=-?\d+', line) and 'tls_reason=' in line and 'phase=download' in line, line
                assert app.call('stop', timeout_ms=5000)['result'] == 'stopped'
                assert app.process.wait(timeout=5) == 0
            finally:
                app.close()
    print('maintenance events: invalid FRS and unchanged/304 recovery without new generation, publication, URL-Test recovery and native TLS reason passed')


if __name__ == '__main__':
    main()

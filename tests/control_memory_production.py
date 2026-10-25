#!/usr/bin/env python3
"""FRS bootstrap/update and URL-Test enter Path using memory-only outbound I/O."""
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

from inbound_adapter_product import receive


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-control-memory-') as directory:
        root = Path(directory)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = {'base': {'state-cache': False},
                  'dns': {'enable': True, 'bootstrap': ['198.51.100.53:53']},
                  'log': {'level': 'silent'},
                  'frs': {'path': str(root / 'rules.frs'), 'url': 'http://rules.test/rules',
                          'auto-update': True, 'update-interval': '1s'},
                  'inbounds': [{'name': 'socks', 'type': 'socks5', 'listen': f'127.0.0.1:{port}'}],
                  'outbounds': [{'name': 'probe', 'type': 'url-test', 'outbounds': ['DIRECT'],
                                 'default': 'DIRECT', 'url': 'http://health.test/health',
                                 'interval': '1s', 'timeout': '1s'}],
                  'rules': ['frs-ip,CN,REJECT', 'MATCH,probe']}
        path = root / 'config.json'
        path.write_text(json.dumps(config))
        log_path = root / 'run.log'
        with log_path.open('w+') as log:
            process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
            def wait(predicate):
                deadline = time.monotonic() + 7
                while not predicate(log_path.read_text()):
                    assert process.poll() is None, (process.returncode, log_path.read_text())
                    assert time.monotonic() < deadline, log_path.read_text()
                    time.sleep(0.01)
            try:
                wait(lambda text: 'purpose=6 ' in text)
                def consume_group():
                    with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                        client.sendall(b'\x05\x01\x00\x05\x01\x00\x01\xcb\x00\x71\x09\x00\x50')
                        assert receive(client, 2) == b'\x05\x00'
                        receive(client, 10)
                deadline = time.monotonic() + 3
                while True:
                    try:
                        consume_group()
                        break
                    except ConnectionRefusedError:
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                wait(lambda text: text.count('purpose=6 generation=1 transport=1') >= 2 and
                     'purpose=5 generation=1 transport=1' in text)
                assert 'purpose=6 generation=1 transport=2' in log_path.read_text()
                assert 'purpose=5 generation=1 transport=2' in log_path.read_text()
                assert (root / 'rules.frs').stat().st_size > 100
                first = (root / 'rules.frs').read_bytes()
                config['outbounds'][0]['url'] = 'http://health.test/health-next'
                config['frs']['url'] = 'http://missing.test/rules'
                path.write_text(json.dumps(config))
                process.send_signal(signal.SIGHUP)
                wait(lambda text: 'reload committed' in text)
                consume_group()
                wait(lambda text: 'reload committed' in text and 'purpose=5 generation=2 transport=1' in text)
                assert 'purpose=5 generation=2 transport=2' in log_path.read_text()
                text = log_path.read_text()
                for purpose, generation in ((6, 1), (5, 1), (5, 2)):
                    assert f'control resolver purpose={purpose} generation={generation} source=1' in text, text
                wait(lambda text: 'control memory dns negative' in text)
                assert (root / 'rules.frs').read_bytes() == first
                process.terminate()
                assert process.wait(timeout=5) == 0
                text = log_path.read_text()
                assert 'AddressSanitizer' not in text and 'runtime error:' not in text
                print('PASS control memory Path: domain DNS, FRS updates and failure retention, URL-Test, reload generations and stop')
            except BaseException:
                print(log_path.read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()

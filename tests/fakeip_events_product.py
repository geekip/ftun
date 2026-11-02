#!/usr/bin/env python3
"""Verify bounded FakeIP mapping detail and real pool exhaustion aggregation."""
from pathlib import Path
import socket
import re
import sys
import tempfile
from ctl_server_product import Instance, wait
from fakeip_cidr import configuration, free_port, query, stop


def main():
    with tempfile.TemporaryDirectory(prefix='ftun-fakeip-events-') as directory:
        root = Path(directory)
        for level in ('info', 'debug', 'warn', 'silent'):
            port, log = free_port(), root / (level + '.log')
            value = configuration('198.18.7.0/30', root / level, port)
            value['log'] = {'level': level, 'output': 'file', 'file': str(log)}
            app = Instance(sys.argv[1], root / ('run-' + level), initial=value)
            try:
                assert query(port, 'first') == '198.18.7.1'
                assert query(port, 'first') == '198.18.7.1'
                assert query(port, 'second') == '198.18.7.2'
                wire = b'\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x05third\x04test\0\0\x01\0\x01'
                for _ in range(10):
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(3)
                        client.sendto(wire, ('127.0.0.1', port))
                        assert client.recv(4096)[3] & 15 == 2
                stop(app)
                output = log.read_text() if log.exists() else ''
                mappings = [line for line in output.splitlines() if '[fakeip][DEBUG] mapping created:' in line]
                assert len(mappings) == (2 if level == 'debug' else 0), output
                if level != 'silent':
                    assert output.count('pool exhausted (first):') == 1, output
                    assert any('pool exhausted:' in line and 'count=10' in line for line in output.splitlines()), output
                else:
                    assert output == '', output
            finally:
                app.close()
        identities = []
        for index in range(2):
            port, log = free_port(), root / f'persistent-{index}.log'
            value = configuration('198.18.9.0/24', root / 'durable', port, persist=True)
            value['log'] = {'level': 'info', 'output': 'file', 'file': str(log)}
            app = Instance(sys.argv[1], root / f'persistent-{index}', initial=value)
            try:
                assert query(port, 'retained') == '198.18.9.1'
                stop(app)
                line = next(line for line in log.read_text().splitlines() if '[fakeip][INFO ] identity loaded:' in line)
                identities.append(re.search(r'uuid=([0-9a-f]{8})\b', line)[1])
                assert 'pool_start=198.18.9.1' in line and 'pool_end_exclusive=198.18.9.255' in line, line
            finally:
                app.close()
        assert identities[0] == identities[1], identities
    print('FakeIP events: two committed mappings, repeat lookup quiet, ten exhaustion failures aggregate; level gates passed')


if __name__ == '__main__':
    main()

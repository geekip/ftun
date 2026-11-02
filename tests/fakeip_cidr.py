#!/usr/bin/env python3
"""Use real selected FakeIP listeners to check normalized pools, identity and reload."""
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from ctl_server_product import Instance


def free_port():
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        port = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', port))
        return port


def configuration(cidr, store, listener, persist=False):
    return {'base': {'state-cache': False, 'cache-file': str(store)}, 'log': {'level': 'silent'},
            'dns': {'enable': True, 'cache': False,
                    'fake-ip': {'enable': True, 'persist': persist, 'range': cidr},
                    'default-server': 'fake',
                    'listeners': [{'listen': f'127.0.0.1:{listener}', 'server': 'fake'}],
                    'servers': [{'name': 'fake', 'type': 'udp', 'address': ['127.0.0.1:53'],
                                 'outbound': 'DIRECT', 'fake-ip': True}]}}


def query(port, label='cidr'):
    name = bytes([len(label)]) + label.encode() + b'\x04test\0'
    wire = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + name + b'\0\x01\0\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(4)
        stream.sendto(wire, ('127.0.0.1', port))
        answer = stream.recv(4096)
    assert answer[:2] == wire[:2] and answer[3] & 15 == 0, answer.hex()
    return socket.inet_ntoa(answer[-4:])


def checked(binary, path, value, code=0):
    path.write_text(json.dumps(value))
    before = set(path.parent.rglob('*'))
    # Occupied listener is a startup condition; check must never bind it.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as held:
        held.bind(('127.0.0.1', int(value['dns']['listeners'][0]['listen'].rsplit(':', 1)[1])))
        result = subprocess.run([binary, 'check', '-c', str(path)], capture_output=True, text=True, timeout=8)
    assert result.returncode == code, result
    assert set(path.parent.rglob('*')) == before, 'check changed files'
    return result


def stop(app):
    assert app.call('stop', boot=app.boot, timeout_ms=4000)['result'] == 'stopped'
    assert app.process.wait(timeout=3) == 0, app.output.read_text()


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-cidr-product-') as directory:
        root = Path(directory)
        for index, cidr in enumerate(['198.18.0.0/15', '198.18.1.0/15', '198.18.1.99/15', '198.18.7.2/30']):
            listener = free_port()
            value = configuration(cidr, root / f'volatile-{index}', listener)
            checked(binary, root / f'check-{index}.json', value)
            app = Instance(binary, root / f'run-{index}', initial=value)
            try:
                state = app.call('status')
                assert next(s['state'] for s in state['services'] if s['name'] == 'fakeip') == 'active', state
                assert query(listener) == str(next(ipaddress.ip_network(cidr, strict=False).hosts()))
                stop(app)
            finally:
                app.close()

        store = root / 'durable'
        value = configuration('198.18.7.9/24', store, free_port(), persist=True)
        path = root / 'initialize.json'
        checked(binary, path, value)
        identity = Path(str(store) + '.fakeip') / 'identity'
        original = None
        for index, cidr in enumerate(['198.18.7.9/24', '198.18.7.200/24']):
            value = configuration(cidr, store, free_port(), persist=True)
            app = Instance(binary, root / f'durable-{index}', initial=value)
            listener = int(value['dns']['listeners'][0]['listen'].rsplit(':', 1)[1])
            try:
                if original is None:
                    original = identity.read_bytes()
                assert query(listener) == '198.18.7.1'
                app.config['dns']['fake-ip']['range'] = '198.18.7.33/24'
                app.write()
                result = app.call('reload', boot=app.boot, timeout_ms=5000)
                assert result['result'] == 'committed', result
                assert query(listener) == '198.18.7.1'
                app.config['dns']['fake-ip']['range'] = '198.19.0.9/24'
                app.write()
                assert app.call('reload', boot=app.boot, timeout_ms=5000)['result'] == 'restart-required'
                assert query(listener) == '198.18.7.1'
                stop(app)
            finally:
                app.close()
            assert identity.read_bytes() == original, 'equivalent CIDRs changed durable identity'

        # 同一目录的另一真实池必须拒绝启动，不得重置既有身份或映射。
        mismatch = app.config
        mismatch['dns']['fake-ip']['range'] = '198.19.0.9/24'
        mismatch_path, mismatch_pid = root / 'mismatch.json', root / 'mismatch.pid'
        checked(binary, mismatch_path, mismatch)
        rejected = subprocess.run([binary, 'run', '-c', str(mismatch_path), '-p', str(mismatch_pid)],
                                  capture_output=True, text=True, timeout=8)
        assert rejected.returncode == 3 and 'state-corrupt' in rejected.stderr and not mismatch_pid.exists(), rejected
        assert identity.read_bytes() == original
        recovered_value = configuration('198.18.7.0/24', store, free_port(), persist=True)
        recovered = Instance(binary, root / 'after-mismatch', initial=recovered_value)
        try:
            listener = int(recovered_value['dns']['listeners'][0]['listen'].rsplit(':', 1)[1])
            assert query(listener) == '198.18.7.1'
            stop(recovered)
        finally:
            recovered.close()

        for index, cidr in enumerate(['198.18.0.0/31', '198.18.0.1/32', '198.18.0.0/33', 'fd00::/64', '198.18.0.0/x']):
            value = configuration(cidr, root / f'invalid-{index}', free_port())
            path, pid = root / f'invalid-{index}.json', root / f'invalid-{index}.pid'
            checked(binary, path, value, code=1)
            result = subprocess.run([binary, 'run', '-c', str(path), '-p', str(pid)], capture_output=True, text=True, timeout=8)
            assert result.returncode == 1 and not pid.exists(), result
    print('FakeIP CIDR: active normalized pools, check without binding, durable identity, reload and invalid pools passed')


if __name__ == '__main__':
    main()

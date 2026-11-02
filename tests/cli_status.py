#!/usr/bin/env python3
"""Check real owner snapshots, DNS results, generation ownership and bounded CLI output."""
from contextlib import ExitStack
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
from ctl_server_product import Instance, wait
from ipv6_product import UDP, TCP, DNS, EchoTCP, serving, exact


class Upstream(DNS):
    def handle(self):
        if self.server.bad:
            wire, channel = self.request
            channel.sendto(bytes([wire[0] ^ 255]) + wire[1:2] + b'\x81\x80' + wire[4:], self.client_address)
        else:
            super().handle()


def free_port():
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        return reserved.getsockname()[1]


def query(port, name, rcode=0):
    encoded = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
    wire = b'\x12\x34' + struct.pack('!HHHHH', 0x100, 1, 0, 0, 0) + encoded + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(6)
        stream.sendto(wire, ('127.0.0.1', port))
        answer = stream.recv(4096)
        assert answer[:2] == wire[:2] and answer[3] & 15 == rcode, answer.hex()


def connect(app, port, expected=0):
    stream = socket.create_connection(('127.0.0.1', app.port), timeout=3)
    stream.sendall(b'\x05\x01\x00')
    assert exact(stream, 2) == b'\x05\x00'
    stream.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', port))
    reply = exact(stream, 10)
    assert reply[1] == expected, reply.hex()
    return stream


def command(binary, app, args, code=0, machine=True):
    done = subprocess.run([binary, *args, '-p', str(app.pid), *(['--json'] if machine else [])],
                          capture_output=True, text=True, timeout=8)
    assert done.returncode == code and not done.stderr, (args, done)
    if machine:
        return json.loads(done.stdout)
    assert 0 < len(done.stdout.splitlines()) <= 64, done.stdout
    return done.stdout


def outbound(snapshot, name):
    return next(item for item in snapshot['outbounds']['items'] if item['name'] == name)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    fixture = str(Path(sys.argv[2]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-status-') as directory, ExitStack() as stack:
        root = Path(directory)
        upstream = stack.enter_context(serving(UDP, Upstream, '127.0.0.1'))
        upstream.bad = False
        echo = stack.enter_context(serving(TCP, EchoTCP, '127.0.0.1'))
        dns_port = free_port()
        groups = [{'name': 'choice', 'type': 'select', 'outbounds': ['DIRECT', 'REJECT'], 'default': 'DIRECT'}]
        groups += [{'name': f'组-{i}-' + '中' * 170, 'type': 'select',
                    'outbounds': ['DIRECT'], 'default': 'DIRECT'} for i in range(70)]
        nodes = [{'name': f'node-{i}', 'type': 'socks5', 'server': '127.0.0.1:9'} for i in range(70)]
        initial = {'dns': {'enable': True, 'cache': True, 'fake-ip': {'enable': False, 'persist': False},
                          'bootstrap': [f'127.0.0.1:{upstream.server_address[1]}'],
                          'default-server': 'real', 'listeners': [{'listen': f'127.0.0.1:{dns_port}', 'server': 'real'}],
                          'servers': [{'name': 'real', 'type': 'udp', 'address': [f'127.0.0.1:{upstream.server_address[1]}'],
                                       'outbound': 'DIRECT'}]}, 'outbounds': groups + nodes, 'rules': ['MATCH,choice']}
        app = Instance(binary, root / 'main', initial=initial)
        try:
            state = command(binary, app, ['status'])
            assert state['last_reload'] is None and state['uptime_ms'] >= 0
            services = {item['name']: item['state'] for item in state['services']}
            assert services['proxy'] == services['dns'] == 'active' and services['fakeip'] == 'disabled', services
            assert state['resources']['memory']['used'] < state['resources']['memory']['limit']
            assert state['logs']['output'] == 'disabled' and state['logs']['accepted'] == 0
            assert 'FTUN ' in command(binary, app, ['status'], machine=False)
            query(dns_port, 'dual.test')
            query(dns_port, 'dual.test')
            dns = command(binary, app, ['dns', 'status'])
            assert dns['queries']['total'] == dns['queries']['success'] == 2, dns
            assert dns['cache']['hits'] >= 1 and dns['cache']['misses'] >= 1 and dns['cache']['hit_rate'] > 0
            assert dns['upstreams']['items'][0]['success'] == 1 and dns['upstreams']['items'][0]['latency_ms'] is not None
            upstream.bad = True
            query(dns_port, 'bad.test', rcode=2)
            failed = command(binary, app, ['dns', 'status'])
            assert failed['state'] == 'degraded' and failed['queries']['failures'].get('timeout') == 1, failed
            assert failed['upstreams']['items'][0]['last_failure'] == 'timeout'
            upstream.bad = False
            query(dns_port, 'recover.test')
            healed = command(binary, app, ['dns', 'status'])
            assert healed['state'] == 'active' and healed['upstreams']['items'][0]['success'] == 2, healed
            assert 'Cache:' in command(binary, app, ['dns', 'status'], machine=False)
            proxy = command(binary, app, ['proxy', 'status'])
            assert proxy['groups']['total'] == 71 and proxy['groups']['truncated'] and proxy['groups']['count'] <= 64
            assert proxy['outbounds']['total'] == 72 and proxy['outbounds']['truncated']
            assert any(item['name_truncated'] for item in proxy['groups']['items'])
            assert proxy['groups']['items'][0]['selected'] == 'DIRECT'
            text = command(binary, app, ['proxy', 'status'], machine=False)
            assert 'Output truncated' in text
            stream = connect(app, echo.server_address[1])
            try:
                stream.sendall(b'held'); assert exact(stream, 4) == b'held'
                before = command(binary, app, ['proxy', 'status'])
                assert outbound(before, 'DIRECT')['tcp_active'] == 1 and outbound(before, 'DIRECT')['tcp_connections'] == 1
                assert command(binary, app, ['reload'])['result'] == 'committed'
                current = command(binary, app, ['proxy', 'status'])
                cumulative = command(binary, app, ['dns', 'status'])
                assert cumulative['queries'] == healed['queries'], (healed, cumulative)
                assert cumulative['cache']['hits'] >= healed['cache']['hits']
                assert cumulative['upstreams']['items'][0]['success'] >= healed['upstreams']['items'][0]['success']
                assert current['stats_generation'] > before['stats_generation'] and current['sessions']['tcp'] >= 1
                assert outbound(current, 'DIRECT')['tcp_active'] == outbound(current, 'DIRECT')['tcp_connections'] == 1
                stream.sendall(b'old'); assert exact(stream, 3) == b'old'
            finally:
                stream.close()
            wait(lambda: app.call('proxy.status')['sessions']['tcp'] == 0, app.output.read_text)
            assert outbound(app.call('proxy.status'), 'DIRECT')['tcp_active'] == 0
            with connect(app, echo.server_address[1]) as stream:
                stream.sendall(b'new'); assert exact(stream, 3) == b'new'
            with connect(app, free_port(), expected=2):
                pass
            wait(lambda: app.call('proxy.status')['sessions']['tcp'] == 0, app.output.read_text)
            counters = outbound(app.call('proxy.status'), 'DIRECT')
            assert counters['tcp_connections'] == 3 and sum(counters['tcp_failures'].values()) >= 1, counters
            app.config['rules'] = ['MATCH,REJECT']; app.write()
            command(binary, app, ['reload'])
            with connect(app, echo.server_address[1], expected=2):
                pass
            again = command(binary, app, ['dns', 'status'])
            assert again['queries'] == healed['queries'] and again['cache']['hits'] >= healed['cache']['hits'], again
            query(dns_port, 'after-reload.test')
            final_dns = command(binary, app, ['dns', 'status'])
            assert final_dns['queries']['total'] == healed['queries']['total'] + 1, final_dns
            assert final_dns['upstreams']['items'][0]['success'] == 3, final_dns
            refused = outbound(app.call('proxy.status'), 'REJECT')
            assert refused['tcp_connections'] == refused['tcp_failures']['rejected'] == 1, refused
            app.path.write_text('{"unknown":true}')
            command(binary, app, ['reload'], code=1)
            latest = command(binary, app, ['status'])['last_reload']
            assert latest['result'] == 'rejected' and latest['at'].endswith('Z'), latest
            app.write()
            assert command(binary, app, ['stop'])['result'] == 'stopped'
            assert app.process.wait(timeout=2) == 0
            assert command(binary, app, ['status'], code=1)['result'] == 'not-running'
        finally:
            app.close()
        # 两地址组中首地址失败、备用地址成功：查询成功仍须暴露首地址的退避。
        bad = stack.enter_context(serving(UDP, Upstream, '127.0.0.1'))
        bad.bad = True
        pair_dns = dict(initial['dns'])
        pair_dns['listeners'] = [{'listen': f'127.0.0.1:{free_port()}', 'server': 'pair'}]
        pair_dns['default-server'] = 'pair'
        pair_dns['servers'] = [{'name': 'pair', 'type': 'udp', 'address': [
            f'127.0.0.1:{bad.server_address[1]}', f'127.0.0.1:{upstream.server_address[1]}'], 'outbound': 'DIRECT'}]
        app = Instance(binary, root / 'pair', initial={'dns': pair_dns})
        try:
            query(int(pair_dns['listeners'][0]['listen'].rsplit(':', 1)[1]), 'dual.test')
            snapshot = command(binary, app, ['dns', 'status'])
            first, second = snapshot['upstreams']['items']
            assert snapshot['state'] == 'degraded' and snapshot['queries']['success'] == 1, snapshot
            assert first['failures'] == 1 and first['retry_at_ms'] > 0 and first['state'] == 'degraded', first
            assert second['success'] == 1 and second['state'] == 'active', second
        finally:
            app.close()
        # 文档地址未分配时原生bind进入等待，不改宿主地址/路由。
        waiting_dns = dict(initial['dns'])
        waiting_dns['listeners'] = [{'listen': f'192.0.2.77:{free_port()}', 'server': 'real'}]
        app = Instance(binary, root / 'waiting', initial={'dns': waiting_dns})
        try:
            snapshot = command(binary, app, ['dns', 'status'])
            assert snapshot['state'] == 'waiting' and snapshot['listeners']['items'][0]['state'] == 'waiting', snapshot
            assert snapshot['listeners']['items'][0]['retry_at_ms'] > 0, snapshot
            assert any(item['name'] == 'dns' and item['state'] == 'waiting' for item in app.call('status')['services'])
        finally:
            app.close()
        # 32个真实服务器各4个地址，共128个地址；序列化及CLI不得声称只有64个。
        many_dns = dict(initial['dns'])
        many_dns['listeners'] = [{'listen': f'127.0.0.1:{free_port()}', 'server': 'server-0'}]
        many_dns['default-server'] = 'server-0'
        many_dns['servers'] = [{'name': f'server-{i}', 'type': 'udp', 'outbound': 'DIRECT',
                                'address': [f'127.0.0.{j}:{upstream.server_address[1]}' for j in range(1, 5)]}
                               for i in range(32)]
        app = Instance(binary, root / 'many-dns', initial={'dns': many_dns})
        try:
            snapshot = command(binary, app, ['dns', 'status'])
            assert snapshot['upstreams']['total'] == 128 and snapshot['upstreams']['count'] == 64, snapshot
            assert snapshot['upstreams']['truncated'] and len(snapshot['upstreams']['items']) == 64
            assert 'Output truncated' in command(binary, app, ['dns', 'status'], machine=False)
        finally:
            app.close()
        missing = root / 'missing.frs'
        app = Instance(binary, root / 'frs-missing', initial={
            'frs': {'path': str(missing), 'url': 'http://127.0.0.1:9/rules.frs', 'auto-update': True, 'update-interval': '1s'},
            'rules': ['frs-ip,CN,REJECT', 'MATCH,DIRECT']})
        try:
            snapshot = command(binary, app, ['proxy', 'status'])
            assert snapshot['state'] == 'degraded' and snapshot['frs_state']['state'] == 'not-ready', snapshot
            assert snapshot['frs']['total'] is None
            assert any(item['name'] == 'frs' and item['state'] == 'not-ready' for item in app.call('status')['services'])
        finally:
            app.close()
        rules = root / 'loaded.frs'
        subprocess.run([fixture, '--write', str(rules)], check=True)
        app = Instance(binary, root / 'frs-loaded', initial={
            'frs': {'path': str(rules)}, 'rules': ['frs-ip,CN,REJECT', 'MATCH,DIRECT']})
        try:
            snapshot = command(binary, app, ['proxy', 'status'])
            assert snapshot['frs_state']['state'] == 'active' and snapshot['frs']['total'] > 0, snapshot
            assert any(item['name'] == 'CN' and item['ranges'] > 0 for item in snapshot['frs']['items']), snapshot
            assert all(item['updated_unix_ms'] == rules.stat().st_mtime_ns // 1000000 for item in snapshot['frs']['items']), snapshot
        finally:
            app.close()
    print('CLI status: host, real DNS counters/recovery, generations, proxy groups/failures, FRS and bounded output passed')


if __name__ == '__main__':
    main()

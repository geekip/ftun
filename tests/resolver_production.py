#!/usr/bin/env python3
"""Real Proxy ingress, resolver source selection and reload during resolution."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import errno
import json
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

from inbound_adapter_product import receive
from runtime_memory_datagram import associate


class TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (TimeoutError, ConnectionError):
            pass


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, channel = self.request
        channel.sendto(data, self.client_address)


class DNS:
    def __init__(self, address='127.0.0.1'):
        self.address = socket.inet_aton(address)
        self.received = []
        self.lock = threading.Lock()
        self.release = threading.Event()

    def answer(self, wire, tcp):
        end = 12
        labels = []
        while wire[end]:
            size = wire[end]
            labels.append(wire[end + 1:end + 1 + size].decode('ascii'))
            end += 1 + size
        end += 5
        name = '.'.join(labels)
        with self.lock:
            self.received.append((name, tcp))
        if name.startswith('hold-'):
            assert self.release.wait(10), 'held DNS query was never released'
        flags = 0x8180
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + self.address
        if name == 'missing.test':
            flags, answer = 0x8183, b''
        if name == 'tc.test' and not tcp:
            flags, answer = 0x8380, b''
        return wire[:2] + struct.pack('!5H', flags, 1, bool(answer), 0, 0) + wire[12:end] + answer

    def has(self, name):
        with self.lock:
            return any(item[0] == name for item in self.received)


class DNSTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        wire = receive(self.request, struct.unpack('!H', receive(self.request, 2))[0])
        response = self.server.dns.answer(wire, True)
        self.request.sendall(struct.pack('!H', len(response)) + response)


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, channel = self.request
        channel.sendto(self.server.dns.answer(wire, False), self.client_address)


@contextmanager
def serving(kind, handler, port=0, dns=None):
    server = kind(('127.0.0.1', port), handler)
    server.dns = dns
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        assert not worker.is_alive()


def tcp_exchange(port, domain, target, rejected=False):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
        encoded = domain.encode('ascii')
        client.sendall(b'\x05\x01\x00\x05\x01\x00\x03' + bytes([len(encoded)]) +
                       encoded + struct.pack('!H', target))
        assert receive(client, 2) == b'\x05\x00'
        reply = receive(client, 10)
        assert reply[1] != 0 if rejected else reply[1] == 0, (domain, reply.hex())
        if not rejected:
            payload = b'resolver-tcp:' + encoded
            client.sendall(payload)
            assert receive(client, len(payload)) == payload


def udp_exchange(port, domain, target):
    control, data, relay = associate(port)
    try:
        data.settimeout(5)
        encoded = domain.encode('ascii')
        header = b'\0\0\0\x03' + bytes([len(encoded)]) + encoded + struct.pack('!H', target)
        payload = b'resolver-udp:' + encoded
        data.sendto(header + payload, relay)
        reply, source = data.recvfrom(65535)
        assert source == relay and reply.endswith(payload), (domain, reply)
    finally:
        control.close()
        data.close()


def wait_for(predicate, process, seconds=5):
    deadline = time.monotonic() + seconds
    while not predicate():
        assert process.poll() is None, f'process exited {process.returncode}'
        assert time.monotonic() < deadline, 'condition did not become true'
        time.sleep(0.01)


def exercise(binary, root, mode, dns, dns_port, other, other_port, tcp_port, udp_port):
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    config = {'base': {'state-cache': False}, 'log': {'level': 'silent'},
              'inbounds': [{'name': 'socks', 'type': 'socks5', 'udp': True,
                            'listen': f'127.0.0.1:{port}'}],
              'rules': ['IP-CIDR,127.0.0.0/8,DIRECT', 'MATCH,REJECT'],
              'dns': {'enable': mode != 'system'}}
    if mode != 'system':
        config['dns'].update(cache=False, bootstrap=[f'127.0.0.1:{other_port}'])
    if mode == 'named':
        config['dns'].update({'default-server': 'real', 'servers': [
            {'name': 'real', 'type': 'udp', 'address': [f'127.0.0.1:{dns_port}'],
             'outbound': 'DIRECT'}]})
    path = root / f'{mode}.json'
    path.write_text(json.dumps(config))
    log_path = root / f'{mode}.log'
    with log_path.open('w+') as log:
        process = subprocess.Popen([binary, 'run', '-c', str(path)], stdout=log, stderr=log)
        try:
            def listening():
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        return True
                except ConnectionRefusedError:
                    return False
            wait_for(listening, process)
            domain = 'localhost' if mode == 'system' else f'{mode}.test'
            tcp_exchange(port, domain, tcp_port)
            udp_exchange(port, domain, udp_port)
            tcp_exchange(port, 'blocked.test', tcp_port, rejected=True)
            assert not dns.has('blocked.test') and not other.has('blocked.test')
            source = {'system': 0, 'bootstrap': 1, 'named': 2}[mode]
            assert f'source={source} generation=1' in log_path.read_text()
            if mode == 'named':
                tcp_exchange(port, 'tc.test', tcp_port)
                assert ('tc.test', False) in dns.received and ('tc.test', True) in dns.received
                tcp_exchange(port, 'missing.test', tcp_port, rejected=True)
                assert not other.received, 'named DNS failure fell back to Bootstrap'
                with ThreadPoolExecutor(max_workers=2) as pool:
                    tcp = pool.submit(tcp_exchange, port, 'hold-tcp.test', tcp_port)
                    udp = pool.submit(udp_exchange, port, 'hold-udp.test', udp_port)
                    try:
                        wait_for(lambda: dns.has('hold-tcp.test') and dns.has('hold-udp.test'), process)
                        config['dns']['servers'][0]['address'] = [f'127.0.0.1:{other_port}']
                        path.write_text(json.dumps(config))
                        process.send_signal(signal.SIGHUP)
                        wait_for(lambda: 'reload committed' in log_path.read_text(), process)
                    finally:
                        dns.release.set()
                    tcp.result(timeout=5)
                    udp.result(timeout=5)
                # 新请求必须走新 DNS；127.0.0.2 上没有 echo listener。
                tcp_exchange(port, 'fresh.test', tcp_port, rejected=True)
                assert other.has('fresh.test')
                assert 'source=2 generation=2' in log_path.read_text()
                with socket.create_connection(('127.0.0.1', port), timeout=5) as pending:
                    domain = b'hold-stop.test'
                    pending.sendall(b'\x05\x01\x00\x05\x01\x00\x03' +
                                    bytes([len(domain)]) + domain + struct.pack('!H', tcp_port))
                    assert receive(pending, 2) == b'\x05\x00'
                    wait_for(lambda: other.has('hold-stop.test'), process)
                    # 上游尚未返回时停止；不得依赖 DNS 应答才能排空。
                    process.terminate()
                    assert process.wait(timeout=5) == 0, f'pending stop exited {process.returncode}'
                    other.release.set()
            else:
                process.terminate()
                assert process.wait(timeout=5) == 0, f'stop exited {process.returncode}'
            text = log_path.read_text()
            assert 'AddressSanitizer' not in text and 'runtime error:' not in text, text
            print(f'PASS production resolver {mode}: TCP/UDP, source, rejection and stop')
        except BaseException:
            print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            dns.release.set()
            other.release.set()
            if process.poll() is None:
                process.kill()
                process.wait()


@contextmanager
def serving_dns(dns):
    # 两种传输同时持有同一端口后才启动产品；仅重选绑定冲突的端口。
    for _ in range(100):
        servers = ExitStack()
        try:
            port = servers.enter_context(serving(UDPServer, DNSUDP, dns=dns))
            servers.enter_context(serving(TCPServer, DNSTCP, port=port, dns=dns))
        except OSError as error:
            servers.close()
            if error.errno != errno.EADDRINUSE:
                raise
            continue
        try:
            yield port
        finally:
            servers.close()
        return
    raise RuntimeError('could not reserve paired DNS TCP/UDP port')


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-resolver-') as directory, ExitStack() as stack:
        tcp_port = stack.enter_context(serving(TCPServer, EchoTCP))
        udp_port = stack.enter_context(serving(UDPServer, EchoUDP))
        for mode in ('named', 'bootstrap', 'system'):
            with ExitStack() as servers:
                dns = DNS()
                other = DNS('127.0.0.2' if mode == 'named' else '127.0.0.1')
                dns_port = servers.enter_context(serving_dns(dns))
                other_port = servers.enter_context(serving_dns(other))
                exercise(binary, Path(directory), mode, dns, dns_port, other, other_port, tcp_port, udp_port)


if __name__ == '__main__':
    main()

"""恢复契约验收（R1～R13）的测试设施。

整个运行在 `unshare -mn` 出来的私有网络与挂载命名空间里：宿主的网络、路由和
/run 都不受影响。命名空间内再建一个 peer 命名空间（veth + 多个地址）放假上游，
故障工具是 nft 丢包、`ip link down` 和地址/路由变更。
"""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

SKIP = 77
MARK = 'FTUN_RESILIENCE_ISOLATED'


class Skip(Exception):
    """场景依赖尚未实现的能力：以退出码 77 跳过，并写明原因，不当作通过。"""


def isolate(argv):
    """在私有命名空间里重新执行自己；无法隔离时跳过。"""
    if os.environ.get(MARK) == '1':
        return
    if shutil.which('unshare') is None or os.geteuid() != 0:
        print('resilience: needs root and unshare', file=sys.stderr)
        sys.exit(SKIP)
    env = dict(os.environ, **{MARK: '1'})
    result = subprocess.run(['unshare', '--mount', '--net', '--propagation', 'private',
                             sys.executable] + argv, env=env)
    sys.exit(result.returncode)


def sh(*argv, check=True, capture=False, **kwargs):
    result = subprocess.run([str(a) for a in argv], check=False, text=True,
                            capture_output=capture, **kwargs)
    if check and result.returncode != 0:
        raise RuntimeError(f'{" ".join(map(str, argv))} -> {result.returncode}: '
                           f'{result.stderr if capture else ""}')
    return result


def wait_until(predicate, timeout, interval=0.1, what='condition'):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (OSError, AssertionError) as error:
            last = error
        time.sleep(interval)
    raise AssertionError(f'timeout waiting for {what} (last={last!r})')


def free_tcp_port():
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        return reserve.getsockname()[1]


# ---------------------------------------------------------------- 探测客户端

def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError('closed')
        data += chunk
    return data


def socks_open(proxy, target, port, timeout=5.0):
    """经 SOCKS5 打开到 target:port 的连接。返回 (socket, 回复码)；回复码非 0 时 socket 已关闭。"""
    sock = socket.create_connection(proxy, timeout=timeout)
    try:
        sock.sendall(b'\x05\x01\x00')
        if recv_exact(sock, 2) != b'\x05\x00':
            raise ConnectionError('method rejected')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(target) + struct.pack('>H', port))
        reply = recv_exact(sock, 10)
    except BaseException:
        sock.close()
        raise
    if reply[1] != 0:
        sock.close()
        return None, reply[1]
    return sock, 0


def socks_echo(proxy, target, port, payload=b'ping', timeout=5.0):
    sock, code = socks_open(proxy, target, port, timeout)
    if sock is None:
        raise ConnectionError(f'socks reply {code}')
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        return recv_exact(sock, len(payload)) == payload
    finally:
        sock.close()


def dns_query(server, name='probe.test', timeout=3.0, ident=0x4242):
    """向 server 发 A 查询；返回应答里的第一个 IPv4（字符串），超时或畸形返回 None。"""
    labels = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, server)
            data, _ = sock.recvfrom(4096)
        except (TimeoutError, OSError):
            return None
    if len(data) < 12 or data[:2] != packet[:2]:
        return None
    if struct.unpack('!H', data[6:8])[0] == 0:
        return f'rcode{data[3] & 15}'
    return socket.inet_ntoa(data[-4:])


# ---------------------------------------------------------------- 进程观测

def proc_stats(pid):
    """(打开的 fd 数, RSS KiB, 累计 CPU tick)。"""
    fds = len(os.listdir(f'/proc/{pid}/fd'))
    rss = 0
    for line in Path(f'/proc/{pid}/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            rss = int(line.split()[1])
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return fds, rss, int(fields[11]) + int(fields[12])


# ---------------------------------------------------------------- 实验室

class Lab:
    """peer 命名空间 + 假上游 + 被测的 ftun 进程。"""

    PEER_ADDRESSES = ('198.51.100.2', '198.51.100.53', '198.51.100.54', '198.51.100.80', '198.51.100.7')

    def __init__(self, ftun, fixture, scale=1.0):
        self.ftun = ftun
        self.fixture = fixture
        self.scale = scale
        self.root = Path(tempfile.mkdtemp(prefix='ftun-resilience-'))
        self.control = self.root / 'control'
        self.control.mkdir()
        self.process = None
        self.fakes = None
        self.log = self.root / 'ftun.log'
        self.config_path = self.root / 'config.json'
        self.output = self.root / 'ftun.out'
        self.socks = ('127.0.0.1', 11081)
        self.dns = ('127.0.0.1', 15353)
        self._setup_network()

    def seconds(self, value):
        return value * self.scale

    # -- 网络 ------------------------------------------------------------
    def _setup_network(self):
        # /run 换成私有 tmpfs：ip netns 与 ftun 的实例锁都落在这里，不碰宿主。
        sh('mount', '-t', 'tmpfs', 'tmpfs', '/run')
        sh('ip', 'link', 'set', 'lo', 'up')
        sh('ip', 'netns', 'add', 'peer')
        sh('ip', 'link', 'add', 'phys0', 'type', 'veth', 'peer', 'name', 'peer0')
        sh('ip', 'link', 'set', 'peer0', 'netns', 'peer')
        self.peer('ip', 'link', 'set', 'lo', 'up')
        self.peer('ip', 'link', 'set', 'peer0', 'up')
        for address in self.PEER_ADDRESSES:
            self.peer('ip', 'address', 'add', f'{address}/24', 'dev', 'peer0')
        sh('ip', 'link', 'set', 'phys0', 'up')
        sh('sysctl', '-q', '-w', 'net.ipv4.conf.phys0.rp_filter=0')

    def peer(self, *argv, **kwargs):
        return sh('ip', 'netns', 'exec', 'peer', *argv, **kwargs)

    def attach(self):
        """给 phys0 配地址（默认就是联网状态）。"""
        sh('ip', 'address', 'add', '198.51.100.1/24', 'dev', 'phys0')

    def detach(self):
        sh('ip', 'address', 'flush', 'dev', 'phys0')

    def blackhole(self):
        """phys0 上双向丢弃全部报文，模拟断网（链路仍然 up）。"""
        sh('nft', 'add', 'table', 'ip', 'lab')
        sh('nft', 'add', 'chain', 'ip', 'lab', 'out', '{', 'type', 'filter', 'hook', 'output',
           'priority', '0', ';', '}')
        sh('nft', 'add', 'chain', 'ip', 'lab', 'in', '{', 'type', 'filter', 'hook', 'input',
           'priority', '0', ';', '}')
        sh('nft', 'add', 'rule', 'ip', 'lab', 'out', 'oifname', 'phys0', 'drop')
        sh('nft', 'add', 'rule', 'ip', 'lab', 'in', 'iifname', 'phys0', 'drop')

    def restore(self):
        sh('nft', 'delete', 'table', 'ip', 'lab', check=False, capture=True)

    # -- 假上游 ----------------------------------------------------------
    def start_fakes(self):
        frs = self.root / 'source.frs'
        sh(self.fixture, '--write', frs)
        ready = self.control / 'ready'
        self.fakes = subprocess.Popen(
            ['ip', 'netns', 'exec', 'peer', sys.executable,
             str(Path(__file__).with_name('fakes.py')), str(self.control), str(frs)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        wait_until(lambda: ready.exists(), 10, what='fakes ready')

    def mode(self, name, value):
        (self.control / name).write_text(value)

    def counter(self, name):
        path = self.control / name
        return int(path.read_text() or 0) if path.exists() else 0

    # -- ftun ------------------------------------------------------------
    def config(self, **sections):
        """默认配置；sections 按顶层键整体覆盖或用 dict 合并（以 '+' 结尾的键为合并）。"""
        config = {
            'base': {'state-cache': False, 'cache-file': str(self.root / 'cache'),
                     'watchdog': '4s',
                     'timeouts': {'connect': '2s', 'handshake': '3s',
                                  'tcp-keepalive': {'idle': '2s', 'interval': '1s', 'count': 2},
                                  'write-progress': os.environ.get('FTUN_R8_WRITE_PROGRESS', '10s')}},
            'log': {'level': 'info', 'file': str(self.log)},
            'frs': {'path': str(self.root / 'rules.frs'), 'url': 'http://frs.lab.test/rules',
                    'auto-update': True, 'update-interval': '2s'},
            'dns': {'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                    'bootstrap': ['198.51.100.53:53'], 'default-server': 'up',
                    'listeners': [{'listen': '127.0.0.1:15353', 'server': 'up'}],
                    'servers': [{'name': 'up', 'type': 'udp', 'outbound': 'DIRECT',
                                 'address': ['198.51.100.53:53', '198.51.100.54:53']}]},
            'inbounds': [{'name': 'in', 'type': 'socks5', 'listen': '127.0.0.1:11081'}],
            'rules': ['frs-ip,CN,REJECT', 'MATCH,DIRECT'],
        }
        for key, value in sections.items():
            if value is None:
                config.pop(key, None)
            else:
                config[key] = value
        return config

    def write_config(self, config):
        self.config_path.write_text(json.dumps(config))

    def start(self, config=None, prefix=None, quiet=False):
        if config is not None:
            self.write_config(config)
        argv = (prefix or []) + [self.ftun, 'run', '-c', str(self.config_path)]
        self.process = subprocess.Popen(argv, stdout=open(self.output, 'ab'),
                                        stderr=subprocess.STDOUT)
        return self.process

    def alive(self):
        assert self.process.poll() is None, \
            f'ftun exited: {self.process.returncode}\n{self.log_text()[-2000:]}'

    def log_text(self):
        return self.log.read_text() if self.log.exists() else ''

    def wait_ready(self, timeout=15):
        wait_until(lambda: socket.create_connection(self.socks, timeout=1).close() or True,
                   timeout, what='socks listener')

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def close(self):
        self.stop()
        if self.fakes is not None:
            self.fakes.terminate()
            try:
                self.fakes.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.fakes.kill()
        self.restore()
        sh('ip', 'netns', 'delete', 'peer', check=False)
        shutil.rmtree(self.root, ignore_errors=True)

    # -- 判定 ------------------------------------------------------------
    def socks_ok(self, timeout=4.0):
        try:
            return socks_echo(self.socks, '198.51.100.7', 7000, timeout=timeout)
        except (OSError, ConnectionError):
            return False

    def dns_answer(self, timeout=3.0, server=None):
        return dns_query(server or self.dns, timeout=timeout)

    def snapshot(self):
        return proc_stats(self.process.pid)

    def assert_resources(self, baseline, fd_slack=16, rss_factor=1.6, rss_slack_kib=8192):
        """A7 资源不变量（候选阈值，开测前固定）：fd 与 RSS 不随故障增长。"""
        fds, rss, _ = self.snapshot()
        assert fds <= baseline[0] + fd_slack, f'fd grew {baseline[0]} -> {fds}'
        assert rss <= baseline[1] * rss_factor + rss_slack_kib, f'rss grew {baseline[1]} -> {rss}'

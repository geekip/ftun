#!/usr/bin/env python3
"""R13 长稳：按事先固定的计划反复注入 R2～R8 的故障，全程同一进程。

用法：soak.py --ftun 路径 --fixture 路径 --kind combined|dns|proxy --duration 秒 --seed N --out 目录
整个运行在 `unshare -mn` 私有命名空间里（由 lib.isolate 重新执行自己），宿主网络不受影响。
输出（都在 --out 下）：manifest.json（输入与计划）、events.jsonl（每次故障的结果与恢复时间）、
probes.csv（持续探测）、samples.csv（资源采样）、summary.json（结束时写入）。
R9、R10、R11 不进 R13：它们要么依赖测试钩子构建，要么本身就会重启进程。"""
import argparse
import csv
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import lib  # noqa: E402

lib.isolate([str(Path(__file__).resolve())] + sys.argv[1:])

import scenarios  # noqa: E402
from lib import dns_query, sh, socks_echo, socks_open, wait_until  # noqa: E402

RECOVERY_MAX = scenarios.RECOVERY_MAX
ROUTING_MARK = '0x4654'
SAMPLE_SECONDS = 60
PROBE_SECONDS = 5
EVENTS = {
    'proxy': ['R2', 'R3', 'R4', 'R5', 'R6', 'R8'],
    'dns': ['R2', 'R3', 'R4', 'R6', 'R7'],
    'combined': ['R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8'],
}


class Run:
    def __init__(self, args, lab):
        self.args = args
        self.lab = lab
        self.out = Path(args.out)
        self.start = time.monotonic()
        self.pid = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.fault_until = 0.0  # 故障窗口（含恢复期）结束的单调时刻，探测据此标注
        self.events = open(self.out / 'events.jsonl', 'a', buffering=1)
        self.probes = csv.writer(open(self.out / 'probes.csv', 'a', buffering=1))
        self.probes.writerow(['t', 'probe', 'ok', 'latency_ms', 'in_fault'])
        self.samples = csv.writer(open(self.out / 'samples.csv', 'a', buffering=1))
        self.samples.writerow(['t', 'pid', 'fds', 'rss_kib', 'pss_kib', 'hwm_kib', 'threads',
                               'cpu_ticks', 'cg_mem', 'cg_mem_peak', 'cg_pids', 'egress_packets'])
        self.failures = 0
        self.quiet = None

    def now(self):
        return round(time.monotonic() - self.start, 1)

    # -- 记录 ------------------------------------------------------------
    def event(self, kind, began, ok, detail='', recovery=None):
        record = {'kind': kind, 't_start': began, 't_end': self.now(), 'ok': ok,
                  'recovery_s': recovery, 'detail': detail}
        if not ok:
            self.failures += 1
        self.events.write(json.dumps(record, ensure_ascii=False) + '\n')

    def probe(self, name, ok, latency):
        with self.lock:
            self.probes.writerow([self.now(), name, int(ok), round(latency * 1000, 1),
                                  int(time.monotonic() < self.fault_until)])

    # -- 后台线程 --------------------------------------------------------
    def prober(self):
        kind = self.args.kind
        while not self.stop.wait(PROBE_SECONDS):
            if kind in ('combined', 'proxy'):
                began = time.monotonic()
                ok = bool(self.lab.socks_ok(timeout=3))
                self.probe('socks', ok, time.monotonic() - began)
            if kind in ('combined', 'dns'):
                began = time.monotonic()
                ok = dns_query(self.lab.dns, timeout=2) is not None
                self.probe('dns', ok, time.monotonic() - began)

    def quiet_keeper(self):
        """一条长期安静的健康连接：每分钟收发一次，非故障期间不能被关。"""
        if self.args.kind == 'dns':
            return
        while not self.stop.wait(60):
            began = time.monotonic()
            ok = False
            try:
                if self.quiet is None:
                    self.quiet, _ = socks_open(self.lab.socks, '198.51.100.7', 7000)
                if self.quiet is not None:
                    self.quiet.setblocking(True)
                    self.quiet.settimeout(3)
                    self.quiet.sendall(b'alive')
                    ok = self.quiet.recv(5) == b'alive'
            except OSError:
                ok = False
            if not ok:
                if self.quiet is not None:
                    self.quiet.close()
                self.quiet = None
            self.probe('quiet', ok, time.monotonic() - began)

    def sampler(self):
        cgroup = None
        try:
            path = Path('/proc/self/cgroup').read_text().strip().split(':')[-1]
            cgroup = Path('/sys/fs/cgroup') / path.lstrip('/')
        except OSError:
            pass
        while True:
            row = [self.now(), self.pid]
            try:
                fds, rss, ticks = lib.proc_stats(self.pid)
                status = Path(f'/proc/{self.pid}/status').read_text()
                threads = int(re.search(r'Threads:\s+(\d+)', status).group(1))
                hwm = int(re.search(r'VmHWM:\s+(\d+)', status).group(1))
                pss = 0
                try:
                    pss = int(re.search(r'Pss:\s+(\d+)', Path(f'/proc/{self.pid}/smaps_rollup').read_text()).group(1))
                except (OSError, AttributeError):
                    pass
                row += [fds, rss, pss, hwm, threads, ticks]
            except (OSError, AttributeError):
                row += [-1] * 6
            for name in ('memory.current', 'memory.peak', 'pids.current'):
                try:
                    row.append(int((cgroup / name).read_text()))
                except (OSError, TypeError, ValueError):
                    row.append(-1)
            row.append(self.egress())
            self.samples.writerow(row)
            if self.stop.wait(SAMPLE_SECONDS):
                break

    # -- 未授权物理出口 --------------------------------------------------
    def install_egress_watch(self):
        """TUN 自动路由开启时，从 phys0 离开且没有 FTUN 标记的 IP 报文视为未授权出口
        （kernel 对已关闭连接的 RST 不计入）。"""
        if self.args.kind != 'combined':
            return
        sh('nft', 'add', 'table', 'ip', 'soakwatch')
        sh('nft', 'add', 'chain', 'ip', 'soakwatch', 'out', '{', 'type', 'filter', 'hook',
           'output', 'priority', '0', ';', '}')
        sh('nft', 'add', 'rule', 'ip', 'soakwatch', 'out', 'oifname', 'phys0', 'meta', 'mark',
           '!=', ROUTING_MARK, 'tcp', 'flags', '&', 'rst', '==', '0', 'counter')
        sh('nft', 'add', 'rule', 'ip', 'soakwatch', 'out', 'oifname', 'phys0', 'meta', 'mark',
           '!=', ROUTING_MARK, 'meta', 'l4proto', '!=', 'tcp', 'counter')

    def egress(self):
        if self.args.kind != 'combined':
            return -1
        result = sh('nft', '-j', 'list', 'chain', 'ip', 'soakwatch', 'out', check=False, capture=True)
        total = 0
        try:
            for item in json.loads(result.stdout)['nftables']:
                for expr in item.get('rule', {}).get('expr', []):
                    if 'counter' in expr:
                        total += expr['counter']['packets']
        except (ValueError, KeyError):
            return -1
        return total

    # -- 通用判定 --------------------------------------------------------
    def healthy(self, within):
        """DNS、Proxy 都在上限内回来；返回恢复用时（秒）或抛出 AssertionError。"""
        began = time.monotonic()
        kind = self.args.kind
        if kind in ('combined', 'dns'):
            wait_until(lambda: self.lab.dns_answer(timeout=2) is not None, within, what='dns')
        if kind in ('combined', 'proxy'):
            wait_until(self.lab.socks_ok, within, what='proxy')
        return round(time.monotonic() - began, 1)

    def invariants(self):
        assert self.lab.process.poll() is None, f'ftun exited: {self.lab.process.returncode}'
        assert self.lab.process.pid == self.pid, 'pid changed'
        assert 'watchdog' not in self.lab.output.read_text(), 'watchdog fired'
        if self.args.kind == 'combined':
            assert sh('ip', 'link', 'show', 'ftun-soak', check=False, capture=True).returncode == 0, \
                'tun device missing'

    def run_event(self, kind, function):
        began = self.now()
        self.fault_until = time.monotonic() + 3600
        try:
            recovery = function()
            self.invariants()
            self.event(kind, began, True, recovery=recovery)
        except Exception as error:  # noqa: BLE001 - 记录任何失败后继续，保留完整证据
            self.event(kind, began, False, detail=f'{type(error).__name__}: {error}')
            self.lab.restore()
            try:
                sh('ip', 'link', 'set', 'phys0', 'up', check=False)
                sh('ip', 'address', 'replace', '198.51.100.1/24', 'dev', 'phys0', check=False)
            except Exception:  # noqa: BLE001
                pass
        finally:
            self.fault_until = time.monotonic() + RECOVERY_MAX

    # -- 故障 ------------------------------------------------------------
    def fault_outage(self, seconds):
        self.lab.blackhole()
        time.sleep(seconds)
        self.lab.restore()
        return self.healthy(RECOVERY_MAX)

    def fault_address(self):
        sh('ip', 'link', 'set', 'phys0', 'down')
        time.sleep(5)
        sh('ip', 'link', 'set', 'phys0', 'up')
        sh('ip', 'address', 'replace', '198.51.100.9/24', 'dev', 'phys0')
        time.sleep(5)
        sh('ip', 'address', 'replace', '198.51.100.1/24', 'dev', 'phys0')
        sh('ip', 'address', 'del', '198.51.100.9/24', 'dev', 'phys0', check=False)
        return self.healthy(RECOVERY_MAX)

    def fault_flap(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            sh('ip', 'link', 'set', 'phys0', 'down')
            time.sleep(10)
            sh('ip', 'link', 'set', 'phys0', 'up')
            sh('ip', 'address', 'replace', '198.51.100.1/24', 'dev', 'phys0')
            time.sleep(10)
            self.invariants()
        return self.healthy(RECOVERY_MAX)

    def fault_fds(self):
        pid = self.pid
        soft = sh('prlimit', '--pid', str(pid), '--nofile', '-o', 'SOFT,HARD', '--noheadings',
                  capture=True).stdout.split()
        low = lib.proc_stats(pid)[0] + 40
        sh('prlimit', '--pid', str(pid), f'--nofile={low}:{soft[1]}')
        held = []
        try:
            for _ in range(400):
                try:
                    held.append(socket.create_connection(self.lab.socks, timeout=1))
                except OSError:
                    break
                time.sleep(0.002)
            time.sleep(5)
            self.invariants()
        finally:
            for sock in held:
                sock.close()
            sh('prlimit', '--pid', str(pid), f'--nofile={soft[0]}:{soft[1]}')
        return self.healthy(RECOVERY_MAX)

    def fault_reload(self):
        good = self.lab.config_path.read_text()
        committed = self.lab.output.read_text().count('reload committed')
        try:
            for index in range(6):
                self.lab.config_path.write_text('{"base": ')
                self.lab.process.send_signal(signal.SIGHUP)
                time.sleep(0.4)
                self.invariants()
                variant = json.loads(good)
                # 每一代只在规则最前面加一条不影响结构的端口规则：模块组成不变，不会要求重启。
                variant['rules'] = [f'DST-PORT,{20000 + index},REJECT'] + json.loads(good)['rules']
                self.lab.config_path.write_text(json.dumps(variant))
                self.lab.process.send_signal(signal.SIGHUP)
                committed += 1
                wait_until(lambda: self.lab.output.read_text().count('reload committed') >= committed,
                           15, what=f'reload {index} committed')
                if index == 2:
                    self.lab.blackhole()
                if index == 4:
                    self.lab.restore()
        finally:
            self.lab.restore()
            self.lab.config_path.write_text(good)
            self.lab.process.send_signal(signal.SIGHUP)
            committed += 1
            wait_until(lambda: self.lab.output.read_text().count('reload committed') >= committed,
                       15, what='original configuration restored')
        return self.healthy(RECOVERY_MAX)

    def fault_dns(self):
        lab = self.lab
        for broken in ('silent', 'malformed', 'badid'):
            lab.mode('dns53.mode', broken)
            wait_until(lambda: lab.dns_answer(timeout=6) == '203.0.113.6' or None, 15,
                       what=f'failover on {broken}')
            lab.mode('dns53.mode', 'normal')
            wait_until(lambda: lab.dns_answer(timeout=3) == '203.0.113.5' or None, 45,
                       interval=0.5, what=f'switch back after {broken}')
        return self.healthy(RECOVERY_MAX)

    def fault_loss(self):
        lab = self.lab
        slow, _ = socks_open(lab.socks, '198.51.100.7', 7001)
        stuck, _ = socks_open(lab.socks, '198.51.100.7', 7002)
        lost, _ = socks_open(lab.socks, '198.51.100.7', 7000)
        assert slow is not None and stuck is not None and lost is not None
        scenarios.fill(slow)
        scenarios.fill(stuck)
        time.sleep(16)
        assert not scenarios.closed_by_peer(slow, 0.5), 'slow but progressing connection was closed'
        assert scenarios.closed_by_peer(stuck, 12), 'stalled zero-window connection was not reclaimed'
        lab.blackhole()
        assert scenarios.closed_by_peer(lost, 25), 'silently lost connection was not reclaimed'
        lab.restore()
        slow.close()
        return self.healthy(RECOVERY_MAX)

    def perform(self, name, long_outage=False):
        if name == 'R2':
            seconds = self.rng.choice([5, 10] if self.args.fast else [30, 60, 120, 300])
            self.run_event(f'R2-outage-{seconds}s', lambda: self.fault_outage(seconds))
        elif name == 'R3':
            self.run_event('R3-address-change', self.fault_address)
        elif name == 'R4':
            span = 40 if self.args.fast else 300
            self.run_event(f'R4-flap-{span}s', lambda: self.fault_flap(span))
        elif name == 'R5':
            self.run_event('R5-fd-exhaustion', self.fault_fds)
        elif name == 'R6':
            self.run_event('R6-reload-storm', self.fault_reload)
        elif name == 'R7':
            self.run_event('R7-dns-upstream', self.fault_dns)
        elif name == 'R8':
            self.run_event('R8-silent-loss', self.fault_loss)

    # -- 主流程 ----------------------------------------------------------
    def configure(self):
        lab = self.lab
        kind = self.args.kind
        extra = {}
        if kind == 'dns':
            extra = {'frs': None, 'inbounds': [], 'rules': ['MATCH,DIRECT']}
        elif kind == 'proxy':
            # 没有 DNS 模块时 FRS 地址必须是 IP 字面量（域名需要本地解析器）。
            extra = {'dns': {'enable': False},
                     'frs': {'path': str(lab.root / 'rules.frs'), 'url': 'http://198.51.100.80/rules',
                             'auto-update': True, 'update-interval': '2s'}}
        config = lab.config(**extra)
        if kind == 'combined':
            config['tun'] = {'interface': 'ftun-soak', 'mtu': 1400,
                             'ipv4': {'address': '10.77.31.1/30'},
                             'auto-route': True, 'strict-route': True}
            config['inbounds'].append({'name': 'tun-in', 'type': 'tun', 'tcp': True,
                                       'udp': False, 'dns-hijack': False})
        return config

    def execute(self):
        lab = self.lab
        lab.attach()
        lab.start_fakes()
        lab.start(self.configure())
        self.pid = lab.process.pid
        if self.args.kind != 'dns':
            lab.wait_ready()
        def ready():
            try:
                self.healthy(3)
                return True
            except AssertionError:
                return False
        wait_until(ready, 40, what='baseline')
        self.install_egress_watch()
        time.sleep(3)
        manifest = json.loads((self.out / 'manifest.json').read_text())
        manifest.update({'pid': self.pid, 'baseline': lib.proc_stats(self.pid)[:2]})
        (self.out / 'manifest.json').write_text(json.dumps(manifest, indent=1))
        for target in (self.prober, self.quiet_keeper, self.sampler):
            threading.Thread(target=target, daemon=True).start()
        self.rng = random.Random(self.args.seed)
        names = [n for n in EVENTS[self.args.kind] if not self.args.only or n in self.args.only.split(',')]
        deadline = self.start + self.args.duration
        long_done = self.args.long_outage == 0
        round_index = 0
        while time.monotonic() < deadline:
            order = names[:]
            self.rng.shuffle(order)
            for name in order:
                if time.monotonic() >= deadline:
                    break
                time.sleep(min(self.args.pause, max(0, deadline - time.monotonic())))
                if time.monotonic() >= deadline:
                    break
                if not long_done and time.monotonic() - self.start > self.args.duration / 2:
                    long_done = True
                    self.run_event(f'R2-outage-{self.args.long_outage}s',
                                   lambda: self.fault_outage(self.args.long_outage))
                self.perform(name)
            round_index += 1
        time.sleep(30)
        self.invariants()

    def finish(self, error):
        self.stop.set()
        time.sleep(1)
        code = None
        if self.lab.process is not None and self.lab.process.poll() is None:
            self.lab.process.send_signal(signal.SIGTERM)
            try:
                code = self.lab.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.lab.process.kill()
                code = 'killed'
        else:
            code = self.lab.process.returncode if self.lab.process else None
        for name, source in (('ftun.out', self.lab.output), ('ftun.log', self.lab.log)):
            try:
                (self.out / name).write_bytes(source.read_bytes())
            except OSError:
                pass
        summary = {'elapsed_s': self.now(), 'planned_s': self.args.duration,
                   'events_failed': self.failures, 'error': error, 'exit_code': code,
                   'completed': error is None}
        (self.out / 'summary.json').write_text(json.dumps(summary, indent=1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ftun', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--kind', choices=sorted(EVENTS), default='combined')
    parser.add_argument('--duration', type=float, default=7200)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--pause', type=float, default=120)
    parser.add_argument('--long-outage', type=int, default=0)
    parser.add_argument('--only', default='', help='只注入这些事件（逗号分隔），调试用')
    parser.add_argument('--fast', action='store_true', help='冒烟用：缩短断网与抖动时长')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    Path(args.out).mkdir(parents=True, exist_ok=True)
    manifest = {'argv': sys.argv[1:], 'kind': args.kind, 'seed': args.seed,
                'duration_s': args.duration, 'pause_s': args.pause,
                'long_outage_s': args.long_outage, 'events': EVENTS[args.kind],
                'recovery_max_s': RECOVERY_MAX, 'started_utc': time.strftime('%FT%TZ', time.gmtime())}
    (Path(args.out) / 'manifest.json').write_text(json.dumps(manifest, indent=1))
    lab = lib.Lab(str(Path(args.ftun).resolve()), str(Path(args.fixture).resolve()))
    run = Run(args, lab)
    error = None
    try:
        run.execute()
    except Exception as exc:  # noqa: BLE001
        error = f'{type(exc).__name__}: {exc}'
    finally:
        run.finish(error)
        lab.close()
    print(json.dumps(json.loads((Path(args.out) / 'summary.json').read_text())))
    return 0 if error is None and run.failures == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

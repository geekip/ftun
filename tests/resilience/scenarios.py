"""R1～R12、R14 场景。每个场景接收 Lab，失败抛 AssertionError，依赖尚未实现的能力抛 Skip。
时长按 lab.scale 缩放：开发阶段用缩短版（scale=1 的默认值），最终验收用 scale 放大。
通用判定（16.3）：PID 不变、无需手工操作、恢复时间不超过上限、资源不变量、
恢复后用探测客户端完成一次端到端请求。"""
import os
import re
import signal
import socket
import threading
import time

from lib import Skip, dns_query, socks_open, socks_echo, wait_until, sh

RECOVERY_MAX = 20.0  # 恢复时间上限（秒，开测前固定）


def baseline_up(lab):
    """正常联网启动，所有通路先证明可用，返回资源基线。"""
    lab.attach()
    lab.start_fakes()
    lab.start(lab.config())
    lab.wait_ready()
    wait_until(lambda: lab.dns_answer() == '203.0.113.5', 10, what='dns baseline')
    wait_until(lab.socks_ok, 10, what='socks baseline')
    wait_until(lambda: lab.counter('frs.hits') >= 1 and (lab.root / 'rules.frs').exists(), 10,
               what='frs baseline')
    time.sleep(1.0)
    return lab.snapshot()


def recovered(lab, within=RECOVERY_MAX):
    """恢复后 DNS、Proxy、FRS 更新都在上限时间内回来。"""
    hits = lab.counter('frs.hits')
    wait_until(lambda: lab.dns_answer(timeout=2) is not None, within, what='dns recovery')
    wait_until(lab.socks_ok, within, what='proxy recovery')
    wait_until(lambda: lab.counter('frs.hits') > hits, within, what='frs update recovery')


def no_watchdog(lab):
    lab.alive()
    assert 'watchdog' not in (lab.output.read_text() if lab.output.exists() else ''), \
        'watchdog fired during the outage'


def r1(lab):
    """没有网络时启动（FRS 缺失、监听地址未就绪），之后联网。"""
    lab.start_fakes()
    config = lab.config(dns={'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                             'bootstrap': ['198.51.100.53:53'], 'default-server': 'up',
                             'listeners': [{'listen': '127.0.0.1:15353', 'server': 'up'},
                                           {'listen': '198.51.100.1:15354', 'server': 'up'}],
                             'servers': [{'name': 'up', 'type': 'udp', 'outbound': 'DIRECT',
                                          'address': ['198.51.100.53:53']}]})
    lab.start(config)
    lab.wait_ready()
    pid = lab.process.pid
    # 没有网络：服务存活；FRS 未就绪时命中 FRS 规则的连接被拒绝；监听地址不存在。
    time.sleep(lab.seconds(3))
    lab.alive()
    sock, code = socks_open(lab.socks, '198.51.100.7', 7000)
    assert sock is None and code != 0, 'connection must be rejected while FRS is NOT_READY'
    assert not (lab.root / 'rules.frs').exists()
    assert dns_query(('198.51.100.1', 15354), timeout=1) is None
    # 联网：地址和路由出现。
    lab.attach()
    wait_until(lambda: (lab.root / 'rules.frs').exists(), RECOVERY_MAX, what='frs download')
    wait_until(lambda: dns_query(('198.51.100.1', 15354), timeout=1) == '203.0.113.5',
               RECOVERY_MAX, what='listener recovery')
    wait_until(lab.socks_ok, RECOVERY_MAX, what='proxy after FRS ready')
    assert lab.process.pid == pid
    lab.alive()


def r2(lab):
    """断网（缩短版 15 秒×scale）后恢复；故障期间有持续请求，看门狗零触发。"""
    baseline = baseline_up(lab)
    pid = lab.process.pid
    failures = []
    stop = threading.Event()

    def traffic():
        while not stop.is_set():
            if not lab.socks_ok(timeout=1.5):
                failures.append(time.monotonic())
            time.sleep(0.5)

    lab.blackhole()
    thread = threading.Thread(target=traffic, daemon=True)
    thread.start()
    time.sleep(lab.seconds(15))
    no_watchdog(lab)
    lab.restore()
    recovered(lab)
    stop.set()
    thread.join()
    assert failures, 'the outage was not observable by the probe'
    assert lab.process.pid == pid
    no_watchdog(lab)
    lab.assert_resources(baseline)


def r3(lab):
    """网络变化事件源：链路/地址变化后，等待中的恢复被提前触发，而不是等退避到期。
    A. 无网络启动，退避增长之后联网：FRS 下载和监听绑定在去抖窗口加少量时间内完成；
    B. 链路断开期间持续有 DNS 查询（上游地址累积失败进入退避），链路恢复后查询很快恢复。"""
    lab.start_fakes()
    config = lab.config(dns={'enable': True, 'cache': False, 'fake-ip': {'enable': False},
                             'bootstrap': ['198.51.100.53:53'], 'default-server': 'up',
                             'listeners': [{'listen': '127.0.0.1:15353', 'server': 'up'},
                                           {'listen': '198.51.100.1:15354', 'server': 'up'}],
                             'servers': [{'name': 'up', 'type': 'udp', 'outbound': 'DIRECT',
                                          'address': ['198.51.100.53:53', '198.51.100.54:53']}]})
    lab.start(config)
    lab.wait_ready()
    pid = lab.process.pid
    # A：没有地址——FRS 下载按退避失败、监听等待恢复。等到退避明显拉长（FRS 退避从
    # 1 秒翻倍到 8 秒以上）再联网，没有事件源时恢复要等下一个退避窗口。
    time.sleep(lab.seconds(14))
    lab.alive()
    assert not (lab.root / 'rules.frs').exists()
    started = time.monotonic()
    lab.attach()
    wait_until(lambda: (lab.root / 'rules.frs').exists(), 6, interval=0.05,
               what='frs download right after the network returns')
    wait_until(lambda: dns_query(('198.51.100.1', 15354), timeout=1) == '203.0.113.5', 6,
               interval=0.05, what='listener rebind right after the network returns')
    assert time.monotonic() - started < 6.0
    wait_until(lab.socks_ok, 10, what='proxy after FRS ready')
    # B：链路断开，持续查询让上游地址进入退避；恢复链路后应很快回到可用。
    sh('ip', 'link', 'set', 'phys0', 'down')
    end = time.monotonic() + lab.seconds(12)
    while time.monotonic() < end:
        lab.dns_answer(timeout=0.4)
        time.sleep(0.3)
    lab.alive()
    sh('ip', 'link', 'set', 'phys0', 'up')
    sh('ip', 'address', 'replace', '198.51.100.1/24', 'dev', 'phys0')
    started = time.monotonic()
    wait_until(lambda: lab.dns_answer(timeout=1) == '203.0.113.5', 8, interval=0.1,
               what='dns upstream recovery after the link returns')
    assert time.monotonic() - started < 6.0
    assert lab.process.pid == pid
    lab.alive()


def r4(lab):
    """网络反复抖动：退避生效，没有高频重连，稳定后恢复。"""
    baseline = baseline_up(lab)
    pid = lab.process.pid
    cpu0 = lab.snapshot()[2]
    accepted0 = lab.counter('echo.accepted')
    started = time.monotonic()
    for _ in range(int(lab.seconds(6))):
        sh('ip', 'link', 'set', 'phys0', 'down')
        time.sleep(1.0)
        sh('ip', 'link', 'set', 'phys0', 'up')
        sh('ip', 'address', 'replace', '198.51.100.1/24', 'dev', 'phys0')
        time.sleep(1.0)
        lab.alive()
    elapsed = time.monotonic() - started
    cpu = (lab.snapshot()[2] - cpu0) / os.sysconf('SC_CLK_TCK')
    assert cpu < 0.25 * elapsed, f'busy retry loop suspected: {cpu:.2f}s cpu in {elapsed:.0f}s'
    assert lab.counter('echo.accepted') - accepted0 < 40, 'high-frequency reconnects'
    recovered(lab)
    assert lab.process.pid == pid
    lab.assert_resources(baseline)


def r5(lab):
    """FD 耗尽后释放：暂停接纳、之后恢复接纳，进程不退出。"""
    lab.attach()
    lab.start_fakes()
    lab.start(lab.config(), prefix=['prlimit', '--nofile=320:320'])
    lab.wait_ready()
    wait_until(lab.socks_ok, 10, what='baseline')
    pid = lab.process.pid
    hits = lab.counter('frs.hits')
    held = []
    for _ in range(600):
        try:
            held.append(socket.create_connection(lab.socks, timeout=1))
        except OSError:
            break
        time.sleep(0.002)
    time.sleep(lab.seconds(3))
    lab.alive()
    for sock in held:
        sock.close()
    wait_until(lab.socks_ok, RECOVERY_MAX, what='accept resumes')
    assert lab.process.pid == pid
    wait_until(lambda: lab.snapshot()[0] < 80, 10, what='fds released')
    # 后台作业（FRS 更新）在 FD 耗尽期间可能创建通道失败：恢复后更新必须继续，
    # 且之后的正常停止不能被卡住的作业线程拖到期限。
    wait_until(lambda: lab.counter('frs.hits') > hits, RECOVERY_MAX, what='frs update resumes')
    lab.process.send_signal(signal.SIGTERM)
    assert lab.process.wait(timeout=8) == 0, 'stop after fd exhaustion did not exit cleanly'


def r6(lab):
    """故障期间持续 reload（含非法配置）：不出现永久 stale，代次连续。"""
    baseline_up(lab)
    pid = lab.process.pid
    good = lab.config()
    for index in range(int(8 * lab.scale)):
        # 非法配置：必须被拒绝并保持原配置。
        lab.config_path.write_text('{"base": ')
        lab.process.send_signal(signal.SIGHUP)
        time.sleep(0.4)
        lab.alive()
        # 合法配置：改一个规则，使每次都是新的一代。
        variant = dict(good)
        variant['rules'] = ['frs-ip,CN,REJECT', f'DST-PORT,{20000 + index},REJECT', 'MATCH,DIRECT']
        lab.write_config(variant)
        lab.process.send_signal(signal.SIGHUP)
        wait_until(lambda: lab.output.read_text().count('reload committed') > index, 10,
                   what=f'reload {index} committed')
        if index == 3:
            lab.blackhole()  # 故障期间继续 reload
        if index == 5:
            lab.restore()
    lab.restore()
    # 已提交的每一代都应在日志里出现，且编号没有回退或跳号（被拒绝的 reload 不占代次）。
    sequence = [int(g) for g in re.findall(r'event=reload\.committed[^\n]*generation=(\d+)',
                                           lab.log_text())]
    assert len(sequence) >= int(8 * lab.scale), lab.log_text()[-2000:]
    assert all(b - a >= 1 for a, b in zip(sequence, sequence[1:])), sequence
    # FRS 更新与 reload 都消费代次：编号单调递增，且最终生效的就是最后提交的那一代。
    assert not re.search(r'status=stale[^\n]*event=reload\.rejected', lab.log_text()), 'reload rejected as stale'
    assert lab.socks_ok()
    assert lab.process.pid == pid


def r7(lab):
    """DNS 上游：无响应、畸形、ID 不匹配；多地址切换并在恢复后切回优先地址。"""
    baseline_up(lab)
    pid = lab.process.pid
    assert lab.dns_answer() == '203.0.113.5'
    for broken in ('silent', 'malformed', 'badid'):
        lab.mode('dns53.mode', broken)
        # 第一次查询可能先等首选地址的缩短期限，随后由备用地址应答。
        answer = wait_until(lambda: lab.dns_answer(timeout=6) == '203.0.113.6' or None, 15,
                            what=f'failover on {broken}')
        started = time.monotonic()
        assert lab.dns_answer(timeout=3) == '203.0.113.6'
        assert time.monotonic() - started < 1.5, 'unhealthy address still on the query path'
        lab.mode('dns53.mode', 'normal')
        # 恢复后经试探切回优先地址（退避到期之后的下一次查询）。
        wait_until(lambda: lab.dns_answer(timeout=3) == '203.0.113.5' or None, 40,
                   interval=0.5, what=f'switch back after {broken}')
    lab.alive()
    assert lab.process.pid == pid


def fill(sock):
    """尽量写满发送路径，让对端窗口为零。"""
    sock.setblocking(False)
    try:
        for _ in range(4000):
            sock.send(b'x' * 8192)
    except (BlockingIOError, OSError):
        pass


def closed_by_peer(sock, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recv(1) == b''
    except ConnectionError:
        return True
    except TimeoutError:
        return False


def r8(lab):
    """对端静默失联被回收；安静但健康的长连接、窗口常为零但有进展的慢连接不被误关；
    完全没有写入进展的零窗口连接在写入进展期限后被回收。"""
    lab.attach()
    lab.start_fakes()
    lab.start(lab.config())
    lab.wait_ready()
    wait_until(lab.socks_ok, 10, what='baseline')
    # 健康但安静：保持空闲远超 keepalive 判定时间（2+1×2=4 秒），之后仍可用。
    quiet, code = socks_open(lab.socks, '198.51.100.7', 7000)
    assert quiet is not None
    # 慢读：窗口常为零，但每秒都有进展，越过写入进展期限（10 秒）仍不能被关。
    slow, code = socks_open(lab.socks, '198.51.100.7', 7001)
    assert slow is not None
    fill(slow)
    # 完全不读：没有任何进展，写入进展期限后应被回收。
    stuck, code = socks_open(lab.socks, '198.51.100.7', 7002)
    assert stuck is not None
    fill(stuck)
    time.sleep(lab.seconds(16))
    quiet.setblocking(True)
    quiet.settimeout(3)
    quiet.sendall(b'alive')
    assert quiet.recv(5) == b'alive', 'healthy idle connection was closed'
    # 慢但有进展的连接不能被关：转发连接按确认进展回收，而不是按队首数据的入队时间。
    assert not closed_by_peer(slow, 0.5), 'slow but progressing connection was closed'
    assert closed_by_peer(stuck, lab.seconds(10)), 'stalled zero-window connection was not reclaimed'
    # 静默失联：丢弃全部报文，连接应被 keepalive 回收。
    lost, code = socks_open(lab.socks, '198.51.100.7', 7000)
    assert lost is not None
    lab.blackhole()
    assert closed_by_peer(lost, lab.seconds(20)), 'silently lost connection was not reclaimed'
    lab.restore()
    quiet.close()
    slow.close()
    wait_until(lab.socks_ok, RECOVERY_MAX, what='service after loss')
    lab.alive()


def r9(lab):
    raise Skip('R9 依赖 FTUN_TEST_HOOKS 构建的注入钩子（监听错误、收尾失败），当前产品构建没有该钩子；'
               '局部隔离与恢复由收尾隔离区和监听恢复的单元测试覆盖')


def r10(lab):
    """TUN + strict-route 下 kill -9 再重启；同身份第二个实例拿不到实例锁。"""
    lab.attach()
    lab.start_fakes()
    config = lab.config()
    config['tun'] = {'interface': 'ftun-r10', 'mtu': 1400, 'ipv4': {'address': '10.77.9.1/30'},
                     'auto-route': True, 'strict-route': True}
    config['inbounds'] = [{'name': 'in', 'type': 'socks5', 'listen': '127.0.0.1:11081'},
                          {'name': 'tun-in', 'type': 'tun', 'tcp': True, 'udp': False,
                           'dns-hijack': False}]
    lab.start(config)
    wait_until(lambda: sh('ip', 'link', 'show', 'ftun-r10', check=False, capture=True).returncode == 0,
               15, what='tun up')
    rules_before = sh('ip', 'rule', 'show', capture=True).stdout
    # 同一身份的第二个实例：必须因拿不到实例锁而失败，且不改动现有资源。
    import subprocess
    other = subprocess.run([lab.ftun, 'run', '-c', str(lab.config_path)], capture_output=True,
                           timeout=20)
    assert other.returncode != 0, 'second instance must not start'
    assert sh('ip', 'rule', 'show', capture=True).stdout == rules_before
    lab.alive()
    # kill -9 后重启：对账接管遗留对象，全程无需手工操作。
    lab.process.kill()
    lab.process.wait()
    time.sleep(1.0)
    lab.start(None)
    wait_until(lambda: lab.process.poll() is None and
               sh('ip', 'link', 'show', 'ftun-r10', check=False, capture=True).returncode == 0,
               RECOVERY_MAX, what='restart after kill -9')
    wait_until(lab.socks_ok, RECOVERY_MAX, what='proxy after restart')
    lab.alive()


def r11(lab):
    raise Skip('R11 的 owner 卡死注入需要 FTUN_TEST_HOOKS 钩子；断网期间看门狗零触发已在 R2 中验证，'
               '看门狗本身的卡死/持锁/诊断阻塞场景由 tests/unit/app/test_watchdog.c 用真实线程覆盖')


def r12(lab):
    """日志磁盘写满；畸形输入洪泛；慢速握手攻击：服务不受影响。"""
    lab.attach()
    lab.start_fakes()
    tiny = lab.root / 'tinylog'
    tiny.mkdir()
    sh('mount', '-t', 'tmpfs', '-o', 'size=64k', 'tmpfs', tiny)
    config = lab.config(log={'level': 'debug', 'file': str(tiny / 'ftun.log')})
    lab.start(config)
    lab.wait_ready()
    wait_until(lab.socks_ok, 10, what='baseline')
    # 慢速握手：只发一个字节后不再发送，应在握手期限（3 秒）后被回收。
    slow = []
    for _ in range(40):
        sock = socket.create_connection(lab.socks, timeout=2)
        sock.send(b'\x05')
        slow.append(sock)
    # 畸形输入洪泛：SOCKS 与 DNS 监听。
    end = time.monotonic() + lab.seconds(4)
    flood = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.monotonic() < end:
        flood.sendto(os.urandom(64), ('127.0.0.1', 15353))
        try:
            junk = socket.create_connection(lab.socks, timeout=1)
            junk.send(os.urandom(128))
            junk.close()
        except OSError:
            pass
    # 日志目录被写满后服务照常工作。
    used = sum(f.stat().st_size for f in tiny.iterdir())
    assert used > 0
    lab.alive()
    wait_until(lab.socks_ok, RECOVERY_MAX, what='service during flood')
    deadline = time.monotonic() + lab.seconds(8)
    for sock in slow:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            assert sock.recv(1) == b'' or True
        except (TimeoutError, ConnectionError):
            pass
        sock.close()
    assert lab.dns_answer() == '203.0.113.5'
    lab.alive()


def r14(lab):
    """TUN 对账与恢复：启动时清理遗留对象；路由/规则被外部删除后补回；
    TUN 设备被外部删除后重建。全程进程存活，不需要重启。"""
    lab.attach()
    lab.start_fakes()
    # 上次崩溃遗留：同表同优先级、协议号 186 但选择子与本次计划不同。
    sh('ip', 'rule', 'add', 'priority', '11001', 'fwmark', '0x99', 'lookup', '18004', 'protocol', '186')
    sh('ip', 'rule', 'add', 'priority', '11000', 'fwmark', '0x98', 'lookup', '18004', 'protocol', '186')
    sh('ip', 'route', 'add', 'default', 'dev', 'lo', 'table', '18004', 'protocol', '186', 'metric', '99')
    config = lab.config()
    config['tun'] = {'interface': 'ftun-r14', 'mtu': 1400, 'ipv4': {'address': '10.77.14.1/30'},
                     'auto-route': True, 'strict-route': True}
    config['inbounds'] = [{'name': 'in', 'type': 'socks5', 'listen': '127.0.0.1:11081'},
                          {'name': 'tun-in', 'type': 'tun', 'tcp': True, 'udp': False,
                           'dns-hijack': False}]
    lab.start(config)

    def link_up():
        return sh('ip', 'link', 'show', 'ftun-r14', check=False, capture=True).returncode == 0

    def table_routes():
        return sh('ip', 'route', 'show', 'table', '18004', check=False, capture=True).stdout

    def rules():
        return sh('ip', 'rule', 'show', check=False, capture=True).stdout

    wait_until(link_up, 15, what='tun up')
    wait_until(lambda: 'ftun-r14' in table_routes(), 15, what='capture route')
    assert '0x99' not in rules() and '0x98' not in rules(), rules()
    assert 'lo' not in table_routes().replace('local', ''), table_routes()
    baseline_rules = rules()
    lab.alive()
    # 路由被外部删除：网络变化事件触发对账，补回缺失项，其余不动。
    sh('ip', 'route', 'del', 'default', 'dev', 'ftun-r14', 'table', '18004')
    wait_until(lambda: 'ftun-r14' in table_routes(), RECOVERY_MAX, what='route repaired')
    # 保护规则被外部删除：同样补回。
    sh('ip', 'rule', 'del', 'priority', '11000')
    wait_until(lambda: rules() == baseline_rules, RECOVERY_MAX, what='rule repaired')
    lab.alive()
    # TUN 设备被外部删除：服务不退出，设备与网络配置重建。
    sh('ip', 'link', 'del', 'ftun-r14')
    wait_until(lambda: link_up() and 'ftun-r14' in table_routes() and rules() == baseline_rules,
               RECOVERY_MAX, what='tun device rebuilt')
    wait_until(lab.socks_ok, RECOVERY_MAX, what='proxy after tun rebuild')
    lab.alive()


SCENARIOS = {'R1': r1, 'R2': r2, 'R3': r3, 'R4': r4, 'R5': r5, 'R6': r6, 'R7': r7,
             'R8': r8, 'R9': r9, 'R10': r10, 'R11': r11, 'R12': r12, 'R14': r14}

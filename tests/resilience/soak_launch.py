#!/usr/bin/env python3
"""R13 长稳启动器：冻结二进制与驱动，把每个实例作为 systemd 临时 service 启动。

service 属于系统管理器而不是当前会话，关闭终端、SSH 或 code-server 都不会终止它们。
需要 root。用法：
  soak_launch.py --run ID --duration 86400 --seed 1 --musl 目录 --asan 目录 --tsan 目录
各目录是已构建的树（含 ftun 与 ftun-v04-frs-test）。启动前会把二进制和驱动复制到
/data/soak/<ID>/ 并记录 sha256，之后重新构建源码树不会影响正在运行的实例。"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path('/data/soak')
HERE = Path(__file__).resolve().parent
DRIVER = ['lib.py', 'fakes.py', 'scenarios.py', 'soak.py', 'soak_report.py']
INSTANCES = [
    # 名字, 配置, 构建, 是否判资源曲线, 内存上限
    ('a1-combined-musl', 'combined', 'musl', True, '1G'),
    ('a2-dns-musl', 'dns', 'musl', True, '1G'),
    ('a3-proxy-musl', 'proxy', 'musl', True, '1G'),
    ('b1-combined-asan', 'combined', 'asan', False, '4G'),
    ('b2-combined-tsan', 'combined', 'tsan', False, '4G'),
]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def source_fingerprint(repository):
    digest = hashlib.sha256()
    for sub in ('src', 'include', 'CMakeLists.txt', 'schema.json', 'cmake'):
        base = repository / sub
        files = [base] if base.is_file() else sorted(p for p in base.rglob('*') if p.is_file())
        for path in files:
            digest.update(str(path.relative_to(repository)).encode())
            digest.update(sha256(path).encode())
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--duration', type=int, required=True)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--pause', type=int, default=120)
    parser.add_argument('--long-outage', type=int, default=0)
    parser.add_argument('--musl', required=True)
    parser.add_argument('--asan')
    parser.add_argument('--tsan')
    parser.add_argument('--only', default='', help='只启动这些实例（逗号分隔名字前缀）')
    parser.add_argument('--cpus', default='2-5')
    parser.add_argument('--thresholds', help='事先登记的阈值文件，随运行一起冻结')
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit('soak_launch: root required')
    trees = {'musl': Path(args.musl), 'asan': Path(args.asan) if args.asan else None,
             'tsan': Path(args.tsan) if args.tsan else None}
    run = ROOT / args.run
    if run.exists():
        sys.exit(f'{run} already exists; choose a new run id')
    (run / 'driver').mkdir(parents=True)
    for name in DRIVER:
        shutil.copy2(HERE / name, run / 'driver' / name)
    fixture_source = trees['musl'] / 'ftun-v04-frs-test'
    (run / 'bin').mkdir()
    shutil.copy2(fixture_source, run / 'bin' / 'ftun-v04-frs-test')
    if args.thresholds:
        shutil.copy2(args.thresholds, run / 'thresholds.json')
    manifest = {'run': args.run, 'duration_s': args.duration, 'seed': args.seed,
                'pause_s': args.pause, 'long_outage_s': args.long_outage,
                'cpus': args.cpus, 'launched_utc': time.strftime('%FT%TZ', time.gmtime()),
                'source_fingerprint': source_fingerprint(HERE.parent.parent),
                'driver': {n: sha256(run / 'driver' / n) for n in DRIVER},
                'fixture_sha256': sha256(run / 'bin' / 'ftun-v04-frs-test'), 'instances': {}}
    wanted = [w for w in args.only.split(',') if w]
    for index, (name, kind, build, strict, memory) in enumerate(INSTANCES):
        if wanted and not any(name.startswith(w) for w in wanted):
            continue
        tree = trees[build]
        if tree is None:
            sys.exit(f'--{build} is required for {name}')
        out = run / name
        (out / 'bin').mkdir(parents=True)
        binary = out / 'bin' / 'ftun'
        shutil.copy2(tree / 'ftun', binary)
        seed = args.seed + index
        unit = f'ftun-soak-{args.run}-{name}'
        environment = []
        if build == 'asan':
            environment = [f'ASAN_OPTIONS=detect_leaks=1:log_path={out}/sanitizer',
                           'UBSAN_OPTIONS=print_stacktrace=1']
        if build == 'tsan':
            environment = [f'TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1:log_path={out}/sanitizer']
        command = ['systemd-run', f'--unit={unit}', '--collect',
                   f'--description=FTUN R13 soak {args.run} {name}',
                   '--property=Type=exec', f'--property=AllowedCPUs={args.cpus}',
                   f'--property=MemoryMax={memory}', '--property=MemorySwapMax=0',
                   '--property=TasksMax=4096', '--property=KillMode=control-group',
                   '--property=TimeoutStopSec=60',
                   f'--property=StandardOutput=file:{out}/unit.out',
                   f'--property=StandardError=file:{out}/unit.err']
        command += [f'--setenv={item}' for item in environment]
        script = [sys.executable, '-u', str(run / 'driver' / 'soak.py'),
                  '--ftun', str(binary), '--fixture', str(run / 'bin' / 'ftun-v04-frs-test'),
                  '--kind', kind, '--duration', str(args.duration), '--seed', str(seed),
                  '--pause', str(args.pause), '--long-outage', str(args.long_outage),
                  '--out', str(out)]
        manifest['instances'][name] = {'unit': unit, 'kind': kind, 'build': build,
                                       'strict_resources': strict, 'seed': seed,
                                       'binary_sha256': sha256(binary), 'memory_max': memory}
        (run / 'manifest.json').write_text(json.dumps(manifest, indent=1))
        subprocess.run(command + script, check=True)
    print(json.dumps(manifest, indent=1))


if __name__ == '__main__':
    main()

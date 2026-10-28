#!/usr/bin/env python3
"""R13 长稳报告：读取 soak.py 的输出目录，按事先登记的阈值给出逐项判定。

用法：soak_report.py 输出目录 [--thresholds thresholds.json] [--strict-resources]
退出码：0 全部通过；1 有判定未通过。资源曲线判定只对 --strict-resources 的实例生效
（ASan/TSan 实例的 RSS 被 shadow 和 quarantine 污染，只判崩溃、sanitizer 报告和恢复）。"""
import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

DEFAULTS = {
    'recovery_max_s': 20.0,
    'warmup_s': 3600.0,
    'rss_growth_max_kib': 4096,
    'pss_growth_max_kib': 4096,
    'fd_spread_max': 8,
    'thread_spread_max': 1,
    'steady_margin_s': 30.0,
    'egress_max_packets': 0,
    'min_elapsed_ratio': 1.0,
}
DENY = ('watchdog', 'stop.failed', 'module.failed', 'state-corrupt', 'STATE_CORRUPT')
SANITIZER = ('ERROR: AddressSanitizer', 'ERROR: LeakSanitizer', 'WARNING: ThreadSanitizer',
             'runtime error:', 'SUMMARY: ')


def load_csv(path):
    with open(path, newline='') as handle:
        return list(csv.DictReader(handle))


def windows(events, margin):
    return [(e['t_start'], e['t_end'] + margin) for e in events]


def steady(t, spans):
    return not any(a <= t <= b for a, b in spans)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('out')
    parser.add_argument('--thresholds')
    parser.add_argument('--strict-resources', action='store_true')
    args = parser.parse_args()
    out = Path(args.out)
    limits = dict(DEFAULTS)
    if args.thresholds:
        limits.update(json.loads(Path(args.thresholds).read_text()))
    manifest = json.loads((out / 'manifest.json').read_text())
    summary = json.loads((out / 'summary.json').read_text()) if (out / 'summary.json').exists() else {}
    events = [json.loads(line) for line in (out / 'events.jsonl').read_text().splitlines() if line]
    probes = load_csv(out / 'probes.csv')
    samples = load_csv(out / 'samples.csv')
    spans = windows(events, limits['steady_margin_s'])
    checks = []

    def check(name, ok, detail):
        checks.append({'check': name, 'ok': bool(ok), 'detail': detail})

    elapsed = float(summary.get('elapsed_s', samples and float(samples[-1]['t']) or 0))
    check('completed', summary.get('completed') is True and
          elapsed >= manifest['duration_s'] * limits['min_elapsed_ratio'],
          f"elapsed {elapsed:.0f}s of {manifest['duration_s']:.0f}s, error={summary.get('error')}")
    check('exit_code', summary.get('exit_code') == 0, f"exit_code={summary.get('exit_code')}")
    failed = [e for e in events if not e['ok']]
    check('events', not failed and events,
          f"{len(events)} events, {len(failed)} failed" +
          ''.join(f"\n    {e['t_start']:.0f}s {e['kind']}: {e['detail'][:160]}" for e in failed[:10]))
    slow = [e for e in events if e['recovery_s'] is not None and e['recovery_s'] > limits['recovery_max_s']]
    recoveries = [e['recovery_s'] for e in events if e['recovery_s'] is not None]
    check('recovery_time', not slow,
          f"max {max(recoveries) if recoveries else 0}s (limit {limits['recovery_max_s']}s), "
          f"p99 {sorted(recoveries)[int(len(recoveries) * 0.99) - 1] if recoveries else 0}s")
    pids = {row['pid'] for row in samples if row['pid'] not in ('', '-1')}
    check('pid_unchanged', len(pids) == 1 and str(manifest.get('pid')) in pids, f"pids={sorted(pids)}")
    bad = [row for row in probes
           if row['probe'] in ('socks', 'dns') and row['in_fault'] == '0' and row['ok'] == '0']
    # 安静的健康长连接每分钟检查一次：故障期间（断网超过 keepalive 判定时间等）被回收是
    # 预期行为，要到下一次检查才会发现。所以只有“上次成功检查到这次失败之间没有任何故障
    # 窗口”的失败才算连接被误关。
    last_ok = 0.0
    for row in probes:
        if row['probe'] != 'quiet':
            continue
        t = float(row['t'])
        if row['ok'] == '1':
            last_ok = t
        elif not any(a <= t and b >= last_ok for a, b in spans):
            bad.append(row)
    total_steady = sum(1 for row in probes if row['in_fault'] == '0')
    check('steady_probes', not bad,
          f"{len(bad)} failures in {total_steady} steady probes" +
          ''.join(f"\n    t={r['t']} {r['probe']}" for r in bad[:10]))
    if manifest['kind'] == 'combined':
        egress = [int(r['egress_packets']) for r in samples]
        check('unauthorized_egress', egress and max(egress) <= limits['egress_max_packets'],
              f"max counter {max(egress) if egress else None} (limit {limits['egress_max_packets']})")
    log = (out / 'ftun.log').read_text(errors='replace') if (out / 'ftun.log').exists() else ''
    output = (out / 'ftun.out').read_text(errors='replace') if (out / 'ftun.out').exists() else ''
    hits = [word for word in DENY if word in log or word in output]
    check('log_deny_list', not hits, f"matched: {hits}")
    sanitizer_logs = ''.join(p.read_text(errors='replace') for p in out.glob('sanitizer*'))
    reports = [word for word in SANITIZER if word in output or word in sanitizer_logs]
    check('sanitizer_reports', not reports, f"matched: {reports}")
    if args.strict_resources:
        rows = [r for r in samples if r['fds'] != '-1' and float(r['t']) >= limits['warmup_s']
                and steady(float(r['t']), spans)]
        if len(rows) >= 20:
            def column(name):
                return [int(r[name]) for r in rows]
            head = max(1, len(rows) // 10)
            for name, key in (('rss_kib', 'rss_growth_max_kib'), ('pss_kib', 'pss_growth_max_kib')):
                values = column(name)
                growth = statistics.median(values[-head:]) - statistics.median(values[:head])
                check(f'{name}_growth', growth <= limits[key],
                      f"median last10% - first10% = {growth:.0f} KiB (limit {limits[key]})")
            fds, threads = column('fds'), column('threads')
            check('fd_spread', max(fds) - min(fds) <= limits['fd_spread_max'],
                  f"fds {min(fds)}..{max(fds)} (limit spread {limits['fd_spread_max']})")
            check('thread_spread', max(threads) - min(threads) <= limits['thread_spread_max'],
                  f"threads {min(threads)}..{max(threads)} (limit spread {limits['thread_spread_max']})")
        else:
            check('resource_samples', False, f"only {len(rows)} steady samples after warmup")
    verdict = all(c['ok'] for c in checks)
    (out / 'verdict.json').write_text(json.dumps({'pass': verdict, 'limits': limits, 'checks': checks}, indent=1))
    lines = [f"# {manifest['kind']} soak  seed={manifest['seed']}  "
             f"{'PASS' if verdict else 'FAIL'}", '']
    for c in checks:
        lines.append(f"- [{'x' if c['ok'] else ' '}] {c['check']}: {c['detail']}")
    (out / 'report.md').write_text('\n'.join(lines) + '\n')
    print('\n'.join(lines))
    return 0 if verdict else 1


if __name__ == '__main__':
    sys.exit(main())

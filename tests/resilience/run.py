#!/usr/bin/env python3
"""恢复契约验收入口：run.py <R1..R12|all> --ftun <路径> --fixture <FRS 夹具> [--scale N]
退出码 77 表示场景依赖尚未实现的能力（跳过，不是通过）。"""
import argparse
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).parent))
import lib  # noqa: E402

lib.isolate([str(Path(__file__).resolve())] + sys.argv[1:])

import scenarios  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('scenario')
    parser.add_argument('--ftun', required=True)
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--scale', type=float, default=1.0)
    args = parser.parse_args()
    names = list(scenarios.SCENARIOS) if args.scenario == 'all' else [args.scenario]
    worst = 0
    for name in names:
        lab = lib.Lab(str(Path(args.ftun).resolve()), str(Path(args.fixture).resolve()), args.scale)
        try:
            scenarios.SCENARIOS[name](lab)
            print(f'{name}: PASS')
        except lib.Skip as reason:
            print(f'{name}: SKIP {reason}')
            worst = worst or lib.SKIP
        except BaseException:
            print(f'{name}: FAIL')
            traceback.print_exc()
            print(lab.log_text()[-3000:], file=sys.stderr)
            worst = 1
        finally:
            lab.close()
    sys.exit(worst)


if __name__ == '__main__':
    main()

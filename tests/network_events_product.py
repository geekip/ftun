#!/usr/bin/env python3
"""Drive the real owner/logger through storm aggregation and observed recovery."""
from pathlib import Path
import sys
import tempfile

from ctl_server_product import Instance, wait


def main():
    with tempfile.TemporaryDirectory(prefix='ftun-net-events-') as directory:
        root = Path(directory)
        log = root / 'network.log'
        running = Instance(sys.argv[1], root / 'run', initial={
            'log': {'level': 'info', 'output': 'file', 'file': str(log)}})
        try:
            for _ in range(110):
                assert running.call('status')['state'] == 'running'
            wait(lambda: log.exists() and 'network stable:' in log.read_text(),
                 lambda: log.read_text() if log.exists() else '')
            assert running.call('stop', timeout_ms=5000)['result'] == 'stopped'
            assert running.process.wait(timeout=5) == 0
            output = log.read_text()
            assert output.count('] change storm (first):') == 1, output
            stable = next(line for line in output.splitlines() if '] network stable:' in line)
            assert 'count=100' in stable and 'duration_ms=' in stable and 'gen=1' in stable, stable
            assert 'reason=overflow' in output, output
            assert '[net   ][WARN ] change storm' in output, output
        finally:
            running.close()
    print('network events: 100 storm batches, one first warning, recovery total/duration and overflow reason passed')


if __name__ == '__main__':
    main()

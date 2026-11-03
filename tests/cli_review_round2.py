#!/usr/bin/env python3
"""复审回归：持久路径、排队接纳失败、停止时确定未执行的请求。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from ctl_server_product import Instance, response, wait
from fakeip_cidr import configuration, free_port


def reachability(binary, root, tilde):
    directory = root / 'app'
    home = root / 'home'
    home.mkdir()
    value = configuration('198.18.9.0/24', home / 'state', free_port(), persist=True)
    value['base']['cache-file'] = '~/state' if tilde else '../home/state'
    app = Instance(binary, directory, initial=value, env=dict(os.environ, HOME=str(home)))
    try:
        for enabled in (False, True):
            app.config['dns']['servers'][0]['fake-ip'] = enabled
            app.write()
            result = app.call('reload')
            assert result['result'] == 'committed', result
        original = app.config['base']['cache-file']
        app.config['base']['cache-file'] = '~/changed' if tilde else '../home/changed'
        app.write()
        result = app.call('reload')
        assert result['result'] == 'restart-required', result
        app.config['base']['cache-file'] = original
        app.write()
        assert app.call('stop')['result'] == 'stopped'
        assert app.process.wait(timeout=5) == 0
    finally:
        app.close()


def admission(binary, root, kind):
    app = Instance(binary, root / 'app',
                   initial={'log': {'level': 'info', 'output': 'file', 'file': str(root / 'events.log')}},
                   env=dict(os.environ, FTUN_TEST_QUEUED_ADMISSION=kind))
    try:
        fifo, first = app.blocked_reload('blocked')
        app.config['base'] = {'state-cache': False}
        app.write()
        queued = app.connect({'op': 'reload', 'timeout_ms': 5000})
        another = app.connect({'op': 'reload', 'timeout_ms': 5000})
        # 已得到回执或已超时的请求不再等待批次结果，不能被重复计为拒绝。
        with app.connect({'op': 'reload', 'timeout_ms': 0}) as no_wait, \
                app.connect({'op': 'reload', 'timeout_ms': 100}) as short:
            assert response(no_wait)['result'] == 'accepted'
            assert response(short)['result'] == 'timeout'
        wait(lambda: app.call('status')['control']['merged'] == 4, app.output.read_text)
        before = app.call('status')['control']['rejected']
        app.release_fifo(fifo)
        with first, queued, another:
            assert response(first)['result'] == 'committed'
            result = response(queued)
            other = response(another)
        assert result['result'] == 'busy' and result['status'] == kind, result
        assert other['result'] == 'busy' and other['op_id'] == result['op_id'], other
        assert app.call('status')['control']['rejected'] == before + 2
        assert app.call('stop')['result'] == 'stopped'
        assert app.process.wait(timeout=5) == 0
        events = (root / 'events.log').read_text()
        assert 'busy (first)' in events and 'result=busy' in events, events
    finally:
        app.close()


def stopped(binary, root):
    app = Instance(binary, root / 'app',
                   initial={'log': {'level': 'info', 'output': 'file', 'file': str(root / 'events.log')}})
    try:
        _, first = app.blocked_reload('blocked')
        with subprocess.Popen([binary, 'reload', '-p', str(app.pid), '--timeout', '5', '--json'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as queued:
            wait(lambda: app.call('status')['control']['merged'] == 1, app.output.read_text)
            assert app.call('stop', timeout_ms=50)['result'] == 'timeout'
            with first:
                in_flight = response(first)
            # 已交付取消回调时结果已知；没有回调的在途请求才是未知。
            assert (in_flight['result'], in_flight['status']) in (
                ('timeout', 'result-unknown'), ('rejected', 'cancelled')), in_flight
            output, errors = queued.communicate(timeout=5)
            never_submitted = json.loads(output)
            assert queued.returncode == 1 and not errors, (output, errors)
            assert never_submitted['result'] == 'rejected' and never_submitted['status'] == 'not-executed', never_submitted
        assert app.process.wait(timeout=5) == 1
        events = (root / 'events.log').read_text()
        assert 'result=not-executed' in events and 'request rejected' in events, events
    finally:
        app.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('case', choices=['relative', 'tilde', 'again', 'limit', 'stop'])
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='ftun-review2-') as temp:
        root = Path(temp)
        if args.case in ('relative', 'tilde'):
            reachability(str(args.binary.resolve()), root, args.case == 'tilde')
        elif args.case == 'stop':
            stopped(str(args.binary.resolve()), root)
        else:
            admission(str(args.binary.resolve()), root, args.case)


if __name__ == '__main__':
    main()

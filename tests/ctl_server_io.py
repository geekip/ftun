#!/usr/bin/env python3
"""Prove partial/failed/blocked control writes preserve owner and data progress."""
import os
from pathlib import Path
import tempfile
import sys
import time
import threading
from ctl_server_product import Instance, response, wait


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='ftun-ctl-io-') as directory:
        for mode in ('short', 'error', 'block', 'kernel'):
            os.environ['FTUN_CTL_TEST_WRITE'] = mode
            app = Instance(binary, Path(directory) / mode, long_path=mode == 'kernel')
            try:
                if mode == 'short':
                    assert app.call('status')['result'] == 'ok'
                    assert app.call('reload')['result'] == 'committed'
                else:
                    with app.connect({'op': 'status'}) as target:
                        wait(lambda: 'ctl write injection armed' in app.output.read_text(), app.output.read_text)
                        started = time.monotonic()
                        for _ in range(20):
                            assert app.call('status')['result'] == 'ok'
                            app.probe()
                        assert time.monotonic() - started < 3
                        if mode == 'kernel':
                            stopped = threading.Event()
                            errors = []

                            def flood():
                                try:
                                    while not stopped.is_set():
                                        assert app.call('status')['result'] == 'ok'
                                except BaseException as error:
                                    errors.append(error)
                                    stopped.set()

                            workers = [threading.Thread(target=flood, daemon=True) for _ in range(2)]
                            for worker in workers:
                                worker.start()
                            try:
                                wait(lambda: app.call('status')['control']['timeouts'] >= 1, app.output.read_text)
                            finally:
                                stopped.set()
                                for worker in workers:
                                    worker.join(timeout=8)
                                    assert not worker.is_alive()
                            assert not errors, errors
                            data = b''
                            while part := target.recv(65536):
                                data += part
                            assert data and not data.endswith(b'\n'), len(data)
                        else:
                            assert target.recv(1) == b''
                    usage = app.call('status')['control']
                    assert usage['write_failed'] >= 1, usage
                    if mode in ('block', 'kernel'):
                        assert usage['timeouts'] >= 1, usage
                assert app.call('stop')['result'] == 'stopped'
                assert app.process.wait(timeout=5) == 0, app.output.read_text()
            finally:
                app.close()
    print('Control output: partial/failed/blocked writes, unread kernel backpressure, deadlines and concurrent owner/data progress passed')


if __name__ == '__main__':
    main()

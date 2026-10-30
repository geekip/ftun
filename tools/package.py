#!/usr/bin/env python3
"""只分发已构建程序、模块清单与许可文档；不打包工作区。"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

PLATFORMS = ('darwin-amd64', 'darwin-arm64', 'windows-amd64', 'windows-arm64',
             'linux-amd64-musl', 'linux-arm64-musl', 'linux-armv7-musl',
             'linux-mips-musl', 'linux-mipsel-musl')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=PLATFORMS)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--tag', help='release tag; defaults to the CMake project version')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = root / 'build' / args.platform
    cache = dict(line.split('=', 1) for line in (build / 'CMakeCache.txt').read_text().splitlines()
                 if '=' in line and not line.startswith(('#', '//')))
    version = cache['CMAKE_PROJECT_VERSION:STATIC']
    tag = args.tag or 'v' + version
    if tag != 'v' + version and not tag.startswith('v' + version + '-'):
        raise SystemExit('release tag does not match the CMake project version')
    if any(character not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-' for character in tag):
        raise SystemExit('invalid release tag')
    binary = 'ftun.exe' if args.platform.startswith('windows-') else 'ftun'
    files = {binary: (build / binary).read_bytes(),
             'ftun-build-modules.txt': (build / 'ftun-build-modules.txt').read_bytes()}
    for license in (build / 'toolchain-licenses').iterdir():
        files['docs/' + license.name] = license.read_bytes()
    files['README.md'] = (root / 'README.md').read_bytes()
    for document in (root / 'docs').glob('*.md'):
        files['docs/' + document.name] = document.read_bytes()
    for path in ('LICENSE', 'third_party/LOCK.json'):
        files['docs/' + Path(path).name] = (root / path).read_bytes()
    files['docs/THIRD_PARTY_NOTICES.md'] = (build / 'THIRD_PARTY_NOTICES.md').read_bytes()
    files['docs/README-third-party.md'] = (root / 'third_party/README.md').read_bytes()
    for component, source in [('cJSON', 'cjson/LICENSE'), ('wolfSSL', 'wolfssl/COPYING')]:
        files['docs/LICENSE-' + component] = (root / 'third_party' / source).read_bytes()
    if args.platform.startswith('windows-'):
        files['docs/LICENSE-wepoll'] = (root / 'third_party/wepoll/LICENSE').read_bytes()
    if cache['FTUN_MODULE_TUN:STRING'] == 'BUILTIN':
        files['docs/LICENSE-lwIP'] = (root / 'third_party/lwip/LICENSE').read_bytes()
    if args.platform.startswith('windows-') and cache['FTUN_MODULE_TUN:STRING'] == 'BUILTIN':
        runtime = json.loads((root / 'third_party/LOCK.json').read_text())['wintun_runtime']
        dll = (build / 'wintun.dll').read_bytes()
        license = (build / 'LICENSE-Wintun-binaries').read_bytes()
        arch = args.platform.split('-')[1]
        if hashlib.sha256(dll).hexdigest() != runtime['binaries'][arch]['sha256'] or \
                hashlib.sha256(license).hexdigest() != runtime['license_sha256']:
            raise SystemExit('Wintun runtime or license differs from lock')
        files['wintun.dll'] = dll
        files['docs/LICENSE-Wintun-binaries'] = license
        files['docs/wintun.h'] = (root / 'third_party/wintun/api/wintun.h').read_bytes()
    epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=root, text=True))
    name = f'ftun-{tag}-{args.platform}'
    args.output.mkdir(parents=True, exist_ok=True)
    if binary.endswith('.exe'):
        archive = args.output / (name + '.zip')
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path, data in sorted(files.items()):
                info = zipfile.ZipInfo(name + '/' + path, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if path == binary else 0o644) << 16
                output.writestr(info, data)
    else:
        archive = args.output / (name + '.tar.gz')
        with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as output:
                for path, data in sorted(files.items()):
                    info = tarfile.TarInfo(name + '/' + path)
                    info.size, info.mtime = len(data), epoch
                    info.mode = 0o755 if path == binary else 0o644
                    output.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + '.sha256').write_text(f'{digest}  {archive.name}\n', encoding='ascii')
    print(archive)


if __name__ == '__main__':
    main()

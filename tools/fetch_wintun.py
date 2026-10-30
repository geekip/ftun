#!/usr/bin/env python3
"""显式准备官方签名运行库；CMake 本身始终离线。"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    lock = json.loads((root / 'third_party/LOCK.json').read_text())['wintun_runtime']
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='use an existing official ZIP offline')
    parser.add_argument('--output', type=Path, default=root / 'build/deps' / ('wintun-' + lock['version']))
    args = parser.parse_args()
    if args.archive:
        data = args.archive.read_bytes()
    else:
        with urllib.request.urlopen(lock['source'], timeout=60) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != lock['archive_sha256']:
        raise SystemExit('Wintun archive SHA256 mismatch')
    # 只取锁中列出的文件；全部验证成功才写入，保留 DLL 原始签名。
    files = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for arch, binary in lock['binaries'].items():
            contents = archive.read(binary['file'])
            if hashlib.sha256(contents).hexdigest() != binary['sha256']:
                raise SystemExit('Wintun DLL SHA256 mismatch: ' + arch)
            files[arch + '/wintun.dll'] = contents
        license = archive.read(lock['license_file'])
        if hashlib.sha256(license).hexdigest() != lock['license_sha256']:
            raise SystemExit('Wintun binary license SHA256 mismatch')
        files['LICENSE-Wintun-binaries'] = license
    for name, contents in files.items():
        destination = args.output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
    print(args.output)


if __name__ == '__main__':
    main()

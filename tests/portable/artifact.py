#!/usr/bin/env python3
"""直接检查ELF/Mach-O/PE头；配置探测成功不能替代对最终可执行文件的核验。"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from package import PLATFORMS


def inspect(platform, data):
    if platform.startswith('linux-'):
        expected = {'amd64': (2, 1, 62), 'arm64': (2, 1, 183),
                    'armv7': (1, 1, 40), 'mips': (1, 2, 8), 'mipsel': (1, 1, 8)}[platform.split('-')[1]]
        assert data[:4] == b'\x7fELF' and tuple(data[4:6]) == expected[:2]
        wide = data[4] == 2
        endian = '<' if data[5] == 1 else '>'
        header = struct.unpack_from(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
        assert header[:2] == (3, expected[2]), 'expected a position independent ET_DYN executable'
        segments = [struct.unpack_from(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'), data,
                                      header[4] + index * header[8]) for index in range(header[9])]
        assert all(segment[0] != 3 for segment in segments), 'unexpected dynamic interpreter'
        stack = next(segment for segment in segments if segment[0] == 0x6474e551)
        assert stack[1 if wide else 6] & 1 == 0, 'executable stack'
        assert any(segment[0] == 0x6474e552 for segment in segments), 'missing RELRO'
        dynamic = next(segment for segment in segments if segment[0] == 2)
        offset, length = (dynamic[2], dynamic[5]) if wide else (dynamic[1], dynamic[4])
        tags = dict(struct.iter_unpack(endian + ('qQ' if wide else 'iI'), data[offset:offset + length]))
        assert 1 not in tags, 'unexpected shared library dependency'
        assert tags.get(30, 0) & 8 or tags.get(0x6ffffffb, 0) & 1, 'missing immediate binding'
        if 'armv7' in platform:
            assert header[6] & 0x400, 'expected hard-float EABI'
        if 'mips' in platform:
            assert header[6] & 0xf0000000 == 0x70000000, 'expected MIPS32r2'
    elif platform.startswith('darwin-'):
        assert data[:4] == b'\xcf\xfa\xed\xfe'
        cpu, _, kind, _, _, flags = struct.unpack_from('<6I', data, 4)
        assert cpu == (0x1000007 if platform.endswith('amd64') else 0x100000c)
        assert kind == 2 and flags & 0x200000, 'expected PIE Mach-O executable'
    else:
        assert data[:2] == b'MZ'
        offset = struct.unpack_from('<I', data, 60)[0]
        assert data[offset:offset + 4] == b'PE\0\0'
        machine = struct.unpack_from('<H', data, offset + 4)[0]
        assert machine == (0x8664 if platform.endswith('amd64') else 0xaa64)
        assert struct.unpack_from('<H', data, offset + 24)[0] == 0x20b
        flags = struct.unpack_from('<H', data, offset + 24 + 70)[0]
        assert flags & 0x140 == 0x140, 'expected ASLR and DEP'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('platform', choices=PLATFORMS)
    args = parser.parse_args()
    build = Path(__file__).resolve().parents[2] / 'build' / args.platform
    binary = build / ('ftun.exe' if args.platform.startswith('windows-') else 'ftun')
    inspect(args.platform, binary.read_bytes())
    manifest = dict(line.split('=', 1) for line in (build / 'ftun-build-modules.txt').read_text().splitlines())
    assert all(manifest[module] == 'BUILTIN' for module in ('core', 'proxy', 'dns', 'fakeip', 'frs'))
    assert manifest['tun'] == ('BUILTIN' if not args.platform.startswith('darwin-') else 'OFF')
    if args.platform.startswith('windows-') and manifest['tun'] == 'BUILTIN':
        runtime = json.loads((build.parents[1] / 'third_party/LOCK.json').read_text())['wintun_runtime']
        dll = (build / 'wintun.dll').read_bytes()
        assert hashlib.sha256(dll).hexdigest() == runtime['binaries'][args.platform.split('-')[1]]['sha256']
        assert hashlib.sha256((build / 'LICENSE-Wintun-binaries').read_bytes()).hexdigest() == runtime['license_sha256']
        inspect(args.platform, dll)
        offset = struct.unpack_from('<I', dll, 60)[0]
        certificate, size = struct.unpack_from('<II', dll, offset + 24 + 112 + 4 * 8)
        assert certificate and size and certificate + size <= len(dll), 'missing Authenticode certificate data'
    print(f'{args.platform}: executable architecture, hardening and modules passed')


if __name__ == '__main__':
    main()

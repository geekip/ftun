#!/usr/bin/env python3
"""Check the selected ELF delivery contract and feature manifest."""

import json
from pathlib import Path
import subprocess
import sys


def fail(message):
  print(f"release contract failed: {message}", file=sys.stderr)
  return 1


def run(*arguments):
  return subprocess.run(arguments, check=True, text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT).stdout


def main():
  if len(sys.argv) != 8:
    return fail("binary, manifest, static/hardening expectations, compile database, source root and configuration are required")
  binary = Path(sys.argv[1])
  manifest = Path(sys.argv[2])
  expect_static = sys.argv[3] == "1"
  expect_hardening = sys.argv[4] in {"1", "ON", "TRUE"}
  compile_database = Path(sys.argv[5])
  source_root = Path(sys.argv[6]).resolve()
  configuration = sys.argv[7]
  if not binary.is_file() or not manifest.is_file() or not compile_database.is_file():
    return fail("binary, feature manifest or compile database is missing")
  try:
    description = run("file", str(binary))
    elf_header = run("readelf", "-W", "-h", str(binary))
    program_headers = run("readelf", "-W", "-l", str(binary))
    dynamic = run("readelf", "-W", "-d", str(binary))
    symbols = run("readelf", "-W", "-s", str(binary))
  except (OSError, subprocess.CalledProcessError) as error:
    return fail(f"cannot inspect ELF: {error}")
  if "ELF 64-bit" not in description or "x86-64" not in description:
    return fail("release binary is not Linux x86_64 ELF")
  if expect_static:
    if "statically linked" not in description and "static-pie linked" not in description:
      return fail("full-static profile is not reported as statically linked")
    if " INTERP " in program_headers or "(NEEDED)" in dynamic:
      return fail("full-static ELF contains PT_INTERP or DT_NEEDED")
  if expect_hardening:
    if "DYN (Position-Independent Executable file)" not in elf_header:
      return fail("hardening profile is not PIE")
    if "GNU_RELRO" not in program_headers:
      return fail("hardening profile has no GNU_RELRO segment")
    stack_line = next((line for line in program_headers.splitlines()
                       if "GNU_STACK" in line), "")
    if not stack_line or " RWE " in stack_line:
      return fail("hardening profile has an executable stack")
    if not expect_static and "BIND_NOW" not in dynamic and " NOW" not in dynamic:
      return fail("dynamic hardening profile does not bind relocations at startup")
    if "__stack_chk_fail" not in symbols:
      return fail("hardening profile has no stack protector reference")
    try:
      commands = json.loads(compile_database.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
      return fail(f"cannot read compile database: {error}")
    protected = []
    first_party_count = 0
    protected_directories = (
      source_root / "src",
      source_root / "third_party" / "cjson",
      source_root / "third_party" / "wolfssl",
      source_root / "third_party" / "lwip",
    )
    for entry in commands:
      source = Path(entry.get("file", ""))
      if not source.is_absolute():
        source = Path(entry.get("directory", ".")) / source
      source = source.resolve()
      matched = None
      for directory in protected_directories:
        try:
          source.relative_to(directory)
          matched = directory
          break
        except ValueError:
          pass
      if matched is None:
        continue
      if matched == protected_directories[0]:
        first_party_count += 1
      protected.append(entry.get("command", " ".join(entry.get("arguments", []))))
    if first_party_count == 0:
      return fail("compile database has no first-party sources")
    if any("-fstack-protector-strong" not in command or
           "-fPIE" not in command for command in protected):
      return fail("a first-party or locked third-party source is missing stack protection or PIE")
    if configuration != "Debug" and any("_FORTIFY_SOURCE=3" not in command
                                         for command in protected):
      return fail("an optimized protected source is missing FORTIFY_SOURCE=3")
  values = {}
  for line in manifest.read_text(encoding="utf-8").splitlines():
    if "=" in line:
      key, value = line.split("=", 1)
      values[key] = value
  if set(values) != {"core", "proxy", "dns", "fakeip", "tun", "frs",
                     "mesh"} or values.get("core") != "BUILTIN" or (
      values.get("proxy") not in {"OFF", "BUILTIN"}) or (
      values.get("mesh") != "OFF"):
    return fail("feature manifest is incomplete")
  if any(value not in {"OFF", "BUILTIN"} for value in values.values()):
    return fail("feature manifest contains an unsupported mode")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

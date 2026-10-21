#!/usr/bin/env python3
"""Check the selected ELF delivery contract and feature manifest."""

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
  if len(sys.argv) != 4:
    return fail("binary, module manifest and static expectation are required")
  binary = Path(sys.argv[1])
  manifest = Path(sys.argv[2])
  expect_static = sys.argv[3] == "1"
  if not binary.is_file() or not manifest.is_file():
    return fail("binary or feature manifest is missing")
  try:
    description = run("file", str(binary))
    program_headers = run("readelf", "-W", "-l", str(binary))
    dynamic = run("readelf", "-W", "-d", str(binary))
  except (OSError, subprocess.CalledProcessError) as error:
    return fail(f"cannot inspect ELF: {error}")
  if "ELF 64-bit" not in description or "x86-64" not in description:
    return fail("release binary is not Linux x86_64 ELF")
  if expect_static:
    if "statically linked" not in description:
      return fail("full-static profile is not reported as statically linked")
    if " INTERP " in program_headers or "(NEEDED)" in dynamic:
      return fail("full-static ELF contains PT_INTERP or DT_NEEDED")
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

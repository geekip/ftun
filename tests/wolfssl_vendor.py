#!/usr/bin/env python3
"""Validate the pinned wolfSSL submodule and its compile boundary."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


REVISION = "59f4fa568615396fbf381b073b220d1e8d61e4c2"
TAG = "v5.8.4-stable"
COPYING_SHA256 = "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903"


def fail(message):
  print(f"wolfSSL vendor check failed: {message}", file=sys.stderr)
  return 1


def git(vendor, *arguments):
  return subprocess.run(
    ["git", "-C", str(vendor), *arguments], check=True,
    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def main():
  if len(sys.argv) != 3:
    return fail("source root and compile_commands.json are required")
  root = Path(sys.argv[1])
  vendor = root / "third_party/wolfssl"
  try:
    if git(vendor, "rev-parse", "HEAD") != REVISION:
      return fail("submodule revision differs from the reviewed release")
    if git(vendor, "describe", "--tags", "--exact-match") != TAG:
      return fail("submodule is not at the reviewed release tag")
    if git(vendor, "status", "--porcelain"):
      return fail("submodule contains local modifications")
  except (OSError, subprocess.CalledProcessError) as error:
    return fail(f"cannot inspect submodule: {error}")
  if hashlib.sha256((vendor / "COPYING").read_bytes()).hexdigest() != (
      COPYING_SHA256):
    return fail("retained GPLv3 license differs from the reviewed release")

  commands = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
  wolfssl = [entry for entry in commands
             if "/third_party/wolfssl/" in entry["file"]]
  if not wolfssl:
    return fail("wolfSSL sources were not compiled")
  required = ("-DWOLFSSL_TLS13", "-DNO_OLD_TLS", "-DHAVE_SNI")
  if any(any(option not in entry["command"] for option in required)
         for entry in wolfssl):
    return fail("TLS 1.3, obsolete-TLS removal or SNI options are missing")
  forbidden = ("/examples/", "/tests/", "/benchmark/")
  if any(any(path in entry["file"] for path in forbidden)
         for entry in wolfssl):
    return fail("upstream examples, tests or benchmarks were compiled")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

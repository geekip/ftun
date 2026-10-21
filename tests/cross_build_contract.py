#!/usr/bin/env python3
"""Verify native trimming and fail-closed ARM/OpenWrt configuration."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def fail(message):
  print(f"cross build contract failed: {message}", file=sys.stderr)
  return 1


def configure(root, cmake, *definitions):
  environment = os.environ.copy()
  for name in list(environment):
    if name.startswith("FTUN_OPENWRT_"):
      del environment[name]
  with tempfile.TemporaryDirectory(prefix="ftun-openwrt-contract-") as build:
    return subprocess.run(
      [cmake, "-S", str(root), "-B", build,
       "-DCMAKE_TOOLCHAIN_FILE=" + str(
         root / "cmake/toolchains/linux-openwrt-arm.cmake"), *definitions],
      check=False, text=True, stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT, env=environment)


def main():
  if len(sys.argv) != 3:
    return fail("source root and cmake executable are required")
  root = Path(sys.argv[1]).resolve()
  cmake = sys.argv[2]
  presets = json.loads((root / "CMakePresets.json").read_text(encoding="utf-8"))
  configured = {item["name"]: item for item in presets["configurePresets"]}
  trimmed = configured.get("release-trimmed", {})
  values = trimmed.get("cacheVariables", {})
  expected = {
    "CMAKE_BUILD_TYPE": "Release",
    "FTUN_OPTIMIZATION": "balanced",
    "FTUN_SECTION_GC": True,
    "FTUN_MODULE_DNS": "OFF",
    "FTUN_MODULE_FAKEIP": "OFF",
    "FTUN_MODULE_TUN": "OFF",
    "FTUN_MODULE_FRS": "OFF",
  }
  if any(values.get(name) != value for name, value in expected.items()):
    return fail("release-trimmed must retain O2/section GC and disable optional modules")
  cross = configured.get("linux-openwrt-arm", {})
  if cross.get("inherits") != "release-trimmed" or (
      cross.get("cacheVariables", {}).get("BUILD_TESTING") is not False):
    return fail("linux-openwrt-arm must inherit the non-runnable trimmed profile")
  toolchain = cross.get("toolchainFile", "")
  if not toolchain.endswith("/cmake/toolchains/linux-openwrt-arm.cmake"):
    return fail("linux-openwrt-arm toolchain is missing")

  missing = configure(root, cmake)
  if missing.returncode == 0 or "FTUN_OPENWRT_PROCESSOR is required" not in missing.stdout:
    return fail("missing SDK inputs did not fail at configure time")
  invalid = configure(root, cmake, "-DFTUN_OPENWRT_PROCESSOR=x86_64")
  if invalid.returncode == 0 or (
      "FTUN_OPENWRT_PROCESSOR must be arm, armv7 or aarch64" not in invalid.stdout):
    return fail("non-ARM target was not rejected")
  host_cc = shutil.which("cc")
  host_ar = shutil.which("ar")
  host_ranlib = shutil.which("ranlib")
  if not host_cc or not host_ar or not host_ranlib:
    return fail("host compiler tools are required for the negative target check")
  host = configure(
    root, cmake, "-DFTUN_OPENWRT_PROCESSOR=aarch64",
    "-DFTUN_OPENWRT_CC=" + host_cc, "-DFTUN_OPENWRT_AR=" + host_ar,
    "-DFTUN_OPENWRT_RANLIB=" + host_ranlib,
    "-DFTUN_OPENWRT_SYSROOT=/")
  if host.returncode == 0 or "FTUN_OPENWRT_CC does not target ARM" not in host.stdout:
    return fail("host compiler was accepted as an ARM cross compiler")
  print("cross build contract: ok")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

#!/usr/bin/env python3
"""Validate the locked heiher/lwIP tree, local patch and compile boundary."""

import hashlib
import json
from pathlib import Path
import sys
import subprocess


def fail(message):
  print(f"lwIP vendor check failed: {message}", file=sys.stderr)
  return 1


def tree_digest(vendor):
  manifest = bytearray()
  files = sorted(path for path in vendor.rglob("*")
                 if path.is_file() and path.name != "FTUN-UPSTREAM.json")
  for path in files:
    relative = path.relative_to(vendor).as_posix()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest.extend(f"{digest}  {relative}\n".encode("utf-8"))
  return hashlib.sha256(manifest).hexdigest()


def main():
  if len(sys.argv) != 3:
    return fail("source root and compile_commands.json are required")
  root = Path(sys.argv[1])
  vendor = root / "third_party/lwip"
  metadata = json.loads((root / "third_party/lwip.UPSTREAM.json").read_text(encoding="utf-8"))
  revision = "150d2b1a2658612741b4ac002578d440e7874540"
  archive_digest = "bab562a52da5ccad9e66ec3af98e559249c0da2cb21ef68a399bc91cae31a416"
  if metadata.get("revision") != revision or metadata.get("sha256") != archive_digest:
    return fail("revision or archive digest differs from the reviewed commit")
  if metadata.get("license") != "BSD-3-Clause" or hashlib.sha256(
      (vendor / "LICENSE").read_bytes()).hexdigest() != metadata.get("license_sha256"):
    return fail("license declaration or retained license differs")
  if metadata.get("source_form") != "git-submodule" or metadata.get("local_patches") != []:
    return fail("lwIP must use the unmodified dual-stack submodule")
  actual = subprocess.check_output(["git", "-C", str(vendor), "rev-parse", "HEAD"], text=True).strip()
  if actual != revision or subprocess.run(["git", "-C", str(vendor), "diff", "--quiet", "HEAD"]).returncode:
    return fail("submodule differs from the pinned upstream revision")

  commands = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
  lwip_commands = [entry["command"] for entry in commands
                   if "/third_party/lwip/src/core/" in entry["file"]]
  if len(lwip_commands) != 23:
    return fail("the reviewed raw-core source set must compile exactly once")
  required = ("/src/proxy/netstack", "/third_party/lwip/src/include")
  if any(any(item not in command for item in required) for command in lwip_commands):
    return fail("lwIP compile commands do not use the FTUN port configuration")
  forbidden = ("/src/api/", "/src/apps/", "/src/netif/", "/src/ports/")
  if any(any(item in entry["file"] for item in forbidden) for entry in commands
         if "/third_party/lwip/" in entry["file"]):
    return fail("socket, application, netif or upstream OS-port sources were compiled")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

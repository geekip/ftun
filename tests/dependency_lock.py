#!/usr/bin/env python3
"""Verify the public dependency lock, retained licenses and submodule pin."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


def fail(message):
  print(f"dependency lock check failed: {message}", file=sys.stderr)
  return 1


def sha256(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *arguments):
  return subprocess.run(
    ["git", "-C", str(root), *arguments], check=True, text=True,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def main():
  if len(sys.argv) != 2:
    return fail("source root is required")
  root = Path(sys.argv[1]).resolve()
  project_license = (root / "LICENSE").read_text(encoding="utf-8")
  if not project_license.startswith(
      "                    GNU GENERAL PUBLIC LICENSE\n"
      "                       Version 3, 29 June 2007\n"):
    return fail("FTUN root license is not the selected GNU GPL version 3")
  lock = json.loads((root / "third_party/LOCK.json").read_text(encoding="utf-8"))
  if lock.get("schema") != "ftun.third-party-lock/v1" or (
      lock.get("status") != "locked-and-reviewed") or not lock.get("offline_build"):
    return fail("lock schema, review status or offline policy is invalid")
  dependencies = lock.get("dependencies")
  if not isinstance(dependencies, list) or {item.get("name") for item in dependencies} != {
      "libev", "cJSON", "heiher/lwIP", "wolfSSL"}:
    return fail("dependency set is incomplete or contains an unreviewed entry")
  for dependency in dependencies:
    vendor = root / dependency.get("path", "")
    license_file = root / dependency.get("license_file", "")
    if not vendor.is_dir() or not license_file.is_file():
      return fail(f"{dependency.get('name')} source or license is missing")
    if sha256(license_file) != dependency.get("license_sha256"):
      return fail(f"{dependency.get('name')} retained license differs")
    if not dependency.get("license") or not dependency.get("build_boundary"):
      return fail(f"{dependency.get('name')} review metadata is incomplete")
    for patch in dependency.get("local_patches", []):
      patch_path = root / patch.get("path", "")
      if not patch_path.is_file() or sha256(patch_path) != patch.get("sha256"):
        return fail(f"{dependency.get('name')} local patch differs")
    metadata_path = dependency.get("metadata")
    if metadata_path:
      metadata = json.loads((root / metadata_path).read_text(encoding="utf-8"))
      if dependency.get("revision") is not None and (
          dependency["revision"] != metadata.get("revision")):
        return fail(f"{dependency.get('name')} revision disagrees with metadata")
      if dependency.get("version") is not None and (
          dependency["version"] != metadata.get("version")):
        return fail(f"{dependency.get('name')} version disagrees with metadata")
      if dependency.get("archive_sha256") != metadata.get("sha256"):
        return fail(f"{dependency.get('name')} archive digest disagrees with metadata")
      if dependency.get("vendored_tree_sha256") is not None and (
          dependency["vendored_tree_sha256"] !=
          metadata.get("vendored_tree_sha256")):
        return fail(f"{dependency.get('name')} tree digest disagrees with metadata")
  modules = (root / ".gitmodules").read_text(encoding="utf-8")
  if modules.count("path = ") != 1 or "path = third_party/wolfssl" not in modules:
    return fail("only the locked wolfSSL source may be a submodule")
  wolfssl = next(item for item in dependencies if item["name"] == "wolfSSL")
  try:
    index = git(root, "ls-files", "-s", "third_party/wolfssl").split()
    if len(index) < 2 or index[0] != "160000" or index[1] != wolfssl["revision"]:
      return fail("wolfSSL gitlink differs from the public lock")
    if git(root / wolfssl["path"], "rev-parse", "HEAD") != wolfssl["revision"]:
      return fail("checked-out wolfSSL revision differs from the public lock")
    if git(root / wolfssl["path"], "status", "--porcelain"):
      return fail("wolfSSL submodule has local modifications")
  except (OSError, subprocess.CalledProcessError) as error:
    return fail(f"cannot inspect wolfSSL submodule: {error}")
  notices = (root / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
  if any(name not in notices for name in ("libev", "cJSON", "lwIP", "wolfSSL")):
    return fail("third-party notice does not cover the complete lock")
  cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
  if "FetchContent" in cmake or "ExternalProject_Add" in cmake:
    return fail("build must not fetch dependencies")
  if "install(FILES LICENSE README.md" not in cmake:
    return fail("installed release materials omit the FTUN project license")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

#!/usr/bin/env python3
"""Verify the public dependency lock, retained licenses and submodule pin."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def fail(message):
  print(f"dependency lock check failed: {message}", file=sys.stderr)
  return 1


def sha256(path):
  return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *arguments):
  return subprocess.run(
    ["git", "-C", str(root), *arguments], check=True, text=True,
    stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def check_notices(root, lock, cmake):
  # 独立调用生产生成器，覆盖带空格路径、完整告知、无效输入及失败保全。
  with tempfile.TemporaryDirectory(prefix="ftun notice ") as directory:
    temporary = Path(directory)
    source = temporary / "LOCK.json"
    output = temporary / "THIRD_PARTY_NOTICES.md"
    command = [cmake, f"-DFTUN_DEPENDENCY_LOCK={source}",
               f"-DFTUN_NOTICES_OUTPUT={output}",
               "-P", str(root / "cmake/ThirdPartyNotices.cmake")]
    source.write_text(json.dumps(lock), encoding="utf-8")
    generated = subprocess.run(command, capture_output=True, text=True)
    if generated.returncode:
      return fail(f"cannot generate notices: {generated.stderr}")
    notices = output.read_text(encoding="utf-8")
    for dependency in lock["dependencies"]:
      for field in ("name", "source", "license", "selected_license",
                    "license_file", "build_boundary", "notice"):
        if dependency[field] not in notices:
          return fail(f"generated notice omits {dependency['name']} {field}")
      for patch in dependency["local_patches"]:
        if patch["description"] not in notices:
          return fail("generated notice omits a patch description")
    modified = json.loads(json.dumps(lock))
    modified["dependencies"][0]["notice"] = "Updated attribution; 保留完整文本."
    source.write_text(json.dumps(modified), encoding="utf-8")
    updated = subprocess.run(command, capture_output=True, text=True)
    if updated.returncode or modified["dependencies"][0]["notice"] not in output.read_text(encoding="utf-8"):
      return fail("notice generation did not preserve changed lock text")
    if lock["attribution_notice"] not in notices:
      return fail("generated notices omit the complete attribution license")
    if "README-third-party.md" not in notices:
      return fail("generated notices omit borrowed-code attribution")
    expected = output.read_bytes()
    for field in ("selected_license", "notice"):
      invalid = json.loads(json.dumps(modified))
      del invalid["dependencies"][0][field]
      source.write_text(json.dumps(invalid), encoding="utf-8")
      rejected = subprocess.run(command, capture_output=True, text=True)
      if rejected.returncode == 0 or output.read_bytes() != expected:
        return fail("invalid notice metadata was accepted or replaced the last valid output")
    invalid = json.loads(json.dumps(modified))
    del invalid["attribution_notice"]
    source.write_text(json.dumps(invalid), encoding="utf-8")
    rejected = subprocess.run(command, capture_output=True, text=True)
    if rejected.returncode == 0 or output.read_bytes() != expected:
      return fail("missing attribution license was accepted or replaced valid notices")
  return 0


def main():
  if len(sys.argv) not in (2, 3):
    return fail("source root is required")
  cmake = sys.argv[2] if len(sys.argv) == 3 else shutil.which("cmake")
  if not cmake:
    return fail("cmake is required to verify generated notices")
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
      "cJSON", "heiher/lwIP", "wolfSSL", "wepoll", "Wintun API"}:
    return fail("dependency set is incomplete or contains an unreviewed entry")
  for dependency in dependencies:
    vendor = root / dependency.get("path", "")
    license_file = root / dependency.get("license_file", "")
    if not vendor.is_dir() or not license_file.is_file():
      return fail(f"{dependency.get('name')} source or license is missing")
    if sha256(license_file) != dependency.get("license_sha256"):
      return fail(f"{dependency.get('name')} retained license differs")
    if any(not isinstance(dependency.get(field), str) or not dependency[field].strip()
           for field in ("license", "selected_license", "build_boundary", "notice")):
      return fail(f"{dependency.get('name')} review metadata is incomplete")
    if dependency.get("source_form") != "git-submodule" or dependency.get("local_patches") != []:
      return fail(f"{dependency['name']} must be an unmodified Git submodule")
  expected_entries = {"LOCK.json", "README.md"} | {Path(item["path"]).name for item in dependencies}
  if {path.name for path in (root / "third_party").iterdir()} != expected_entries:
    return fail("third_party must contain only LOCK.json, README.md and declared submodules")
  readme = (root / "third_party/README.md").read_text(encoding="utf-8")
  entries = {}
  labels = ("开源协议：", "使用版本：", "仓库地址：", "集成能力：")
  for section in readme.split("\n## ")[1:]:
    name, _, body = section.partition("\n")
    lines = [line for line in body.splitlines() if line.strip()]
    if name in entries or len(lines) != 4 or any(
        not line.startswith(label) or not line[len(label):].strip()
        for line, label in zip(lines, labels)):
      return fail("README sections must contain exactly the four requested fields")
    entries[name] = [line[len(label):] for line, label in zip(lines, labels)]
  for dependency in dependencies:
    fields = entries.get(dependency["name"])
    if fields is None or any(value not in field for value, field in zip((
        dependency["selected_license"], dependency["version"], dependency["source"]), fields)):
      return fail(f"{dependency['name']} README license, version or source differs from lock")
  # README 仅保留简介和字段；完整版权与许可由锁清单传递到分发告知。
  attribution = lock["attribution_notice"]
  permission = "Permission is hereby granted"
  mit = permission + (root / "third_party/cjson/LICENSE").read_text().split(permission, 1)[1]
  if " ".join(mit.split()) not in " ".join(attribution.split()) or any(notice not in attribution for notice in (
      "Copyright © 2005-2020 Rich Felker, et al.",
      "Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.", "src/util/ip.c")):
    return fail("lock omits borrowed-code/API attribution or complete MIT terms")
  modules = (root / ".gitmodules").read_text(encoding="utf-8")
  submodules = dependencies
  if modules.count("path = ") != len(submodules) or any(
      f"path = {item['path']}" not in modules for item in submodules):
    return fail("submodules differ from the public lock")
  try:
    for dependency in submodules:
      if (root / ".git").exists():
        index = git(root, "ls-files", "-s", dependency["path"]).split()
        if len(index) < 2 or index[0] != "160000" or index[1] != dependency["revision"]:
          return fail(f"{dependency['name']} gitlink differs from the public lock")
      if git(root / dependency["path"], "rev-parse", "HEAD") != dependency["revision"]:
        return fail(f"checked-out {dependency['name']} revision differs from the public lock")
      if git(root / dependency["path"], "status", "--porcelain"):
        return fail(f"{dependency['name']} submodule has local modifications")
  except (OSError, subprocess.CalledProcessError) as error:
    return fail(f"cannot inspect submodule: {error}")
  if (root / "THIRD_PARTY_NOTICES.md").exists():
    return fail("third-party notices must be generated, not maintained in the source tree")
  if check_notices(root, lock, cmake):
    return 1
  cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8") + "\n" + "\n".join(p.read_text() for p in (root / "cmake").glob("*.cmake"))
  if "FetchContent" in cmake or "ExternalProject_Add" in cmake:
    return fail("build must not fetch dependencies")
  if "install(FILES LICENSE README.md" not in cmake:
    return fail("installed release materials omit the FTUN project license")
  if (root / "document").exists() or "document/" in cmake:
    return fail("development documents must not be installed as user documentation")
  release_workflow = (
    root / ".github/workflows/release.yml"
  ).read_text(encoding="utf-8")
  if "document/" in release_workflow:
    return fail("release workflow depends on the retired document directory")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

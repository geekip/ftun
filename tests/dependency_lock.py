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
    expected = output.read_bytes()
    for field in ("selected_license", "notice"):
      invalid = json.loads(json.dumps(modified))
      del invalid["dependencies"][0][field]
      source.write_text(json.dumps(invalid), encoding="utf-8")
      rejected = subprocess.run(command, capture_output=True, text=True)
      if rejected.returncode == 0 or output.read_bytes() != expected:
        return fail("invalid notice metadata was accepted or replaced the last valid output")
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
      "musl IP text codecs", "cJSON", "heiher/lwIP", "wolfSSL", "wepoll", "Wintun API"}:
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
    for patch in dependency.get("local_patches", []):
      if not isinstance(patch.get("description"), str) or not patch["description"].strip():
        return fail(f"{dependency.get('name')} patch description is missing")
      patch_path = root / patch.get("path", "")
      if not patch_path.is_file() or sha256(patch_path) != patch.get("sha256"):
        return fail(f"{dependency.get('name')} local patch differs")
    for name, expected in dependency.get("source_files", {}).items():
      if sha256(vendor / name) != expected:
        return fail(f"{dependency['name']} source snapshot differs: {name}")
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
  submodules = [item for item in dependencies if item.get("source_form") == "git-submodule"]
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

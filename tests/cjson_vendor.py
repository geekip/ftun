#!/usr/bin/env python3
"""Validate the locked cJSON source subset and compile boundary."""

import hashlib
import json
from pathlib import Path
import sys


def fail(message):
  print(f"cJSON vendor check failed: {message}", file=sys.stderr)
  return 1


def main():
  if len(sys.argv) != 3:
    return fail("source root and compile_commands.json are required")
  root = Path(sys.argv[1])
  vendor = root / "third_party/cjson"
  metadata = json.loads((vendor / "FTUN-UPSTREAM.json").read_text(encoding="utf-8"))
  expected = {"cJSON.c", "cJSON.h", "LICENSE", "SECURITY.md", "FTUN-UPSTREAM.json"}
  if {path.name for path in vendor.iterdir() if path.is_file()} != expected:
    return fail("vendored file set differs from the reviewed source subset")
  if metadata.get("version") != "1.7.19" or metadata.get("revision") != (
      "c859b25da02955fef659d658b8f324b5cde87be3"):
    return fail("version or revision differs from the reviewed release")
  if metadata.get("sha256") != (
      "7fa616e3046edfa7a28a32d5f9eacfd23f92900fe1f8ccd988c1662f30454562"):
    return fail("release archive digest differs from the reviewed value")
  if metadata.get("local_patches") != []:
    return fail("local patch declaration is stale")
  for name, expected_hash in metadata.get("vendored_files", {}).items():
    actual_hash = hashlib.sha256((vendor / name).read_bytes()).hexdigest()
    if actual_hash != expected_hash:
      return fail(f"{name} differs from the locked upstream file")
  commands = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
  cjson_commands = [entry["command"] for entry in commands
                    if entry["file"].endswith("/cjson/cJSON.c")]
  if len(cjson_commands) != 1 or "CJSON_NESTING_LIMIT=32" not in cjson_commands[0]:
    return fail("cJSON must compile once with the reviewed nesting limit")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

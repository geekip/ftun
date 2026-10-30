#!/usr/bin/env python3
"""Verify that the unmodified cJSON submodule compiles only its parser."""

import json
from pathlib import Path
import sys


def main():
  if len(sys.argv) != 3:
    print("source root and compile_commands.json are required", file=sys.stderr)
    return 1
  root = Path(sys.argv[1]).resolve()
  vendor = root / "third_party/cjson"
  commands = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
  sources = [entry for entry in commands if vendor in Path(entry["file"]).parents]
  if len(sources) != 1 or Path(sources[0]["file"]).name != "cJSON.c" or (
      "CJSON_NESTING_LIMIT=32" not in sources[0]["command"]):
    print("cJSON must compile only cJSON.c once with nesting limit 32", file=sys.stderr)
    return 1
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

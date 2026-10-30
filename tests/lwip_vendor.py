#!/usr/bin/env python3
"""Verify the raw-core compile boundary of the locked lwIP submodule."""

import json
from pathlib import Path
import sys


def fail(message):
  print(f"lwIP vendor check failed: {message}", file=sys.stderr)
  return 1


def main():
  if len(sys.argv) != 3:
    return fail("source root and compile_commands.json are required")
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

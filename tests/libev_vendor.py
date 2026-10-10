#!/usr/bin/env python3
"""Validate the locked full libev release and its FTUN compile boundary."""

import json
from pathlib import Path
import sys


def fail(message):
  print(f"libev vendor check failed: {message}", file=sys.stderr)
  return 1


def main():
  if len(sys.argv) != 3:
    return fail("source root and compile_commands.json are required")
  root = Path(sys.argv[1])
  commands_path = Path(sys.argv[2])
  vendor = root / "third_party/libev"
  metadata = json.loads((vendor / "FTUN-UPSTREAM.json").read_text(encoding="utf-8"))
  expected_files = {
    "Changes", "LICENSE", "Makefile.am", "Makefile.in", "README", "Symbols.ev",
    "Symbols.event", "TODO", "aclocal.m4", "autogen.sh", "compile", "config.guess",
    "config.h.in", "config.sub", "configure", "configure.ac", "depcomp", "ev++.h",
    "ev.3", "ev.c", "ev.h", "ev.pod", "ev_epoll.c", "ev_iouring.c",
    "ev_kqueue.c", "ev_linuxaio.c", "ev_poll.c", "ev_port.c", "ev_select.c",
    "ev_vars.h", "ev_win32.c", "ev_wrap.h", "event.c", "event.h", "install-sh",
    "libev.m4", "ltmain.sh", "missing", "mkinstalldirs",
  }
  actual_files = {path.name for path in vendor.iterdir() if path.is_file()}
  allowed_extra = {"FTUN-UPSTREAM.json"}
  if actual_files != expected_files | allowed_extra:
    return fail("vendored release file set is incomplete or has unreviewed files")
  if metadata.get("version") != "4.33" or metadata.get("sha256") != (
      "507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea"):
    return fail("version or archive digest differs from the reviewed release")
  if metadata.get("signature_verified") is not True or metadata.get("local_patches") != []:
    return fail("signature verification or patch declaration is stale")
  commands = json.loads(commands_path.read_text(encoding="utf-8"))
  ev_commands = [entry["command"] for entry in commands if entry["file"].endswith("/libev/ev.c")]
  if len(ev_commands) != 1:
    return fail("ev.c must appear exactly once in compile_commands.json")
  command = ev_commands[0]
  required = ("EV_STANDALONE=1", "EV_NO_THREADS=0",
              'EV_ATOMIC_T="_Atomic sig_atomic_t"', "EV_USE_EPOLL=1",
              "EV_USE_SELECT=0", "EV_USE_POLL=0", "EV_USE_IOURING=0")
  if any(item not in command for item in required):
    return fail("libev compile definitions do not preserve the reviewed Linux boundary")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

#!/usr/bin/env python3
"""Measure the idle CLI process, executable sizes and deployment payload."""

import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time


RUNS = 3
MAX_BINARY_BYTES = 8 * 1024 * 1024
MAX_STRIPPED_BYTES = 4 * 1024 * 1024
MAX_RSS_KIB = 64 * 1024
MAX_PSS_KIB = 64 * 1024
MAX_FDS = 32
MAX_IDLE_CPU_PERCENT = 10.0


def fail(message):
  print(f"resource profile failed: {message}", file=sys.stderr)
  return 1


def proc_kib(pid):
  values = {}
  for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[0] in {"Rss:", "Pss:"}:
      values[fields[0][:-1].lower()] = int(fields[1])
  return values["rss"], values["pss"]


def proc_ticks(pid):
  fields = Path(f"/proc/{pid}/stat").read_text().split()
  return int(fields[13]) + int(fields[14])


def percentile(values, numerator, denominator):
  ordered = sorted(values)
  return ordered[min(len(ordered) - 1,
                     (len(ordered) * numerator) // denominator)]


def main():
  if len(sys.argv) != 4:
    return fail("binary, source root and config template are required")
  binary = Path(sys.argv[1]).resolve()
  root = Path(sys.argv[2]).resolve()
  template = Path(sys.argv[3]).read_text(encoding="utf-8")
  if not binary.is_file():
    return fail("ftun binary is missing")
  notices = binary.parent / "THIRD_PARTY_NOTICES.md"
  if not notices.is_file():
    return fail("generated third-party notices are missing from the build directory")
  samples = []
  with tempfile.TemporaryDirectory(prefix="ftun-resource-") as directory:
    temporary = Path(directory)
    stripped = temporary / "ftun.stripped"
    shutil.copy2(binary, stripped)
    strip = shutil.which("strip")
    if strip is None:
      return fail("strip is required for release size measurement")
    subprocess.run([strip, str(stripped)], check=True)
    for run in range(RUNS):
      config = temporary / f"run-{run}.json"
      cache = temporary / f"cache-{run}"
      config.write_text(template.replace("@CACHE@", str(cache)),
                        encoding="utf-8")
      process = subprocess.Popen(
        [str(binary), "run", "-c", str(config)], stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True)
      try:
        time.sleep(0.20)
        if process.poll() is not None:
          return fail(f"ftun exited during sampling: {process.stderr.read()}")
        rss, pss = proc_kib(process.pid)
        fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
        ticks_start = proc_ticks(process.pid)
        wall_start = time.monotonic()
        time.sleep(0.30)
        ticks_end = proc_ticks(process.pid)
        wall = time.monotonic() - wall_start
        cpu = (ticks_end - ticks_start) / os.sysconf("SC_CLK_TCK")
        cpu_percent = 100.0 * cpu / wall
        samples.append({"rss_kib": rss, "pss_kib": pss, "fds": fds,
                        "idle_cpu_percent": round(cpu_percent, 3)})
      finally:
        if process.poll() is None:
          process.send_signal(signal.SIGTERM)
        try:
          process.wait(timeout=5)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait()
      if process.returncode != 0:
        return fail(f"ftun did not stop cleanly: {process.stderr.read()}")
    unstripped_bytes = binary.stat().st_size
    stripped_bytes = stripped.stat().st_size
    deployment_bytes = stripped_bytes + notices.stat().st_size + sum(
      (root / name).stat().st_size for name in
      ("LICENSE", "third_party/LOCK.json",
       "README.md"))
  report = {
    "runs": RUNS,
    "binary_unstripped_bytes": unstripped_bytes,
    "binary_stripped_bytes": stripped_bytes,
    "deployment_minimum_bytes": deployment_bytes,
    "rss_kib": [sample["rss_kib"] for sample in samples],
    "pss_kib": [sample["pss_kib"] for sample in samples],
    "fds": [sample["fds"] for sample in samples],
    "idle_cpu_percent": [sample["idle_cpu_percent"] for sample in samples],
    "rss_median_kib": statistics.median(sample["rss_kib"] for sample in samples),
    "rss_p95_kib": percentile([sample["rss_kib"] for sample in samples], 95, 100),
  }
  print(json.dumps(report, sort_keys=True))
  if (unstripped_bytes > MAX_BINARY_BYTES or
      stripped_bytes > MAX_STRIPPED_BYTES or
      max(sample["rss_kib"] for sample in samples) > MAX_RSS_KIB or
      max(sample["pss_kib"] for sample in samples) > MAX_PSS_KIB or
      max(sample["fds"] for sample in samples) > MAX_FDS or
      max(sample["idle_cpu_percent"] for sample in samples) >
      MAX_IDLE_CPU_PERCENT):
    return fail("a measured resource regression threshold was exceeded")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

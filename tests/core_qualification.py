#!/usr/bin/env python3
"""Core v1.0 capacity, exploration and long-soak qualification."""

import json
import hashlib
import math
import os
from pathlib import Path
import resource
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from core_capacity import (exact, pick_port, tcp_connect, udp_associate,
                           udp_round_trip)


FORMAL_FLOWS = 1000
EXPLORE_FLOWS = 10000


def fail(message):
  print(f"core qualification failed: {message}", file=sys.stderr)
  return 1


def pick_udp_port():
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    probe.bind(("127.0.0.1", 0))
    return probe.getsockname()[1]


def process_usage(pid):
  values = {"rss_kib": 0, "pss_kib": 0}
  for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
    fields = line.split()
    if fields and fields[0] == "Rss:":
      values["rss_kib"] = int(fields[1])
    elif fields and fields[0] == "Pss:":
      values["pss_kib"] = int(fields[1])
  values["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
  stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
  fields = stat[stat.rfind(")") + 2:].split()
  ticks = int(fields[11]) + int(fields[12])
  values["cpu_seconds"] = round(ticks / os.sysconf("SC_CLK_TCK"), 3)
  return values


def close_tcp(stream):
  try:
    stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                      struct.pack("ii", 1, 0))
  except OSError:
    pass
  stream.close()


def close_udp(resource_value):
  resource_value[0].close()
  resource_value[1].close()


def tcp_progress(stream, index, sequence):
  payload = struct.pack("!II", index, sequence) + b"ftun-qualification-tcp"
  stream.sendall(payload)
  if exact(stream, len(payload)) != payload:
    raise ConnectionError(f"TCP echo mismatch for flow {index}")


def udp_progress(resource_value, target_port, index, sequence):
  udp_round_trip(resource_value, target_port,
                 ((index & 0xffff) << 16) | (sequence & 0xffff), timeout=3)


def write_config(path, proxy_port, capacity, tcp_capacity=None,
                 log_level="silent"):
  if tcp_capacity is None:
    tcp_capacity = capacity
  document = {
    "base": {"state-cache": False, "capacity": {
      "tcp-flows": tcp_capacity, "udp-flows": capacity,
      "udp-associations": capacity}},
    "dns": {"enable": False},
    "log": {"level": log_level},
    "inbounds": [{"name": "qualification", "type": "socks5",
                  "listen": f"127.0.0.1:{proxy_port}", "udp": True}],
    "rules": ["MATCH,DIRECT"],
  }
  temporary = path.with_suffix(".next")
  temporary.write_text(json.dumps(document), encoding="utf-8")
  temporary.replace(path)


def wait_listener(process, port, log_path):
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    if process.poll() is not None:
      break
    try:
      with socket.create_connection(("127.0.0.1", port), timeout=0.05):
        return
    except OSError:
      time.sleep(0.01)
  detail = log_path.read_text(errors="replace") if log_path.exists() else ""
  raise RuntimeError(f"FTUN listener unavailable: {detail[-1000:]}")


def wait_log(process, log_path, marker, previous, timeout=5):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    text = log_path.read_text(errors="replace")
    if text.count(marker) > previous:
      return
    if process.poll() is not None:
      raise RuntimeError(f"FTUN exited while waiting for {marker}")
    time.sleep(0.02)
  raise TimeoutError(f"log marker not observed: {marker}")


def wait_reclaim(process, maximum=32, timeout=15):
  deadline = time.monotonic() + timeout
  count = 1 << 30
  while time.monotonic() < deadline and process.poll() is None:
    count = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
    if count < maximum:
      return count
    time.sleep(0.02)
  raise RuntimeError(f"descriptors were not reclaimed: {count}")


def stop_process(process, timeout=20):
  if process is None or process.poll() is not None:
    return
  process.send_signal(signal.SIGTERM)
  try:
    process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
    process.kill()
    process.wait()


def start_echo(directory):
  tcp_port = pick_port()
  udp_port = pick_udp_port()
  ready = directory / "echo.ready"
  result = directory / "echo.result"
  log_path = directory / "echo.log"
  log = log_path.open("w+")
  script = Path(__file__).resolve().with_name("core_capacity_matrix.py")
  process = subprocess.Popen([
    sys.executable, str(script), "--echo", "127.0.0.1", str(tcp_port),
    str(udp_port), str(ready), str(result)], stdout=subprocess.DEVNULL,
    stderr=log)
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    if ready.exists():
      return process, log, tcp_port, udp_port, result
    if process.poll() is not None:
      break
    time.sleep(0.01)
  log.flush()
  detail = log_path.read_text(errors="replace")
  stop_process(process)
  log.close()
  raise RuntimeError(f"echo backend unavailable: {detail[-1000:]}")


def child_fd_limit(limit):
  def apply_limit():
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(limit, hard), hard))
  return apply_limit


class RunningFtun:
  def __init__(self, binary, directory, capacity, fd_limit=None):
    self.binary = binary
    self.directory = directory
    self.capacity = capacity
    self.proxy_port = pick_port()
    self.config = directory / f"ftun-{self.proxy_port}.json"
    self.log_path = directory / f"ftun-{self.proxy_port}.log"
    write_config(self.config, self.proxy_port, capacity)
    self.log = self.log_path.open("w+")
    preexec = child_fd_limit(fd_limit) if fd_limit is not None else None
    self.process = subprocess.Popen(
      [str(binary), "run", "-c", str(self.config)],
      stdout=subprocess.DEVNULL, stderr=self.log, preexec_fn=preexec)
    wait_listener(self.process, self.proxy_port, self.log_path)

  def close(self):
    stop_process(self.process)
    self.log.close()
    if self.process.returncode != 0:
      detail = self.log_path.read_text(errors="replace")
      raise RuntimeError(
        f"FTUN exited with {self.process.returncode}: {detail[-1000:]}")


def require_rejection(factory):
  try:
    value = factory()
  except (ConnectionError, OSError, TimeoutError) as error:
    return type(error).__name__
  if isinstance(value, tuple):
    close_udp(value)
  else:
    close_tcp(value)
  raise RuntimeError("capacity overflow was accepted")


def cleanup_case(daemon, tcp, udp):
  for stream in tcp:
    close_tcp(stream)
  for association in udp:
    close_udp(association)
  reclaimed = None
  try:
    reclaimed = wait_reclaim(daemon.process)
  finally:
    daemon.close()
  return {"fds_before_exit": reclaimed,
          "process_exit_code": daemon.process.returncode}


def formal_case(binary, directory, tcp_port, udp_port, kind):
  daemon = RunningFtun(binary, directory, FORMAL_FLOWS)
  tcp = []
  udp = []
  result = None
  reloads = 0
  started = time.monotonic()
  try:
    if kind in {"tcp", "mixed"}:
      for index in range(FORMAL_FLOWS):
        stream = None
        try:
          stream = tcp_connect(daemon.proxy_port, tcp_port)
          tcp_progress(stream, index, 0)
        except Exception:
          if stream is not None:
            close_tcp(stream)
          raise
        tcp.append(stream)
      tcp_rejection = require_rejection(
        lambda: tcp_connect(daemon.proxy_port, tcp_port))
    else:
      tcp_rejection = "not-attempted"
    if kind in {"udp", "mixed"}:
      for index in range(FORMAL_FLOWS):
        association = None
        try:
          association = udp_associate(daemon.proxy_port)
          udp_progress(association, udp_port, index, 0)
        except Exception:
          if association is not None:
            close_udp(association)
          raise
        udp.append(association)
      udp_rejection = require_rejection(
        lambda: udp_associate(daemon.proxy_port))
    else:
      udp_rejection = "not-attempted"
    if kind == "mixed":
      for index, stream in enumerate(tcp):
        tcp_progress(stream, index, 1)
      marker = "ftun: reload committed"
      previous = daemon.log_path.read_text(errors="replace").count(marker)
      write_config(daemon.config, daemon.proxy_port, FORMAL_FLOWS,
                   log_level="error")
      daemon.process.send_signal(signal.SIGHUP)
      wait_log(daemon.process, daemon.log_path, marker, previous)
      reloads += 1
      for index, stream in enumerate(tcp):
        tcp_progress(stream, index, 2)
      for index, association in enumerate(udp):
        udp_progress(association, udp_port, index, 1)
    usage = process_usage(daemon.process.pid)
    result = {
      "case": kind, "tcp_active": len(tcp), "udp_active": len(udp),
      "tcp_rejection": tcp_rejection, "udp_rejection": udp_rejection,
      "valid_reloads": reloads,
      "elapsed_seconds": round(time.monotonic() - started, 3), **usage,
    }
  finally:
    cleanup = cleanup_case(daemon, tcp, udp)
  result["cleanup"] = cleanup
  return result


def low_fd_case(binary, directory, tcp_port):
  daemon = RunningFtun(binary, directory, FORMAL_FLOWS, fd_limit=256)
  tcp = []
  rejection = None
  result = None
  try:
    for index in range(FORMAL_FLOWS):
      stream = None
      try:
        stream = tcp_connect(daemon.proxy_port, tcp_port)
        tcp_progress(stream, index, 0)
        tcp.append(stream)
      except (ConnectionError, OSError, TimeoutError) as error:
        if stream is not None:
          close_tcp(stream)
        rejection = type(error).__name__
        break
    if rejection is None or not tcp:
      raise RuntimeError("low-FD admission did not reach a bounded rejection")
    for index in {0, len(tcp) // 2, len(tcp) - 1}:
      tcp_progress(tcp[index], index, 1)
    result = {"case": "low-fd", "limit": 256, "accepted": len(tcp),
              "attempted": len(tcp) + 1, "rejection": rejection,
              **process_usage(daemon.process.pid)}
  finally:
    cleanup = cleanup_case(daemon, tcp, [])
  result["cleanup"] = cleanup
  return result


def reload_case(binary, directory, tcp_port, udp_port):
  daemon = RunningFtun(binary, directory, 16)
  tcp = []
  udp = []
  result = None
  try:
    stream = tcp_connect(daemon.proxy_port, tcp_port)
    tcp_progress(stream, 0, 0)
    tcp.append(stream)
    association = udp_associate(daemon.proxy_port)
    udp_progress(association, udp_port, 0, 0)
    udp.append(association)
    for generation in range(2):
      marker = "ftun: reload committed"
      previous = daemon.log_path.read_text(errors="replace").count(marker)
      write_config(daemon.config, daemon.proxy_port, 16,
                   log_level="error" if generation == 0 else "silent")
      daemon.process.send_signal(signal.SIGHUP)
      wait_log(daemon.process, daemon.log_path, marker, previous)
      tcp_progress(tcp[0], 0, generation + 1)
      udp_progress(udp[0], udp_port, 0, generation + 1)
      if generation == 0:
        association = udp_associate(daemon.proxy_port)
        udp_progress(association, udp_port, 1, 0)
        udp.append(association)
      for index, current in enumerate(udp):
        udp_progress(current, udp_port, index, generation + 10)
    result = {"case": "reload-established-flows", "valid_reloads": 2,
              "tcp_active": len(tcp), "udp_active": len(udp),
              **process_usage(daemon.process.pid)}
  finally:
    cleanup = cleanup_case(daemon, tcp, udp)
  result["cleanup"] = cleanup
  return result


def explore_case(binary, directory, tcp_port, udp_port, kind):
  daemon = RunningFtun(binary, directory, EXPLORE_FLOWS)
  tcp = []
  udp = []
  rejection = "target-reached"
  failed_kind = None
  attempted_tcp = 0
  attempted_udp = 0
  overflow_rejections = {}
  result = None
  started = time.monotonic()
  try:
    for index in range(EXPLORE_FLOWS):
      if kind in {"tcp", "mixed"}:
        attempted_tcp += 1
        stream = None
        try:
          stream = tcp_connect(daemon.proxy_port, tcp_port)
          tcp_progress(stream, index, 0)
          tcp.append(stream)
        except (ConnectionError, OSError, TimeoutError) as error:
          if stream is not None:
            close_tcp(stream)
          rejection = type(error).__name__
          failed_kind = "tcp"
          break
      if kind in {"udp", "mixed"}:
        attempted_udp += 1
        association = None
        try:
          association = udp_associate(daemon.proxy_port)
          udp_progress(association, udp_port, index, 0)
          udp.append(association)
        except (ConnectionError, OSError, TimeoutError) as error:
          if association is not None:
            close_udp(association)
          rejection = type(error).__name__
          failed_kind = "udp"
          break
    if len(tcp) == EXPLORE_FLOWS:
      attempted_tcp += 1
      overflow_rejections["tcp"] = require_rejection(
        lambda: tcp_connect(daemon.proxy_port, tcp_port))
    if len(udp) == EXPLORE_FLOWS:
      attempted_udp += 1
      overflow_rejections["udp"] = require_rejection(
        lambda: udp_associate(daemon.proxy_port))
    for index in {0, len(tcp) // 2, len(tcp) - 1} if tcp else ():
      tcp_progress(tcp[index], index, 1)
    for index in {0, len(udp) // 2, len(udp) - 1} if udp else ():
      udp_progress(udp[index], udp_port, index, 1)
    elapsed = time.monotonic() - started
    usage = process_usage(daemon.process.pid)
    target_reached = ((kind == "tcp" and len(tcp) == EXPLORE_FLOWS) or
                      (kind == "udp" and len(udp) == EXPLORE_FLOWS) or
                      (kind == "mixed" and len(tcp) == EXPLORE_FLOWS and
                       len(udp) == EXPLORE_FLOWS))
    result = {
      "case": kind, "requested_tcp": EXPLORE_FLOWS if kind != "udp" else 0,
      "requested_udp": EXPLORE_FLOWS if kind != "tcp" else 0,
      "accepted_tcp": len(tcp), "accepted_udp": len(udp),
      "served_tcp": len(tcp), "served_udp": len(udp),
      "attempted_tcp": attempted_tcp, "attempted_udp": attempted_udp,
      "first_failed_kind": failed_kind, "first_failure": rejection,
      "first_bottleneck": ("configured-capacity"
                           if target_reached else "runtime-admission"),
      "overflow_rejections": overflow_rejections,
      "elapsed_seconds": round(elapsed, 3),
      "cpu_percent_of_one_core": round(
        usage["cpu_seconds"] * 100.0 / elapsed, 3), **usage,
    }
  finally:
    cleanup = cleanup_case(daemon, tcp, udp)
  result["cleanup"] = cleanup
  return result


def atomic_report(path, value):
  temporary = path.with_suffix(path.suffix + ".next")
  temporary.write_text(json.dumps(value, sort_keys=True) + "\n",
                       encoding="utf-8")
  temporary.replace(path)


def replace_tcp(daemon, tcp_port, streams, index, sequence):
  close_tcp(streams[index])
  deadline = time.monotonic() + 10
  while True:
    stream = None
    try:
      stream = tcp_connect(daemon.proxy_port, tcp_port)
      tcp_progress(stream, index, sequence)
      streams[index] = stream
      return
    except (ConnectionError, OSError, TimeoutError):
      if stream is not None:
        close_tcp(stream)
      if time.monotonic() >= deadline:
        raise
      time.sleep(0.02)


def replace_udp(daemon, udp_port, associations, index, sequence):
  close_udp(associations[index])
  deadline = time.monotonic() + 10
  while True:
    association = None
    try:
      association = udp_associate(daemon.proxy_port)
      udp_progress(association, udp_port, index, sequence)
      associations[index] = association
      return
    except (ConnectionError, OSError, TimeoutError):
      if association is not None:
        close_udp(association)
      if time.monotonic() >= deadline:
        raise
      time.sleep(0.02)


def run_soak(binary, directory, tcp_port, udp_port, report_path):
  seconds = int(os.environ.get("FTUN_SOAK_SECONDS", "86400"))
  cycle_seconds = float(os.environ.get("FTUN_SOAK_CYCLE_SECONDS", "5"))
  batch = int(os.environ.get("FTUN_SOAK_BATCH", "64"))
  allow_short = os.environ.get("FTUN_SOAK_ALLOW_SHORT") == "1"
  if (seconds < 86400 and not allow_short) or seconds > 259200 or \
      cycle_seconds < 0.1 or cycle_seconds > 300 or batch < 1 or \
      batch > FORMAL_FLOWS:
    raise ValueError("invalid soak duration/cycle/batch")
  daemon = RunningFtun(binary, directory, FORMAL_FLOWS)
  tcp = []
  udp = []
  tcp_progresses = [0] * FORMAL_FLOWS
  udp_progresses = [0] * FORMAL_FLOWS
  last_progress = [time.monotonic()] * (FORMAL_FLOWS * 2)
  cycles = 0
  valid_reloads = 0
  rejected_reloads = 0
  rotations = 0
  faults = 0
  last_rotation_index = None
  candidate = {
    "binary": str(binary), "binary_size": binary.stat().st_size,
    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "cycle_seconds": cycle_seconds, "batch": batch,
    "reload_every_cycles": 12, "rejected_reload_every_cycles": 24,
    "fault_every_cycles": 12,
  }
  atomic_report(report_path, {
    "status": "initializing", "phase": "setup",
    "requested_seconds": seconds, "tcp_resident": 0, "udp_resident": 0,
    **candidate})
  try:
    for index in range(FORMAL_FLOWS):
      stream = None
      try:
        stream = tcp_connect(daemon.proxy_port, tcp_port)
        tcp_progress(stream, index, 0)
      except Exception as error:
        if stream is not None:
          close_tcp(stream)
        raise RuntimeError(
          f"setup TCP flow {index} failed: {error}") from error
      tcp.append(stream)
      tcp_progresses[index] += 1
      last_progress[index] = time.monotonic()
    for index in range(FORMAL_FLOWS):
      association = None
      try:
        association = udp_associate(daemon.proxy_port)
        udp_progress(association, udp_port, index, 0)
      except Exception as error:
        if association is not None:
          close_udp(association)
        raise RuntimeError(
          f"setup UDP flow {index} failed: {error}") from error
      udp.append(association)
      udp_progresses[index] += 1
      last_progress[FORMAL_FLOWS + index] = time.monotonic()
    require_rejection(lambda: tcp_connect(daemon.proxy_port, tcp_port))
    require_rejection(lambda: udp_associate(daemon.proxy_port))

    # 满载建立并验证完成后才开始计时，保证报告的 86,400 秒全部处于正式容量窗口。
    started = time.monotonic()
    deadline = started + seconds
    active_started_unix_seconds = round(time.time(), 3)
    last_progress = [started] * (FORMAL_FLOWS * 2)
    usage = process_usage(daemon.process.pid)
    rss_active_start_kib = usage["rss_kib"]
    pss_active_start_kib = usage["pss_kib"]
    fds_active_start = usage["fds"]
    rss_peak_kib = usage["rss_kib"]
    pss_peak_kib = usage["pss_kib"]
    fds_peak = usage["fds"]
    atomic_report(report_path, {
      "status": "running", "phase": "active",
      "requested_seconds": seconds, "elapsed_seconds": 0.0,
      "active_started_unix_seconds": active_started_unix_seconds,
      "pid": daemon.process.pid, "cycles": 0,
      "tcp_resident": len(tcp), "udp_resident": len(udp),
      "tcp_progress_min": min(tcp_progresses),
      "udp_progress_min": min(udp_progresses),
      "max_progress_stall_seconds": 0.0,
      "rss_active_start_kib": rss_active_start_kib,
      "pss_active_start_kib": pss_active_start_kib,
      "fds_active_start": fds_active_start,
      "rss_peak_kib": rss_peak_kib, "pss_peak_kib": pss_peak_kib,
      "fds_peak": fds_peak,
      "valid_reloads": 0, "rejected_reloads": 0, "rotations": 0,
      "rotation_index": last_rotation_index, "faults": 0,
      "unexpected_exits": 0, "restarts": 0,
      **candidate, **usage,
    })

    while time.monotonic() < deadline:
      cycle_started = time.monotonic()
      start = (cycles * batch) % FORMAL_FLOWS
      indices = [(start + offset) % FORMAL_FLOWS for offset in range(batch)]
      for index in indices:
        try:
          tcp_progress(tcp[index], index, tcp_progresses[index])
        except Exception as error:
          raise RuntimeError(
            f"cycle {cycles} TCP flow {index} failed: {error}") from error
        tcp_progresses[index] += 1
        last_progress[index] = time.monotonic()
        try:
          udp_progress(udp[index], udp_port, index, udp_progresses[index])
        except Exception as error:
          raise RuntimeError(
            f"cycle {cycles} UDP flow {index} failed: {error}") from error
        udp_progresses[index] += 1
        last_progress[FORMAL_FLOWS + index] = time.monotonic()

      if cycles != 0 and cycles % 12 == 0:
        marker = "ftun: reload committed"
        previous = daemon.log_path.read_text(errors="replace").count(marker)
        write_config(daemon.config, daemon.proxy_port, FORMAL_FLOWS,
                     log_level="error" if valid_reloads % 2 == 0 else "silent")
        daemon.process.send_signal(signal.SIGHUP)
        wait_log(daemon.process, daemon.log_path, marker, previous)
        valid_reloads += 1
      if cycles != 0 and cycles % 24 == 0:
        marker = "reload rejected"
        previous = daemon.log_path.read_text(errors="replace").count(marker)
        write_config(daemon.config, daemon.proxy_port, FORMAL_FLOWS,
                     tcp_capacity=FORMAL_FLOWS - 1)
        daemon.process.send_signal(signal.SIGHUP)
        wait_log(daemon.process, daemon.log_path, marker, previous)
        write_config(daemon.config, daemon.proxy_port, FORMAL_FLOWS)
        rejected_reloads += 1
      if cycles != 0 and cycles % 12 == 6:
        # 固定轮换同一槽：下一轮 reload 前先释放上一代新建流，避免测试本身
        # 人为钉住每个历史代并触发有界 retained Runtime 的预期拒绝。
        index = 0
        try:
          replace_tcp(daemon, tcp_port, tcp, index, tcp_progresses[index])
        except Exception as error:
          raise RuntimeError(
            f"cycle {cycles} TCP rotation {index} failed: {error}") from error
        tcp_progresses[index] += 1
        last_progress[index] = time.monotonic()
        try:
          replace_udp(daemon, udp_port, udp, index, udp_progresses[index])
        except Exception as error:
          raise RuntimeError(
            f"cycle {cycles} UDP rotation {index} failed: {error}") from error
        udp_progresses[index] += 1
        last_progress[FORMAL_FLOWS + index] = time.monotonic()
        rotations += 1
        last_rotation_index = index
      if cycles != 0 and cycles % 12 == 3:
        unused = pick_port()
        try:
          failed = tcp_connect(daemon.proxy_port, unused)
        except (ConnectionError, OSError, TimeoutError):
          faults += 1
        else:
          close_tcp(failed)
          raise RuntimeError("unreachable target was unexpectedly accepted")

      cycles += 1
      now = time.monotonic()
      max_stall = max(now - value for value in last_progress)
      allowed_stall = math.ceil(FORMAL_FLOWS / batch) * cycle_seconds + 30
      if max_stall > allowed_stall:
        raise RuntimeError(
          f"flow progress window exceeded: {max_stall:.3f}s > {allowed_stall:.3f}s")
      usage = process_usage(daemon.process.pid)
      rss_peak_kib = max(rss_peak_kib, usage["rss_kib"])
      pss_peak_kib = max(pss_peak_kib, usage["pss_kib"])
      fds_peak = max(fds_peak, usage["fds"])
      checkpoint = {
        "status": "running", "phase": "active",
        "requested_seconds": seconds,
        "elapsed_seconds": round(now - started, 3), "pid": daemon.process.pid,
        "cycles": cycles, "tcp_resident": len(tcp), "udp_resident": len(udp),
        "tcp_progress_min": min(tcp_progresses),
        "udp_progress_min": min(udp_progresses),
        "max_progress_stall_seconds": round(max_stall, 3),
        "active_started_unix_seconds": active_started_unix_seconds,
        "rss_active_start_kib": rss_active_start_kib,
        "pss_active_start_kib": pss_active_start_kib,
        "fds_active_start": fds_active_start,
        "rss_peak_kib": rss_peak_kib, "pss_peak_kib": pss_peak_kib,
        "fds_peak": fds_peak,
        "valid_reloads": valid_reloads,
        "rejected_reloads": rejected_reloads, "rotations": rotations,
        "rotation_index": last_rotation_index, "faults": faults,
        "unexpected_exits": 0, "restarts": 0,
        **candidate,
        **usage,
      }
      atomic_report(report_path, checkpoint)
      if cycles == 1 or cycles % 12 == 0:
        print("core-soak-checkpoint " + json.dumps(checkpoint, sort_keys=True),
              flush=True)
      remaining = cycle_seconds - (time.monotonic() - cycle_started)
      if remaining > 0:
        time.sleep(min(remaining, max(0.0, deadline - time.monotonic())))

    # 到期后逐条验证全部常驻流，避免最后一个抽样窗口内的断流被遗漏。
    for index in range(FORMAL_FLOWS):
      tcp_progress(tcp[index], index, tcp_progresses[index])
      tcp_progresses[index] += 1
      last_progress[index] = time.monotonic()
      udp_progress(udp[index], udp_port, index, udp_progresses[index])
      udp_progresses[index] += 1
      last_progress[FORMAL_FLOWS + index] = time.monotonic()
    usage = process_usage(daemon.process.pid)
    rss_peak_kib = max(rss_peak_kib, usage["rss_kib"])
    pss_peak_kib = max(pss_peak_kib, usage["pss_kib"])
    fds_peak = max(fds_peak, usage["fds"])
    summary = json.loads(report_path.read_text(encoding="utf-8"))
    summary["status"] = "passed"
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    summary["tcp_progress_min"] = min(tcp_progresses)
    summary["udp_progress_min"] = min(udp_progresses)
    summary["final_sweep_tcp"] = len(tcp)
    summary["final_sweep_udp"] = len(udp)
    summary["rss_peak_kib"] = rss_peak_kib
    summary["pss_peak_kib"] = pss_peak_kib
    summary["fds_peak"] = fds_peak
    summary.update(usage)
    atomic_report(report_path, summary)
    print("core-soak-summary " + json.dumps(summary, sort_keys=True), flush=True)
    return summary
  finally:
    cleanup = {}
    try:
      for stream in tcp:
        close_tcp(stream)
      for association in udp:
        close_udp(association)
      if daemon.process.poll() is None:
        cleanup["fds_before_exit"] = wait_reclaim(daemon.process)
        cleanup.update(process_usage(daemon.process.pid))
    finally:
      report_path.with_suffix(".ftun.log").write_text(
        daemon.log_path.read_text(errors="replace"), encoding="utf-8")
      try:
        daemon.close()
      finally:
        cleanup["process_exit_code"] = daemon.process.returncode
        if report_path.is_file():
          saved = json.loads(report_path.read_text(encoding="utf-8"))
          saved["cleanup"] = cleanup
          atomic_report(report_path, saved)


def run(mode, binary, report_path=None):
  soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
  wanted = 65535 if hard == resource.RLIM_INFINITY else min(hard, 65535)
  if soft < wanted:
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
  if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 8192:
    print("core qualification skipped: RLIMIT_NOFILE below 8192")
    return 77
  with tempfile.TemporaryDirectory(prefix="ftun-core-qualification-") as root:
    directory = Path(root)
    echo, echo_log, tcp_port, udp_port, echo_result = start_echo(directory)
    try:
      if mode == "formal":
        result = {
          "formal": [formal_case(binary, directory, tcp_port, udp_port, kind)
                     for kind in ("tcp", "udp", "mixed")],
          "low_fd": low_fd_case(binary, directory, tcp_port),
        }
        print("core-qualification " + json.dumps(result, sort_keys=True))
      elif mode == "reload":
        result = reload_case(binary, directory, tcp_port, udp_port)
        print("core-reload " + json.dumps(result, sort_keys=True))
      elif mode == "explore":
        result = {"exploration": [
          explore_case(binary, directory, tcp_port, udp_port, kind)
          for kind in ("tcp", "udp", "mixed")]}
        print("core-exploration " + json.dumps(result, sort_keys=True))
      else:
        if report_path is None:
          raise ValueError("soak report path is required")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        result = run_soak(binary, directory, tcp_port, udp_port, report_path)
    finally:
      stop_process(echo)
      echo_log.close()
    if echo.returncode != 0:
      raise RuntimeError(f"echo backend exited with {echo.returncode}")
    if not echo_result.is_file():
      raise RuntimeError("echo backend did not write its result")
  return 0


def main():
  if len(sys.argv) not in (3, 4) or sys.argv[1] not in {
      "formal", "reload", "explore", "soak"}:
    return fail(
      "usage: core_qualification.py formal|reload|explore|soak FTUN [REPORT]")
  mode = sys.argv[1]
  binary = Path(sys.argv[2]).resolve()
  report = Path(sys.argv[3]).resolve() if len(sys.argv) == 4 else None
  if not binary.is_file():
    return fail("FTUN binary is missing")
  if mode == "soak" and report is None:
    return fail("soak mode requires a report path")
  try:
    return run(mode, binary, report)
  except Exception as error:
    if report is not None:
      report.parent.mkdir(parents=True, exist_ok=True)
      failure = {}
      if report.is_file():
        try:
          failure = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
          failure = {}
      failure.update({"status": "failed", "error": str(error)})
      atomic_report(report, failure)
    return fail(str(error))


if __name__ == "__main__":
  raise SystemExit(main())

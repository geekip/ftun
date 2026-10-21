#!/usr/bin/env python3
"""Repeatable 256-flow socket data-plane baseline for Core hardening."""

import json
import os
from pathlib import Path
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time


FLOW_COUNT = 256
CHURN_FLOW_COUNT = 32
TCP_SMALL_PAYLOAD_BYTES = 1024
TCP_LARGE_PAYLOAD_BYTES = 64 * 1024
UDP_SMALL_PAYLOAD_BYTES = 128
UDP_LARGE_PAYLOAD_BYTES = 1200
LARGE_EVERY = 16
SLOW_EVERY = 16
SLOW_DELAY_SECONDS = 0.005


def fail(message):
  print(f"core baseline failed: {message}", file=sys.stderr)
  return 1


def exact(stream, length):
  result = bytearray()
  while len(result) < length:
    chunk = stream.recv(length - len(result))
    if not chunk:
      raise ConnectionError("unexpected EOF")
    result.extend(chunk)
  return bytes(result)


def percentile(values, numerator, denominator):
  ordered = sorted(values)
  if not ordered:
    return 0
  return ordered[min(len(ordered) - 1,
                     (len(ordered) * numerator) // denominator)]


def pick_port(kind):
  with socket.socket(socket.AF_INET, kind) as probe:
    probe.bind(("127.0.0.1", 0))
    return probe.getsockname()[1]


class TcpEcho:
  def __init__(self):
    self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.listener.bind(("127.0.0.1", 0))
    self.listener.listen(512)
    self.listener.settimeout(0.1)
    self.port = self.listener.getsockname()[1]
    self.stopping = threading.Event()
    self.clients = []
    self.lock = threading.Lock()
    self.thread = threading.Thread(target=self.accept, daemon=True)
    self.thread.start()

  def accept(self):
    while not self.stopping.is_set():
      try:
        connection, _ = self.listener.accept()
      except TimeoutError:
        continue
      except OSError:
        break
      worker = threading.Thread(target=self.echo, args=(connection,),
                                daemon=True)
      with self.lock:
        self.clients.append(worker)
      worker.start()

  @staticmethod
  def echo(connection):
    with connection:
      while True:
        try:
          data = connection.recv(65536)
        except OSError:
          return
        if not data:
          return
        try:
          connection.sendall(data)
        except OSError:
          return

  def close(self):
    self.stopping.set()
    self.listener.close()
    self.thread.join(timeout=2)
    with self.lock:
      clients = list(self.clients)
    for worker in clients:
      worker.join(timeout=2)


class UdpEcho:
  def __init__(self):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    self.socket.bind(("127.0.0.1", 0))
    self.socket.settimeout(0.1)
    self.port = self.socket.getsockname()[1]
    self.stopping = threading.Event()
    self.thread = threading.Thread(target=self.echo, daemon=True)
    self.thread.start()

  def echo(self):
    while not self.stopping.is_set():
      try:
        data, peer = self.socket.recvfrom(65535)
        self.socket.sendto(data, peer)
      except TimeoutError:
        continue
      except OSError:
        break

  def close(self):
    self.stopping.set()
    self.socket.close()
    self.thread.join(timeout=2)


def socks_greeting(stream):
  stream.sendall(b"\x05\x01\x00")
  if exact(stream, 2) != b"\x05\x00":
    raise ConnectionError("SOCKS5 method rejected")


def socks_tcp(proxy_port, target_port):
  stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
  stream.settimeout(3)
  try:
    socks_greeting(stream)
    stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                   struct.pack("!H", target_port))
    reply = exact(stream, 10)
    if reply[:2] != b"\x05\x00" or reply[3] != 1:
      raise ConnectionError("SOCKS5 CONNECT rejected")
    return stream
  except Exception:
    stream.close()
    raise


def socks_udp(proxy_port, target_port):
  datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  datagram.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
  datagram.bind(("127.0.0.1", 0))
  datagram.settimeout(2)
  control = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
  control.settimeout(3)
  try:
    socks_greeting(control)
    local_port = datagram.getsockname()[1]
    control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") +
                    struct.pack("!H", local_port))
    reply = exact(control, 10)
    if reply[:2] != b"\x05\x00" or reply[3] != 1:
      raise ConnectionError("SOCKS5 UDP ASSOCIATE rejected")
    relay_host = socket.inet_ntoa(reply[4:8])
    if relay_host == "0.0.0.0":
      relay_host = "127.0.0.1"
    relay = (relay_host, struct.unpack("!H", reply[8:10])[0])
    target = socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port)
    return control, datagram, relay, b"\x00\x00\x00\x01" + target
  except Exception:
    control.close()
    datagram.close()
    raise


def socket_queue_sample(fd_paths):
  socket_inodes = set()
  for fd_path in fd_paths:
    try:
      target = os.readlink(fd_path)
    except OSError:
      continue
    if target.startswith("socket:[") and target.endswith("]"):
      socket_inodes.add(target[8:-1])
  receive_bytes = 0
  transmit_bytes = 0
  for name in ("tcp", "tcp6", "udp", "udp6"):
    path = Path(f"/proc/net/{name}")
    if not path.exists():
      continue
    for line in path.read_text().splitlines()[1:]:
      fields = line.split()
      if len(fields) < 10 or fields[9] not in socket_inodes:
        continue
      try:
        transmit, receive = fields[4].split(":", 1)
        transmit_bytes += int(transmit, 16)
        receive_bytes += int(receive, 16)
      except ValueError:
        continue
  return len(socket_inodes), receive_bytes, transmit_bytes


def midpoint_resource_sample(pid):
  sample_started = time.perf_counter_ns()
  values = {}
  for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[0] in {
        "Rss:", "Pss:", "Anonymous:", "Shared_Clean:", "Private_Clean:",
        "Private_Dirty:"}:
      values[fields[0][:-1].lower() + "_kib"] = int(fields[1])
  for line in Path(f"/proc/{pid}/status").read_text().splitlines():
    if line.startswith("Threads:"):
      values["threads"] = int(line.split()[1])
    elif line.startswith(("VmData:", "VmStk:", "VmExe:", "VmLib:")):
      fields = line.split()
      values[fields[0][:-1].lower() + "_kib"] = int(fields[1])
  values["fds"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
  values["observer_sample_us"] = round(
    (time.perf_counter_ns() - sample_started) / 1000.0, 3)
  return values


def process_sample(pid):
  sample_started = time.perf_counter_ns()
  memory = {}
  for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[0] in {
        "Rss:", "Pss:", "Anonymous:", "Shared_Clean:", "Private_Clean:",
        "Private_Dirty:"}:
      memory[fields[0][:-1].lower()] = int(fields[1])
  stat = Path(f"/proc/{pid}/stat").read_text().split()
  switches = {}
  status_values = {}
  for line in Path(f"/proc/{pid}/status").read_text().splitlines():
    if line.startswith("voluntary_ctxt_switches:"):
      switches["voluntary"] = int(line.split()[1])
    elif line.startswith("nonvoluntary_ctxt_switches:"):
      switches["nonvoluntary"] = int(line.split()[1])
    elif line.startswith("Threads:"):
      status_values["threads"] = int(line.split()[1])
    elif line.startswith(("VmData:", "VmStk:", "VmExe:", "VmLib:")):
      fields = line.split()
      status_values[fields[0][2:-1].lower() + "_kib"] = int(fields[1])
  fd_paths = list(Path(f"/proc/{pid}/fd").iterdir())
  socket_fds, socket_receive, socket_transmit = socket_queue_sample(fd_paths)
  return {
    "rss_kib": memory["rss"],
    "pss_kib": memory["pss"],
    "anonymous_kib": memory.get("anonymous", 0),
    "shared_clean_kib": memory.get("shared_clean", 0),
    "private_clean_kib": memory.get("private_clean", 0),
    "private_dirty_kib": memory.get("private_dirty", 0),
    "vmdata_kib": status_values.get("data_kib", 0),
    "vmstk_kib": status_values.get("stk_kib", 0),
    "vmexe_kib": status_values.get("exe_kib", 0),
    "vmlib_kib": status_values.get("lib_kib", 0),
    "threads": status_values.get("threads", 0),
    "fds": len(fd_paths),
    "socket_fds": socket_fds,
    "socket_receive_queue_bytes": socket_receive,
    "socket_transmit_queue_bytes": socket_transmit,
    "ticks": int(stat[13]) + int(stat[14]),
    "voluntary_switches": switches["voluntary"],
    "nonvoluntary_switches": switches["nonvoluntary"],
    "observer_sample_us": round((time.perf_counter_ns() - sample_started) /
                                1000.0, 3),
  }


def wait_ready(process, port, stderr_path):
  for _ in range(300):
    if process.poll() is not None:
      break
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.05)
    try:
      probe.connect(("127.0.0.1", port))
      probe.close()
      return
    except OSError:
      probe.close()
      time.sleep(0.01)
  detail = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
  raise RuntimeError(f"FTUN listener did not become ready: {detail[:1000]}")


def rejected_tcp(proxy_port, target_port):
  try:
    extra = socks_tcp(proxy_port, target_port)
  except (OSError, ConnectionError, TimeoutError) as error:
    return type(error).__name__
  extra.close()
  return None


def rejected_udp(proxy_port, target_port):
  try:
    control, datagram, _, _ = socks_udp(proxy_port, target_port)
  except (OSError, ConnectionError, TimeoutError) as error:
    return type(error).__name__
  control.close()
  datagram.close()
  return None


def active_result(kind, process, resources, active_seconds, worker):
  started = threading.Event()
  deadline = [0.0]
  progresses = [0] * len(resources)
  delivered = [0] * len(resources)
  losses = [0] * len(resources)
  latencies = [[] for _ in resources]
  failures = []

  def run_one(index, resource):
    try:
      started.wait()
      worker(index, resource, deadline[0], progresses, delivered, losses,
             latencies)
    except Exception as error:
      failures.append(f"flow {index}: {error}")

  threads = [threading.Thread(target=run_one, args=(index, resource),
                              daemon=True)
             for index, resource in enumerate(resources)]

  for thread in threads:
    thread.start()
  before = process_sample(process.pid)
  sampler = subprocess.Popen(
    [sys.executable, str(Path(__file__).resolve()), "--midpoint",
     str(process.pid), str(active_seconds / 2.0)],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  wall_start = time.monotonic()
  deadline[0] = wall_start + active_seconds
  started.set()
  for thread in threads:
    thread.join(timeout=active_seconds + 4.0)
  wall = time.monotonic() - wall_start
  after = process_sample(process.pid)
  sampler_stderr = ""
  try:
    sampler_stdout, sampler_stderr = sampler.communicate(
      timeout=active_seconds + 1.0)
    midpoint = json.loads(sampler_stdout)
  except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
    sampler.kill()
    sampler.communicate()
    failures.append(f"midpoint resource sample failed: {error}")
    midpoint = {}
  if sampler.returncode != 0:
    failures.append("midpoint resource sample exited with " +
                    f"{sampler.returncode}: {sampler_stderr[:200]}")
  if not midpoint:
    failures.append("midpoint resource sample returned no data")
  if any(thread.is_alive() for thread in threads):
    failures.append("worker did not finish within the bounded window")
  stalled = sum(1 for count in progresses if count == 0)
  if failures or stalled:
    raise RuntimeError(f"{kind} failures={failures[:3]} stalled={stalled}")
  all_latencies = [value for flow in latencies for value in flow]
  total_bytes = sum(delivered)
  cpu_seconds = (after["ticks"] - before["ticks"]) / os.sysconf("SC_CLK_TCK")
  gib = total_bytes / float(1 << 30)
  samples = (before, midpoint, after)
  memory_high_water_keys = (
    "rss_kib", "pss_kib", "anonymous_kib", "shared_clean_kib",
    "private_clean_kib", "private_dirty_kib", "vmdata_kib", "vmstk_kib",
    "vmexe_kib", "vmlib_kib", "threads", "fds")
  boundary_socket_keys = (
    "socket_fds",
    "socket_receive_queue_bytes", "socket_transmit_queue_bytes")
  return {
    "kind": kind,
    "flows": len(resources),
    "active_seconds": round(wall, 6),
    "slow_flows": sum(1 for index in range(len(resources))
                      if index % SLOW_EVERY == 0),
    "progress_min": min(progresses),
    "progress_max": max(progresses),
    "successful_round_trips": sum(progresses),
    "losses": sum(losses),
    "delivered_bytes": total_bytes,
    "throughput_mib_s": round(total_bytes / wall / (1024 * 1024), 3),
    "latency_p50_ms": round(percentile(all_latencies, 50, 100) / 1e6, 3),
    "latency_p95_ms": round(percentile(all_latencies, 95, 100) / 1e6, 3),
    "latency_p99_ms": round(percentile(all_latencies, 99, 100) / 1e6, 3),
    "cpu_percent": round(100.0 * cpu_seconds / wall, 3),
    "cpu_seconds_per_gib": round(cpu_seconds / gib, 6) if gib else 0.0,
    "deadline_overrun_ms": round(max(0.0, wall - active_seconds) * 1000.0,
                                  3),
    "observer_midpoint_sample_us": midpoint["observer_sample_us"],
    "observer_boundary_sample_us": round(before["observer_sample_us"] +
                                          after["observer_sample_us"], 3),
    "observer_sample_us": round(sum(sample["observer_sample_us"]
                                    for sample in samples), 3),
    "voluntary_switches": after["voluntary_switches"] -
                            before["voluntary_switches"],
    "nonvoluntary_switches": after["nonvoluntary_switches"] -
                               before["nonvoluntary_switches"],
    **{key: max(sample[key] for sample in samples)
       for key in memory_high_water_keys},
    **{"boundary_" + key: max(before[key], after[key])
       for key in boundary_socket_keys},
  }


def tcp_worker(index, stream, deadline, progresses, delivered, losses,
               latencies):
  payload_bytes = TCP_LARGE_PAYLOAD_BYTES if index % LARGE_EVERY == 0 \
    else TCP_SMALL_PAYLOAD_BYTES
  payload = struct.pack("!II", index, 0) + bytes([index & 0xff]) * (
    payload_bytes - 8)
  while time.monotonic() < deadline:
    started = time.perf_counter_ns()
    stream.sendall(payload)
    if index % SLOW_EVERY == 0:
      time.sleep(SLOW_DELAY_SECONDS)
    response = exact(stream, len(payload))
    if response != payload:
      raise RuntimeError("TCP echo mismatch")
    latencies[index].append(time.perf_counter_ns() - started)
    progresses[index] += 1
    delivered[index] += len(payload) * 2


def udp_worker(index, resource, deadline, progresses, delivered, losses,
               latencies):
  _, datagram, relay, header = resource
  # A single dropped packet must not consume the entire measurement window.
  # Short retries also exercise progress under a lossy UDP burst.
  datagram.settimeout(0.1)
  sequence = 0
  while time.monotonic() < deadline:
    payload_bytes = UDP_LARGE_PAYLOAD_BYTES if index % LARGE_EVERY == 0 \
      else UDP_SMALL_PAYLOAD_BYTES
    payload = struct.pack("!II", index, sequence) + bytes([index & 0xff]) * (
      payload_bytes - 8)
    started = time.perf_counter_ns()
    datagram.sendto(header + payload, relay)
    if index % SLOW_EVERY == 0:
      time.sleep(SLOW_DELAY_SECONDS)
    try:
      response, _ = datagram.recvfrom(65535)
    except TimeoutError:
      losses[index] += 1
      sequence += 1
      continue
    if len(response) < 10 or response[:4] != b"\x00\x00\x00\x01" or \
        response[10:] != payload:
      raise RuntimeError("UDP relay frame mismatch")
    latencies[index].append(time.perf_counter_ns() - started)
    progresses[index] += 1
    delivered[index] += len(payload) * 2
    sequence += 1


def churn_worker(index, resource, deadline, progresses, delivered, losses,
                 latencies):
  proxy_port, target_port = resource
  sequence = 0
  while time.monotonic() < deadline:
    stream = socks_tcp(proxy_port, target_port)
    try:
      payload_bytes = TCP_LARGE_PAYLOAD_BYTES if index % LARGE_EVERY == 0 \
        else TCP_SMALL_PAYLOAD_BYTES
      payload = struct.pack("!II", index, sequence) + \
        bytes([(index + sequence) & 0xff]) * (payload_bytes - 8)
      started = time.perf_counter_ns()
      stream.sendall(payload)
      response = exact(stream, len(payload))
      if response != payload:
        raise RuntimeError("churn echo mismatch")
      latencies[index].append(time.perf_counter_ns() - started)
      progresses[index] += 1
      delivered[index] += len(payload) * 2
      sequence += 1
    finally:
      stream.close()


def churn_reload_result(process, resources, active_seconds, stderr_path):
  marker = "ftun: reload committed"
  marker_count = stderr_path.read_text(errors="replace").count(marker)
  failures = []

  def reload_once():
    time.sleep(min(0.25, active_seconds / 4.0))
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
      if stderr_path.read_text(errors="replace").count(marker) > marker_count:
        return
      if process.poll() is not None:
        break
      time.sleep(0.01)
    failures.append("reload did not commit within 3 seconds")

  reloader = threading.Thread(target=reload_once, daemon=True)
  reloader.start()
  result = active_result("churn_reload", process, resources, active_seconds,
                         churn_worker)
  reloader.join(timeout=4.0)
  if reloader.is_alive():
    failures.append("reload observer did not terminate")
  if failures:
    raise RuntimeError("; ".join(failures))
  result["reload_committed"] = 1
  return result


def run_once(binary, active_seconds, run):
  tcp_echo = TcpEcho()
  udp_echo = UdpEcho()
  proxy_port = pick_port(socket.SOCK_STREAM)
  with tempfile.TemporaryDirectory(prefix="ftun-core-baseline-") as directory:
    temporary = Path(directory)
    config = temporary / "config.json"
    stderr_path = temporary / "ftun.stderr"
    config.write_text(json.dumps({
      "dns": {"enable": False},
      "log": {"level": "silent"},
      "inbounds": [{"name": "baseline", "type": "socks5",
                    "listen": f"127.0.0.1:{proxy_port}", "udp": True}],
      "rules": ["MATCH,DIRECT"],
    }), encoding="utf-8")
    with stderr_path.open("w+") as stderr_file:
      process = subprocess.Popen([str(binary), "run", "-c", str(config)],
                                 stdout=subprocess.DEVNULL,
                                 stderr=stderr_file)
      try:
        wait_ready(process, proxy_port, stderr_path)
        idle_before = process_sample(process.pid)
        idle_started = time.monotonic()
        time.sleep(0.5)
        idle_after = process_sample(process.pid)
        idle_wall = time.monotonic() - idle_started
        idle_cpu = (idle_after["ticks"] - idle_before["ticks"]) / \
          os.sysconf("SC_CLK_TCK")
        idle = {
          "rss_kib": idle_after["rss_kib"],
          "pss_kib": idle_after["pss_kib"],
          "anonymous_kib": idle_after["anonymous_kib"],
          "shared_clean_kib": idle_after["shared_clean_kib"],
          "private_clean_kib": idle_after["private_clean_kib"],
          "private_dirty_kib": idle_after["private_dirty_kib"],
          "vmdata_kib": idle_after["vmdata_kib"],
          "vmstk_kib": idle_after["vmstk_kib"],
          "vmexe_kib": idle_after["vmexe_kib"],
          "vmlib_kib": idle_after["vmlib_kib"],
          "threads": idle_after["threads"],
          "fds": idle_after["fds"],
          "socket_fds": idle_after["socket_fds"],
          "socket_receive_queue_bytes":
            idle_after["socket_receive_queue_bytes"],
          "socket_transmit_queue_bytes":
            idle_after["socket_transmit_queue_bytes"],
          "cpu_percent": round(100.0 * idle_cpu / idle_wall, 3),
          "observer_sample_us": round(idle_before["observer_sample_us"] +
                                      idle_after["observer_sample_us"], 3),
          "voluntary_switches": idle_after["voluntary_switches"] -
                                  idle_before["voluntary_switches"],
          "nonvoluntary_switches": idle_after["nonvoluntary_switches"] -
                                     idle_before["nonvoluntary_switches"],
        }

        admission_started = time.monotonic()
        tcp = [socks_tcp(proxy_port, tcp_echo.port)
               for _ in range(FLOW_COUNT)]
        tcp_admission_seconds = time.monotonic() - admission_started
        rejection_started = time.monotonic()
        tcp_rejection_reason = rejected_tcp(proxy_port, tcp_echo.port)
        tcp_rejection_ms = (time.monotonic() - rejection_started) * 1000.0
        if tcp_rejection_reason is None:
          raise RuntimeError("257th TCP flow was not rejected")
        tcp_result = active_result("tcp", process, tcp, active_seconds,
                                   tcp_worker)
        tcp_result["accepted"] = len(tcp)
        tcp_result["admission_seconds"] = round(tcp_admission_seconds, 6)
        tcp_result["admission_rate_s"] = round(len(tcp) /
                                                tcp_admission_seconds, 3)
        tcp_result["rejected"] = 1
        tcp_result["rejection_reason"] = tcp_rejection_reason
        tcp_result["rejection_latency_ms"] = round(tcp_rejection_ms, 3)
        for stream in tcp:
          stream.close()
        time.sleep(0.2)

        admission_started = time.monotonic()
        udp = [socks_udp(proxy_port, udp_echo.port)
               for _ in range(FLOW_COUNT)]
        udp_admission_seconds = time.monotonic() - admission_started
        rejection_started = time.monotonic()
        udp_rejection_reason = rejected_udp(proxy_port, udp_echo.port)
        udp_rejection_ms = (time.monotonic() - rejection_started) * 1000.0
        if udp_rejection_reason is None:
          raise RuntimeError("257th UDP association was not rejected")
        udp_result = active_result("udp", process, udp, active_seconds,
                                   udp_worker)
        udp_result["accepted_associations"] = len(udp)
        udp_result["admission_seconds"] = round(udp_admission_seconds, 6)
        udp_result["admission_rate_s"] = round(len(udp) /
                                                udp_admission_seconds, 3)
        udp_result["rejected_associations"] = 1
        udp_result["rejection_reason"] = udp_rejection_reason
        udp_result["rejection_latency_ms"] = round(udp_rejection_ms, 3)
        for control, datagram, _, _ in udp:
          control.close()
          datagram.close()
        time.sleep(0.2)

        churn_resources = [(proxy_port, tcp_echo.port)] * CHURN_FLOW_COUNT
        churn_result = churn_reload_result(process, churn_resources,
                                            active_seconds, stderr_path)
        time.sleep(0.2)
        cleaned = process_sample(process.pid)
      finally:
        if process.poll() is None:
          process.send_signal(signal.SIGTERM)
        try:
          process.wait(timeout=10)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait()
      if process.returncode != 0:
        stderr_file.flush()
        raise RuntimeError(f"FTUN exit={process.returncode}: " +
                           stderr_path.read_text(errors="replace")[:1000])
  tcp_echo.close()
  udp_echo.close()
  return {"run": run, "idle": idle, "tcp": tcp_result,
          "udp": udp_result, "churn_reload": churn_result,
          "cleaned": cleaned}


def summarize(results, active_seconds, total_timeout_seconds):
  summary = {
    "runs": len(results),
    "flow_boundary": FLOW_COUNT,
    "measurement_contract": {
      "requested_active_seconds": active_seconds,
      "total_timeout_seconds": total_timeout_seconds,
      "tcp_small_payload_bytes": TCP_SMALL_PAYLOAD_BYTES,
      "tcp_large_payload_bytes": TCP_LARGE_PAYLOAD_BYTES,
      "udp_small_payload_bytes": UDP_SMALL_PAYLOAD_BYTES,
      "udp_large_payload_bytes": UDP_LARGE_PAYLOAD_BYTES,
      "large_every": LARGE_EVERY,
      "slow_every": SLOW_EVERY,
      "slow_read_delay_ms": SLOW_DELAY_SECONDS * 1000.0,
      "udp_retry_timeout_ms": 100.0,
      "churn_flows": CHURN_FLOW_COUNT,
      "active_process_samples": 3,
    },
  }
  for kind in ("idle", "tcp", "udp", "churn_reload", "cleaned"):
    keys = ("rss_kib", "pss_kib", "fds", "socket_fds", "threads") \
      if kind in {"idle", "cleaned"} else (
        "throughput_mib_s", "latency_p50_ms", "latency_p95_ms",
        "latency_p99_ms", "cpu_percent", "cpu_seconds_per_gib", "rss_kib",
        "pss_kib", "fds", "progress_min",
        "deadline_overrun_ms", "observer_midpoint_sample_us",
        "observer_boundary_sample_us", "observer_sample_us")
    summary[kind] = {}
    for key in keys:
      values = [result[kind][key] for result in results]
      median = statistics.median(values)
      summary[kind][key] = {
        "min": min(values), "median": median,
        "max": max(values),
        "relative_range_percent": round(
          100.0 * (max(values) - min(values)) / median, 3) if median else 0.0,
      }
  return summary


def main():
  if len(sys.argv) == 4 and sys.argv[1] == "--midpoint":
    time.sleep(float(sys.argv[3]))
    print(json.dumps(midpoint_resource_sample(int(sys.argv[2])),
                     sort_keys=True))
    return 0
  if len(sys.argv) != 2:
    return fail("FTUN binary is required")
  binary = Path(sys.argv[1]).resolve()
  if not binary.is_file():
    return fail("FTUN binary is missing")
  try:
    runs = int(os.environ.get("FTUN_BASELINE_RUNS", "1"))
    active_seconds = float(os.environ.get("FTUN_BASELINE_ACTIVE_SECONDS", "1"))
    total_timeout_seconds = int(os.environ.get(
      "FTUN_BASELINE_TOTAL_TIMEOUT_SECONDS", "120"))
  except ValueError:
    return fail("baseline runs, active seconds and timeout must be numeric")
  if runs < 1 or runs > 20 or active_seconds < 0.5 or active_seconds > 30 or \
      total_timeout_seconds < 30 or total_timeout_seconds > 3600:
    return fail("baseline bounds are runs=1..20, active seconds=0.5..30, "
                "timeout=30..3600")

  def timed_out(_signal_number, _frame):
    raise TimeoutError("total baseline deadline expired")

  signal.signal(signal.SIGALRM, timed_out)
  signal.alarm(total_timeout_seconds)
  results = []
  try:
    for run in range(1, runs + 1):
      result = run_once(binary, active_seconds, run)
      results.append(result)
      print("core-baseline-run " + json.dumps(result, sort_keys=True),
            flush=True)
  except Exception as error:
    return fail(str(error))
  finally:
    signal.alarm(0)
  print("core-baseline-summary " + json.dumps(summarize(
                                                results, active_seconds,
                                                total_timeout_seconds),
                                                sort_keys=True))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

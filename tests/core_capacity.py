#!/usr/bin/env python3
"""C10-013：1000 级真实 TCP/UDP 混合容量与启动期配置契约。"""

import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


TCP_CAPACITY = 1000
UDP_FLOW_CAPACITY = 1000
ASSOCIATION_CAPACITY = 1001


def exact(stream, length):
  data = bytearray()
  while len(data) < length:
    chunk = stream.recv(length - len(data))
    if not chunk:
      raise ConnectionError("unexpected EOF")
    data.extend(chunk)
  return bytes(data)


def pick_port():
  with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    return probe.getsockname()[1]


class TcpEcho:
  def __init__(self):
    self.selector = selectors.DefaultSelector()
    self.listener = socket.socket()
    self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.listener.setblocking(False)
    self.listener.bind(("127.0.0.1", 0))
    self.listener.listen(4096)
    self.port = self.listener.getsockname()[1]
    self.selector.register(self.listener, selectors.EVENT_READ, None)
    self.stopping = threading.Event()
    self.thread = threading.Thread(target=self.run, daemon=True)
    self.thread.start()

  def run(self):
    while not self.stopping.is_set():
      try:
        events = self.selector.select(0.05)
      except OSError:
        break
      for key, mask in events:
        if key.data is None:
          try:
            while True:
              connection, _ = self.listener.accept()
              connection.setblocking(False)
              self.selector.register(connection, selectors.EVENT_READ,
                                     bytearray())
          except BlockingIOError:
            pass
          except OSError:
            pass
          continue
        connection = key.fileobj
        pending = key.data
        try:
          if mask & selectors.EVENT_READ:
            chunk = connection.recv(65536)
            if not chunk:
              self.selector.unregister(connection)
              connection.close()
              continue
            pending.extend(chunk)
          if mask & selectors.EVENT_WRITE and pending:
            del pending[:connection.send(pending)]
          interests = selectors.EVENT_READ
          if pending:
            interests |= selectors.EVENT_WRITE
          self.selector.modify(connection, interests, pending)
        except OSError:
          try:
            self.selector.unregister(connection)
          except Exception:
            pass
          connection.close()

  def close(self):
    self.stopping.set()
    self.listener.close()
    self.thread.join(timeout=2)
    for key in list(self.selector.get_map().values()):
      try:
        key.fileobj.close()
      except OSError:
        pass
    self.selector.close()


class UdpEcho:
  def __init__(self):
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.socket.bind(("127.0.0.1", 0))
    self.socket.settimeout(0.05)
    self.port = self.socket.getsockname()[1]
    self.stopping = threading.Event()
    self.thread = threading.Thread(target=self.run, daemon=True)
    self.thread.start()

  def run(self):
    while not self.stopping.is_set():
      try:
        payload, peer = self.socket.recvfrom(65535)
        self.socket.sendto(payload, peer)
      except TimeoutError:
        pass
      except OSError:
        break

  def close(self):
    self.stopping.set()
    self.socket.close()
    self.thread.join(timeout=2)


def greeting(stream):
  stream.sendall(b"\x05\x01\x00")
  if exact(stream, 2) != b"\x05\x00":
    raise ConnectionError("SOCKS5 greeting rejected")


def tcp_connect(proxy_port, target_port):
  stream = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
  stream.settimeout(5)
  try:
    greeting(stream)
    stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") +
                   struct.pack("!H", target_port))
    reply = exact(stream, 10)
    if reply[:2] != b"\x05\x00":
      raise ConnectionError("SOCKS5 CONNECT rejected")
    return stream
  except Exception:
    stream.close()
    raise


def udp_associate(proxy_port):
  datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  datagram.bind(("127.0.0.1", 0))
  datagram.settimeout(5)
  control = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
  control.settimeout(5)
  try:
    greeting(control)
    control.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("127.0.0.1") +
                    struct.pack("!H", datagram.getsockname()[1]))
    reply = exact(control, 10)
    if reply[:2] != b"\x05\x00":
      raise ConnectionError("SOCKS5 UDP ASSOCIATE rejected")
    host = socket.inet_ntoa(reply[4:8])
    if host == "0.0.0.0":
      host = "127.0.0.1"
    return control, datagram, (host, struct.unpack("!H", reply[8:10])[0])
  except Exception:
    control.close()
    datagram.close()
    raise


def udp_round_trip(resource, target_port, sequence, timeout=5):
  _, datagram, relay = resource
  datagram.settimeout(timeout)
  payload = struct.pack("!I", sequence) + b"ftun-capacity"
  header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + \
    struct.pack("!H", target_port)
  datagram.sendto(header + payload, relay)
  response, _ = datagram.recvfrom(65535)
  if len(response) < 10 or response[10:] != payload:
    raise ConnectionError("UDP echo mismatch")


def expect_rejected(factory):
  try:
    resource_value = factory()
  except (OSError, TimeoutError, ConnectionError):
    return
  if isinstance(resource_value, tuple):
    for value in resource_value[:2]:
      value.close()
  else:
    resource_value.close()
  raise RuntimeError("capacity overflow was accepted")


def wait_ready(process, port, stderr_path):
  for _ in range(500):
    if process.poll() is not None:
      break
    try:
      with socket.create_connection(("127.0.0.1", port), timeout=0.05):
        return
    except OSError:
      time.sleep(0.01)
  detail = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
  raise RuntimeError("FTUN did not become ready: " + detail[:500])


def write_config(path, proxy_port, tcp_capacity=TCP_CAPACITY):
  path.write_text(json.dumps({
    "base": {"state-cache": False, "capacity": {
      "tcp-flows": tcp_capacity,
      "udp-flows": UDP_FLOW_CAPACITY,
      "udp-associations": ASSOCIATION_CAPACITY}},
    "dns": {"enable": False},
    "log": {"level": "silent"},
    "inbounds": [{"name": "capacity", "type": "socks5",
                  "listen": f"127.0.0.1:{proxy_port}", "udp": True}],
    "rules": ["MATCH,DIRECT"],
  }), encoding="utf-8")


def process_rss_kib(pid):
  for line in Path(f"/proc/{pid}/status").read_text().splitlines():
    if line.startswith("VmRSS:"):
      return int(line.split()[1])
  return 0


def main():
  if len(sys.argv) != 2:
    print("core capacity failed: FTUN binary is required", file=sys.stderr)
    return 1
  binary = Path(sys.argv[1]).resolve()
  soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
  wanted = min(hard, 16384) if hard != resource.RLIM_INFINITY else 16384
  if soft < wanted:
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
  if resource.getrlimit(resource.RLIMIT_NOFILE)[0] < 8192:
    print("core capacity skipped: RLIMIT_NOFILE below 8192")
    return 77

  tcp_echo = TcpEcho()
  udp_echo = UdpEcho()
  tcp = []
  udp = []
  process = None
  stage = "startup"
  started = time.monotonic()
  try:
    with tempfile.TemporaryDirectory(prefix="ftun-core-capacity-") as directory:
      directory = Path(directory)
      config = directory / "config.json"
      stderr_path = directory / "ftun.stderr"
      proxy_port = pick_port()
      write_config(config, proxy_port)
      with stderr_path.open("w+") as stderr_file:
        process = subprocess.Popen([str(binary), "run", "-c", str(config)],
                                   stdout=subprocess.DEVNULL,
                                   stderr=stderr_file)
        wait_ready(process, proxy_port, stderr_path)
        for index in range(TCP_CAPACITY):
          stage = f"tcp admission {index + 1}/{TCP_CAPACITY}"
          tcp.append(tcp_connect(proxy_port, tcp_echo.port))
        stage = "tcp data"
        for index in (0, TCP_CAPACITY // 2, TCP_CAPACITY - 1):
          payload = struct.pack("!I", index) + b"tcp"
          tcp[index].sendall(payload)
          if exact(tcp[index], len(payload)) != payload:
            raise ConnectionError("TCP echo mismatch")
        stage = "tcp overflow"
        expect_rejected(lambda: tcp_connect(proxy_port, tcp_echo.port))

        for index in range(UDP_FLOW_CAPACITY):
          stage = f"UDP association {index + 1}/{UDP_FLOW_CAPACITY}"
          association = udp_associate(proxy_port)
          stage = f"UDP flow {index + 1}/{UDP_FLOW_CAPACITY}"
          udp_round_trip(association, udp_echo.port, index)
          udp.append(association)

        # UDP 流表已满，但关联仍有一个独立额度：握手成功，首包被流表拒绝。
        stage = "separate UDP association capacity"
        spare = udp_associate(proxy_port)
        udp.append(spare)
        try:
          udp_round_trip(spare, udp_echo.port, UDP_FLOW_CAPACITY, timeout=0.2)
          raise RuntimeError("UDP flow capacity did not reject the 1001st flow")
        except TimeoutError:
          pass
        stage = "UDP association overflow"
        expect_rejected(lambda: udp_associate(proxy_port))

        stage = "capacity reload rejection"
        write_config(config, proxy_port, TCP_CAPACITY - 1)
        process.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
          text = stderr_path.read_text(errors="replace")
          if "reload rejected" in text and "unsupported" in text:
            break
          if process.poll() is not None:
            raise RuntimeError("FTUN exited during rejected reload")
          time.sleep(0.02)
        else:
          raise RuntimeError("capacity-changing reload was not rejected")

        payload = b"after-rejected-reload"
        tcp[0].sendall(payload)
        if exact(tcp[0], len(payload)) != payload:
          raise ConnectionError("existing TCP flow changed during reload")
        udp_round_trip(udp[0], udp_echo.port, UDP_FLOW_CAPACITY + 1)
        active_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
        active_rss = process_rss_kib(process.pid)
        stage = "idle slab and descriptor reclaim"
        for stream in tcp:
          stream.close()
        tcp.clear()
        for control, datagram, _ in udp:
          control.close()
          datagram.close()
        udp.clear()
        deadline = time.monotonic() + 10
        cleaned_fds = active_fds
        while time.monotonic() < deadline:
          cleaned_fds = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
          if cleaned_fds < 32:
            break
          time.sleep(0.02)
        if cleaned_fds >= 32:
          raise RuntimeError(f"descriptors were not reclaimed: {cleaned_fds}")
        metrics = {
          "tcp_active": TCP_CAPACITY,
          "udp_flows_active": UDP_FLOW_CAPACITY,
          "udp_associations_active": ASSOCIATION_CAPACITY,
          "active_ftun_fds": active_fds,
          "cleaned_ftun_fds": cleaned_fds,
          "active_rss_kib": active_rss,
          "cleaned_rss_kib": process_rss_kib(process.pid),
          "elapsed_seconds": round(time.monotonic() - started, 3),
          "reload_capacity_change": "rejected",
        }
        print("core-capacity " + json.dumps(metrics, sort_keys=True))
  except Exception as error:
    detail = ""
    if 'stderr_path' in locals() and stderr_path.exists():
      detail = stderr_path.read_text(errors="replace")[-1000:]
    print(f"core capacity failed at {stage}: {error}; stderr={detail}",
          file=sys.stderr)
    return 1
  finally:
    for stream in tcp:
      stream.close()
    for control, datagram, _ in udp:
      control.close()
      datagram.close()
    if process is not None and process.poll() is None:
      process.send_signal(signal.SIGTERM)
      try:
        process.wait(timeout=15)
      except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    tcp_echo.close()
    udp_echo.close()
  if process is None or process.returncode != 0:
    print(f"core capacity failed: FTUN exit={None if process is None else process.returncode}",
          file=sys.stderr)
    return 1
  return 0


if __name__ == "__main__":
  raise SystemExit(main())

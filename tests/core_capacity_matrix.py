#!/usr/bin/env python3
"""C10-013：补足 socket/TUN × SOCKS5 的 1000+1000 容量矩阵。"""

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
import time

from core_capacity import (ASSOCIATION_CAPACITY, TCP_CAPACITY,
                           UDP_FLOW_CAPACITY, TcpEcho, UdpEcho, exact,
                           pick_port, process_rss_kib, tcp_connect,
                           udp_associate, udp_round_trip)


PEER_ADDRESS = "192.0.2.2"
PEER_TCP_PORT = 18080
PEER_UDP_PORT = 18081
PEER_SOCKS_PORT = 11080
LAN_RULE_PRIORITY = 11002
ROUTE_TABLE = 51820


def raise_descriptor_limit():
  soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
  wanted = 16384 if hard == resource.RLIM_INFINITY else min(hard, 16384)
  if soft < wanted:
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
  return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


def run_command(*arguments, check=True, **kwargs):
  return subprocess.run(arguments, check=check, text=True, **kwargs)


def wait_path(path, processes, timeout, description):
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if path.exists():
      return
    for process in processes:
      if process is not None and process.poll() is not None:
        raise RuntimeError(
          f"{description} exited before readiness: {process.returncode}")
    time.sleep(0.01)
  raise RuntimeError(f"timed out waiting for {description}")


def wait_listener(process, address, port, namespace, log_path):
  probe = (
    "import socket; "
    f"s=socket.create_connection(({address!r},{port}),.2); s.close()")
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    if process.poll() is not None:
      break
    command = [sys.executable, "-c", probe]
    if namespace is not None:
      command = ["ip", "netns", "exec", namespace] + command
    if subprocess.run(command, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
      return
    time.sleep(0.02)
  detail = log_path.read_text(errors="replace") if log_path.exists() else ""
  raise RuntimeError(
    f"listener {address}:{port} unavailable (exit={process.poll()}): "
    f"{detail[-1000:]}")


def wait_interface(process, name, log_path):
  deadline = time.monotonic() + 10
  while time.monotonic() < deadline:
    if process.poll() is not None:
      break
    if subprocess.run(["ip", "link", "show", name],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode == 0:
      return
    time.sleep(0.02)
  detail = log_path.read_text(errors="replace") if log_path.exists() else ""
  raise RuntimeError(f"TUN {name} unavailable: {detail[-1000:]}")


def terminate(process, timeout=20):
  if process is None or process.poll() is not None:
    return
  process.send_signal(signal.SIGTERM)
  try:
    process.wait(timeout=timeout)
  except subprocess.TimeoutExpired:
    process.kill()
    process.wait()


def wait_descriptor_reclaim(process, maximum=32):
  deadline = time.monotonic() + 15
  count = 1 << 30
  while time.monotonic() < deadline and process.poll() is None:
    count = len(list(Path(f"/proc/{process.pid}/fd").iterdir()))
    if count < maximum:
      return count
    time.sleep(0.02)
  raise RuntimeError(f"descriptors were not reclaimed: {count}")


def write_socks_config(path, listen_address, listen_port,
                       upstream_address=None, upstream_port=None):
  document = {
    "base": {"state-cache": False, "allow-lan": True, "capacity": {
      "tcp-flows": TCP_CAPACITY,
      "udp-flows": UDP_FLOW_CAPACITY,
      "udp-associations": max(TCP_CAPACITY, ASSOCIATION_CAPACITY)}},
    "dns": {"enable": False},
    "log": {"level": "error"},
    "inbounds": [{"name": "capacity-socks", "type": "socks5",
                  "listen": f"{listen_address}:{listen_port}", "udp": True}],
  }
  if upstream_address is None:
    document["rules"] = ["MATCH,DIRECT"]
  else:
    document["outbounds"] = [{
      "name": "proxy", "type": "socks5",
      "server": f"{upstream_address}:{upstream_port}", "udp": True}]
    document["rules"] = ["MATCH,proxy"]
  path.write_text(json.dumps(document), encoding="utf-8")


def write_tun_config(path, interface_name, use_proxy):
  document = {
    "base": {"state-cache": False, "capacity": {
      "tcp-flows": TCP_CAPACITY,
      "udp-flows": UDP_FLOW_CAPACITY,
      "udp-associations": TCP_CAPACITY}},
    "dns": {"enable": False},
    "log": {"level": "error"},
    "inbounds": [{
      "name": "capacity-tun", "type": "tun",
      "interface": {"name": interface_name, "mtu": 1400},
      "ipv4": {"address": "10.77.0.1/30"},
      "tcp": True, "udp": True, "auto-route": True,
      "strict-route": True, "dns-hijack": False}],
  }
  if use_proxy:
    document["outbounds"] = [{
      "name": "proxy", "type": "socks5",
      "server": f"{PEER_ADDRESS}:{PEER_SOCKS_PORT}", "udp": True}]
    document["rules"] = ["MATCH,proxy"]
  else:
    document["rules"] = ["MATCH,DIRECT"]
  path.write_text(json.dumps(document), encoding="utf-8")


def start_ftun(binary, config, log_path, namespace=None):
  command = [str(binary), "run", "-c", str(config)]
  if namespace is not None:
    command = ["ip", "netns", "exec", namespace] + command
  log = log_path.open("w+")
  process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
  process.capacity_log = log
  process.capacity_log_path = log_path
  return process


def close_ftun(process):
  if process is None:
    return
  terminate(process)
  process.capacity_log.close()
  if process.returncode != 0:
    raise RuntimeError(f"FTUN exited with {process.returncode}")


def socket_socks_matrix(binary, directory):
  tcp_echo = TcpEcho()
  udp_echo = UdpEcho()
  backend = None
  front = None
  tcp = []
  udp = []
  try:
    backend_port = pick_port()
    front_port = pick_port()
    backend_config = directory / "socket-backend.json"
    front_config = directory / "socket-front.json"
    backend_log = directory / "socket-backend.log"
    front_log = directory / "socket-front.log"
    write_socks_config(backend_config, "127.0.0.1", backend_port)
    write_socks_config(front_config, "127.0.0.1", front_port,
                       "127.0.0.1", backend_port)
    backend = start_ftun(binary, backend_config, backend_log)
    try:
      wait_listener(backend, "127.0.0.1", backend_port, None, backend_log)
      wait_descriptor_reclaim(backend)
    except Exception as error:
      raise RuntimeError(f"backend port={backend_port}: {error}") from error
    front = start_ftun(binary, front_config, front_log)
    try:
      wait_listener(front, "127.0.0.1", front_port, None, front_log)
      wait_descriptor_reclaim(front)
    except Exception as error:
      raise RuntimeError(
        f"front port={front_port} backend={backend_port}: {error}") from error
    started = time.monotonic()
    for _ in range(TCP_CAPACITY):
      tcp.append(tcp_connect(front_port, tcp_echo.port))
    for index in range(UDP_FLOW_CAPACITY):
      association = udp_associate(front_port)
      udp_round_trip(association, udp_echo.port, index)
      udp.append(association)
    for index in (0, TCP_CAPACITY // 2, TCP_CAPACITY - 1):
      payload = struct.pack("!I", index) + b"socket-socks-capacity"
      tcp[index].sendall(payload)
      if exact(tcp[index], len(payload)) != payload:
        raise ConnectionError("socket -> SOCKS5 TCP echo mismatch")
    metrics = {
      "path": "socket-socks5",
      "tcp_active": len(tcp),
      "udp_flows_active": len(udp),
      "udp_associations_active": len(udp),
      "front_active_fds": len(list(Path(f"/proc/{front.pid}/fd").iterdir())),
      "backend_active_fds": len(list(Path(f"/proc/{backend.pid}/fd").iterdir())),
      "front_rss_kib": process_rss_kib(front.pid),
      "backend_rss_kib": process_rss_kib(backend.pid),
      "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    for stream in tcp:
      stream.close()
    tcp.clear()
    for control, datagram, _ in udp:
      control.close()
      datagram.close()
    udp.clear()
    metrics["front_cleaned_fds"] = wait_descriptor_reclaim(front)
    metrics["backend_cleaned_fds"] = wait_descriptor_reclaim(backend)
    return metrics
  finally:
    for stream in tcp:
      stream.close()
    for control, datagram, _ in udp:
      control.close()
      datagram.close()
    terminate(front)
    terminate(backend)
    if front is not None:
      front.capacity_log.close()
    if backend is not None:
      backend.capacity_log.close()
    tcp_echo.close()
    udp_echo.close()
    if front is not None and front.returncode not in (None, 0):
      raise RuntimeError(f"socket front FTUN exited with {front.returncode}")
    if backend is not None and backend.returncode not in (None, 0):
      raise RuntimeError(f"socket backend FTUN exited with {backend.returncode}")


class NamespaceEcho:
  def __init__(self, address, tcp_port, udp_port, ready_path, result_path):
    self.address = address
    self.tcp_port = tcp_port
    self.udp_port = udp_port
    self.ready_path = Path(ready_path)
    self.result_path = Path(result_path)
    self.selector = selectors.DefaultSelector()
    self.tcp_clients = 0
    self.tcp_peak = 0
    self.udp_peers = set()
    self.stop = False

  def signal(self, _signum, _frame):
    self.stop = True

  def run(self):
    raise_descriptor_limit()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setblocking(False)
    listener.bind((self.address, self.tcp_port))
    listener.listen(4096)
    datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    datagram.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    datagram.setblocking(False)
    datagram.bind((self.address, self.udp_port))
    self.selector.register(listener, selectors.EVENT_READ, None)
    self.selector.register(datagram, selectors.EVENT_READ, "udp")
    signal.signal(signal.SIGTERM, self.signal)
    self.ready_path.write_text("ready\n", encoding="utf-8")
    try:
      while not self.stop:
        for key, mask in self.selector.select(0.05):
          if key.fileobj is listener:
            while True:
              try:
                connection, _ = listener.accept()
                connection.setblocking(False)
                self.selector.register(connection, selectors.EVENT_READ,
                                       bytearray())
                self.tcp_clients += 1
                self.tcp_peak = max(self.tcp_peak, self.tcp_clients)
              except BlockingIOError:
                break
          elif key.fileobj is datagram:
            while True:
              try:
                payload, peer = datagram.recvfrom(65535)
                self.udp_peers.add(peer)
                datagram.sendto(payload, peer)
              except BlockingIOError:
                break
          else:
            connection = key.fileobj
            pending = key.data
            try:
              if mask & selectors.EVENT_READ:
                chunk = connection.recv(65536)
                if not chunk:
                  self.selector.unregister(connection)
                  connection.close()
                  self.tcp_clients -= 1
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
              self.tcp_clients -= 1
    finally:
      result = {"tcp_peak": self.tcp_peak,
                "udp_unique_sources": len(self.udp_peers)}
      self.result_path.write_text(json.dumps(result), encoding="utf-8")
      for key in list(self.selector.get_map().values()):
        try:
          key.fileobj.close()
        except OSError:
          pass
      self.selector.close()
    return 0


def tun_client(target_address, tcp_port, udp_port, result_path, release_path):
  if raise_descriptor_limit() < 4096:
    return 77
  tcp = []
  udp = []
  started = time.monotonic()
  try:
    for index in range(TCP_CAPACITY):
      stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      stream.settimeout(15)
      stream.connect((target_address, tcp_port))
      # TUN 的 connect 在本地 lwIP 完成握手后即可返回；首个回显把上游
      # DIRECT/SOCKS5 建连也纳入每个槽位的接纳判定，并避免淹没监听积压。
      payload = struct.pack("!I", index) + b"tun-capacity-open"
      try:
        stream.sendall(payload)
        if exact(stream, len(payload)) != payload:
          raise ConnectionError("payload differs")
      except Exception as error:
        raise ConnectionError(
          f"TUN TCP opening echo failed at {index}: {error}") from error
      tcp.append(stream)
    for index in (0, TCP_CAPACITY // 2, TCP_CAPACITY - 1):
      payload = struct.pack("!I", index) + b"tun-capacity-tcp"
      tcp[index].sendall(payload)
      if exact(tcp[index], len(payload)) != payload:
        raise ConnectionError("TUN TCP echo mismatch")
    for index in range(UDP_FLOW_CAPACITY):
      datagram = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      datagram.settimeout(15)
      datagram.bind(("0.0.0.0", 0))
      payload = struct.pack("!I", index) + b"tun-capacity-udp"
      datagram.sendto(payload, (target_address, udp_port))
      response, source = datagram.recvfrom(65535)
      if response != payload or source != (target_address, udp_port):
        raise ConnectionError("TUN UDP echo mismatch")
      udp.append(datagram)
    for index in (0, TCP_CAPACITY // 2, TCP_CAPACITY - 1):
      payload = struct.pack("!I", index) + b"tun-after-udp"
      tcp[index].sendall(payload)
      if exact(tcp[index], len(payload)) != payload:
        raise ConnectionError("TUN mixed TCP echo mismatch")
    temporary = Path(str(result_path) + ".next")
    temporary.write_text(json.dumps({
      "tcp_active": len(tcp), "udp_flows_active": len(udp),
      "elapsed_seconds": round(time.monotonic() - started, 3)}),
      encoding="utf-8")
    temporary.replace(result_path)
    deadline = time.monotonic() + 90
    while not Path(release_path).exists():
      if time.monotonic() >= deadline:
        raise TimeoutError("parent did not release TUN capacity client")
      time.sleep(0.02)
    return 0
  finally:
    for stream in tcp:
      try:
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack("ii", 1, 0))
      except OSError:
        pass
      stream.close()
    for datagram in udp:
      datagram.close()


def setup_topology():
  run_command("mount", "--make-rprivate", "/")
  run_command("ip", "link", "set", "lo", "up")
  run_command("ip", "netns", "add", "ftun-cap-peer")
  run_command("ip", "netns", "add", "ftun-cap-lan")
  run_command("ip", "link", "add", "phys0", "type", "veth", "peer",
              "name", "peer0")
  run_command("ip", "link", "set", "peer0", "netns", "ftun-cap-peer")
  run_command("ip", "address", "add", "192.0.2.1/24", "dev", "phys0")
  run_command("ip", "link", "set", "phys0", "up")
  run_command("ip", "netns", "exec", "ftun-cap-peer", "ip", "link",
              "set", "lo", "up")
  run_command("ip", "netns", "exec", "ftun-cap-peer", "ip", "link",
              "set", "peer0", "up")
  run_command("ip", "netns", "exec", "ftun-cap-peer", "ip", "address",
              "add", "192.0.2.2/24", "dev", "peer0")
  run_command("ip", "link", "add", "lan0", "type", "veth", "peer",
              "name", "client0")
  run_command("ip", "link", "set", "client0", "netns", "ftun-cap-lan")
  run_command("ip", "address", "add", "10.88.0.1/24", "dev", "lan0")
  run_command("ip", "link", "set", "lan0", "up")
  run_command("ip", "netns", "exec", "ftun-cap-lan", "ip", "link",
              "set", "lo", "up")
  run_command("ip", "netns", "exec", "ftun-cap-lan", "ip", "link",
              "set", "client0", "up")
  run_command("ip", "netns", "exec", "ftun-cap-lan", "ip", "address",
              "add", "10.88.0.2/24", "dev", "client0")
  run_command("ip", "netns", "exec", "ftun-cap-lan", "ip", "route",
              "add", "default", "via", "10.88.0.1")
  for key, value in (
      ("net.ipv4.ip_forward", "1"),
      ("net.ipv4.conf.all.rp_filter", "0"),
      ("net.ipv4.conf.default.rp_filter", "0"),
      ("net.ipv4.conf.phys0.rp_filter", "0"),
      ("net.ipv4.conf.lan0.rp_filter", "0")):
    run_command("sysctl", "-q", "-w", f"{key}={value}")


def cleanup_topology():
  subprocess.run(["ip", "rule", "del", "priority", str(LAN_RULE_PRIORITY),
                  "iif", "lan0", "lookup", str(ROUTE_TABLE)],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  for namespace in ("ftun-cap-lan", "ftun-cap-peer"):
    subprocess.run(["ip", "netns", "del", namespace],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tun_matrix_case(binary, directory, use_proxy, backend):
  label = "tun-socks5" if use_proxy else "tun-direct"
  interface_name = "ftun-cap0"
  config = directory / f"{label}.json"
  log_path = directory / f"{label}.log"
  result_path = directory / f"{label}.result"
  release_path = directory / f"{label}.release"
  client_log_path = directory / f"{label}.client.log"
  write_tun_config(config, interface_name, use_proxy)
  front = start_ftun(binary, config, log_path)
  client = None
  rule_installed = False
  try:
    wait_interface(front, interface_name, log_path)
    run_command("ip", "rule", "add", "priority", str(LAN_RULE_PRIORITY),
                "iif", "lan0", "lookup", str(ROUTE_TABLE))
    rule_installed = True
    client_log = client_log_path.open("w+")
    client = subprocess.Popen([
      "ip", "netns", "exec", "ftun-cap-lan", sys.executable,
      str(Path(__file__).resolve()), "--tun-client", PEER_ADDRESS,
      str(PEER_TCP_PORT), str(PEER_UDP_PORT), str(result_path),
      str(release_path)], stdout=subprocess.DEVNULL, stderr=client_log)
    client.capacity_log = client_log
    try:
      wait_path(result_path, (front, client), 90, label + " client")
    except Exception as error:
      client_log.flush()
      detail = client_log_path.read_text(errors="replace")
      daemon_detail = log_path.read_text(errors="replace")
      backend_detail = ""
      if backend is not None:
        backend.capacity_log.flush()
        backend_detail = backend.capacity_log_path.read_text(errors="replace")
      raise RuntimeError(
        f"{error}; client={detail[-1000:]}; daemon={daemon_detail[-1000:]}; "
        f"backend={backend_detail[-1000:]}") \
        from error
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("tcp_active") != TCP_CAPACITY or \
        result.get("udp_flows_active") != UDP_FLOW_CAPACITY:
      raise RuntimeError(f"incomplete {label} capacity result: {result}")
    metrics = {
      "path": label,
      **result,
      "front_active_fds": len(list(Path(f"/proc/{front.pid}/fd").iterdir())),
      "front_rss_kib": process_rss_kib(front.pid),
    }
    if backend is not None:
      metrics["backend_active_fds"] = len(
        list(Path(f"/proc/{backend.pid}/fd").iterdir()))
      metrics["backend_rss_kib"] = process_rss_kib(backend.pid)
    release_path.write_text("release\n", encoding="utf-8")
    client.wait(timeout=30)
    client.capacity_log.close()
    if client.returncode != 0:
      detail = client_log_path.read_text(errors="replace")
      raise RuntimeError(f"{label} client failed: {detail[-1000:]}")
    client = None
    # TUN UDP 没有控制连接可通知关闭，产品按 120 秒空闲期回收；这里记录
    # 客户端关闭后的即时值，池本身的 trim/代际复用由专项契约测试验证。
    time.sleep(0.5)
    metrics["front_post_client_fds"] = len(
      list(Path(f"/proc/{front.pid}/fd").iterdir()))
    if backend is not None:
      metrics["backend_post_client_fds"] = len(
        list(Path(f"/proc/{backend.pid}/fd").iterdir()))
    return metrics
  finally:
    if client is not None:
      release_path.write_text("release\n", encoding="utf-8")
      terminate(client)
      client.capacity_log.close()
    if rule_installed:
      subprocess.run([
        "ip", "rule", "del", "priority", str(LAN_RULE_PRIORITY), "iif",
        "lan0", "lookup", str(ROUTE_TABLE)], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    terminate(front)
    front.capacity_log.close()
    if front.returncode not in (None, 0):
      detail = log_path.read_text(errors="replace")
      raise RuntimeError(f"{label} FTUN failed: {detail[-1000:]}")


def enter_isolated_namespace(binary):
  if os.environ.get("FTUN_CAPACITY_MATRIX_NAMESPACE") == "1":
    return True
  if subprocess.run(["unshare", "-Urn", "true"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL).returncode != 0:
    print("core capacity matrix skipped: isolated namespaces unavailable")
    return False
  environment = os.environ.copy()
  environment["FTUN_CAPACITY_MATRIX_NAMESPACE"] = "1"
  os.execvpe("unshare", ["unshare", "-Urnm", sys.executable,
                         str(Path(__file__).resolve()), str(binary)],
             environment)
  return False


def orchestrate(binary):
  if raise_descriptor_limit() < 8192:
    print("core capacity matrix skipped: RLIMIT_NOFILE below 8192")
    return 77
  if not enter_isolated_namespace(binary):
    return 77
  stage = "socket -> SOCKS5"
  echo = None
  backend = None
  try:
    with tempfile.TemporaryDirectory(prefix="ftun-capacity-matrix-") as root:
      directory = Path(root)
      run_command("ip", "link", "set", "lo", "up")
      results = [socket_socks_matrix(binary, directory)]
      stage = "isolated TUN topology"
      setup_topology()
      echo_ready = directory / "echo.ready"
      echo_result = directory / "echo.result"
      echo_log_path = directory / "echo.log"
      echo_log = echo_log_path.open("w+")
      echo = subprocess.Popen([
        "ip", "netns", "exec", "ftun-cap-peer", sys.executable,
        str(Path(__file__).resolve()), "--echo", PEER_ADDRESS,
        str(PEER_TCP_PORT), str(PEER_UDP_PORT), str(echo_ready),
        str(echo_result)], stdout=subprocess.DEVNULL, stderr=echo_log)
      echo.capacity_log = echo_log
      wait_path(echo_ready, (echo,), 10, "namespace echo")

      stage = "TUN -> DIRECT"
      results.append(tun_matrix_case(binary, directory, False, None))

      stage = "TUN SOCKS5 backend"
      backend_config = directory / "tun-backend.json"
      backend_log = directory / "tun-backend.log"
      write_socks_config(backend_config, PEER_ADDRESS, PEER_SOCKS_PORT)
      backend = start_ftun(binary, backend_config, backend_log,
                           "ftun-cap-peer")
      wait_listener(backend, PEER_ADDRESS, PEER_SOCKS_PORT, "ftun-cap-peer",
                    backend_log)
      wait_descriptor_reclaim(backend)
      stage = "TUN -> SOCKS5"
      results.append(tun_matrix_case(binary, directory, True, backend))
      close_ftun(backend)
      backend = None
      terminate(echo)
      echo.capacity_log.close()
      if echo.returncode != 0:
        detail = echo_log_path.read_text(errors="replace")
        raise RuntimeError(f"namespace echo failed: {detail[-1000:]}")
      echo = None
      echo_metrics = json.loads(echo_result.read_text(encoding="utf-8"))
      if echo_metrics.get("tcp_peak", 0) < TCP_CAPACITY or \
          echo_metrics.get("udp_unique_sources", 0) < UDP_FLOW_CAPACITY:
        raise RuntimeError(f"namespace echo saw incomplete load: {echo_metrics}")
      print("core-capacity-matrix " + json.dumps({
        "paths": results, "namespace_echo": echo_metrics}, sort_keys=True))
  except Exception as error:
    print(f"core capacity matrix failed at {stage}: {error}", file=sys.stderr)
    return 1
  finally:
    if backend is not None:
      terminate(backend)
      backend.capacity_log.close()
    if echo is not None:
      terminate(echo)
      echo.capacity_log.close()
    cleanup_topology()
  return 0


def main():
  if len(sys.argv) >= 2 and sys.argv[1] == "--echo":
    if len(sys.argv) != 7:
      return 2
    return NamespaceEcho(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                         sys.argv[5], sys.argv[6]).run()
  if len(sys.argv) >= 2 and sys.argv[1] == "--tun-client":
    if len(sys.argv) != 7:
      return 2
    return tun_client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                      Path(sys.argv[5]), Path(sys.argv[6]))
  if len(sys.argv) != 2:
    print("usage: core_capacity_matrix.py FTUN", file=sys.stderr)
    return 2
  return orchestrate(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
  raise SystemExit(main())

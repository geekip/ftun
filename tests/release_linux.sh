#!/bin/sh
set -eu

for tool in ip unshare mount; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing test prerequisite: $tool" >&2
    exit 77
  fi
done

if [ "$#" -ne 3 ]; then
  echo "usage: $0 FTUN INTEGRATION_HELPER FRS_FIXTURE" >&2
  exit 2
fi

ftun_binary=$1
helper_binary=$2
fixture_binary=$3

if [ "${FTUN_RELEASE_NAMESPACE:-0}" != 1 ]; then
  if ! unshare -Urnm true >/dev/null 2>&1; then
    echo "isolated user/network namespaces unavailable" >&2
    exit 77
  fi
  exec env FTUN_RELEASE_NAMESPACE=1 unshare -Urnm sh "$0" \
    "$ftun_binary" "$helper_binary" "$fixture_binary"
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-release.XXXXXX")
peer_pid=
local_pid=
ftun_pid=
stage=setup

cleanup()
{
  status=$?
  if [ -n "$ftun_pid" ]; then
    kill -TERM "$ftun_pid" >/dev/null 2>&1 || true
    wait "$ftun_pid" || status=1
  fi
  if [ -n "$peer_pid" ]; then
    kill -TERM "$peer_pid" >/dev/null 2>&1 || true
    wait "$peer_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$local_pid" ]; then
    kill -TERM "$local_pid" >/dev/null 2>&1 || true
    wait "$local_pid" >/dev/null 2>&1 || true
  fi
  ip rule del priority 11002 iif lan0 lookup 18004 >/dev/null 2>&1 || true
  ip netns del ftun-lan >/dev/null 2>&1 || true
  ip netns del ftun-peer >/dev/null 2>&1 || true
  if [ "$status" -ne 0 ]; then
    echo "release production test failed (status $status, stage $stage)" >&2
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/peer.log" >&2 || true
    sed -n '1,200p' /tmp/ftun-release.log >&2 || true
  fi
  rm -f /tmp/ftun-release.log "$temporary/config.json" "$temporary/ready" \
    "$temporary/config.next" "$temporary/config.good" \
    "$temporary/peer.log" "$temporary/ftun.log" \
    "$temporary/source.frs" "$temporary/rules.frs" \
    "$temporary/local.ready" "$temporary/local.log"
  rm -f "$temporary/cache.fakeip/identity" \
    "$temporary/cache.fakeip/reservations" \
    "$temporary/cache.fakeip/mappings" "$temporary/cache.fakeip/lock"
  rmdir "$temporary/cache.fakeip" >/dev/null 2>&1 || true
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mount --make-rprivate /
ip link set lo up
"$fixture_binary" --write "$temporary/source.frs"
ip netns add ftun-peer
ip netns add ftun-lan

ip link add phys0 type veth peer name peer0
ip link set peer0 netns ftun-peer
ip address add 192.0.2.1/24 dev phys0
ip link set phys0 up
ip netns exec ftun-peer ip link set lo up
ip netns exec ftun-peer ip link set peer0 up
ip netns exec ftun-peer ip address add 192.0.2.2/24 dev peer0
ip netns exec ftun-peer ip address add 192.0.2.53/24 dev peer0

ip link add lan0 type veth peer name client0
ip link set client0 netns ftun-lan
ip address add 10.88.0.1/24 dev lan0
ip link set lan0 up
ip netns exec ftun-lan ip link set lo up
ip netns exec ftun-lan ip link set client0 up
ip netns exec ftun-lan ip address add 10.88.0.2/24 dev client0
ip netns exec ftun-lan ip route add default via 10.88.0.1

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w net.ipv4.conf.all.rp_filter=0
sysctl -q -w net.ipv4.conf.default.rp_filter=0
sysctl -q -w net.ipv4.conf.phys0.rp_filter=0
sysctl -q -w net.ipv4.conf.lan0.rp_filter=0

cat >"$temporary/config.json" <<EOF
{
  "base": {"cache-file":"$temporary/cache","state-cache":false},
  "log": {"level":"debug","file":"/tmp/ftun-release.log"},
  "frs": {
    "path":"$temporary/rules.frs",
    "url":"http://frs.release.test:18082/redirect",
    "auto-update":true,
    "update-interval":"1s",
    "update-outbound":"DIRECT",
    "dns-server":"real"
  },
  "dns": {
    "enable":true,
    "cache":true,
    "bootstrap":["192.0.2.53:53"],
    "default-server":"real",
    "fake-ip":{"enable":true,"range":"198.18.0.0/15","persist":true},
    "listeners":[
      {"listen":"127.0.0.1:15353","server":"real"},
      {"listen":"127.0.0.1:15354","server":"fake"},
      {"listen":"127.0.0.1:15355"}
    ],
    "servers":[
      {"name":"real","type":"udp","address":["dns.release.test:53"],"outbound":"proxy"},
      {"name":"fake","type":"udp","address":["192.0.2.53:53"],"outbound":"DIRECT","fake-ip":true}
    ]
  },
  "tun": {
    "interface":"ftun-prod0","mtu":1400,
    "ipv4":{"address":"10.77.0.1/30"},
    "auto-route":true,"strict-route":true
  },
  "inbounds": [
    {"name":"release-socks","type":"socks5","listen":"127.0.0.1:11081","udp":true},
    {"name":"release-mixed","type":"mixed","listen":"127.0.0.1:11082","udp":true},
    {
      "name":"release-tun",
      "type":"tun",
      "tcp":true,
      "udp":true,
      "dns-hijack":true
    }
  ],
  "outbounds":[
    {"name":"proxy","type":"socks5","server":"proxy.release.test:11080","udp":true},
    {"name":"bad","type":"socks5","server":"proxy.release.test:9","udp":true},
    {
      "name":"auto","type":"url-test","outbounds":["DIRECT","bad"],
      "default":"bad","url":"http://health-url.release.test:18082/health",
      "interval":"1s","timeout":"500ms","tolerance":0,
      "lazy":false,"expected-status":204
    }
  ],
  "rules":["DOMAIN,health.release.test,auto","DOMAIN,remote.release.test,proxy","FRS-DOMAIN,CN,DIRECT","NETWORK,udp,proxy","MATCH,DIRECT"]
}
EOF

# FakeIP offline initialization validates the same active FRS references; give
# it the valid local artifact, then remove it to exercise run-time bootstrap.
cp "$temporary/source.frs" "$temporary/rules.frs"
"$ftun_binary" fakeip init -c "$temporary/config.json"
rm -f "$temporary/rules.frs"

ip netns exec ftun-peer "$helper_binary" --peer "$temporary/ready" \
  "$temporary/source.frs" \
  >"$temporary/peer.log" 2>&1 &
peer_pid=$!

attempt=0
while [ ! -f "$temporary/ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$peer_pid" 2>/dev/null; then
    sed -n '1,200p' "$temporary/peer.log" >&2
    exit 1
  fi
  sleep 0.01
done

"$ftun_binary" run -c "$temporary/config.json" \
  >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!

attempt=0
while ! ip link show ftun-prod0 >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    sed -n '1,200p' "$temporary/ftun.log" >&2
    exit 1
  fi
  sleep 0.01
done

# 本地规则文件缺失：服务不等待下载，以 NOT_READY 启动；后台下载成功并发布新
# 快照后才继续（此前的第一条 FRS 规则会拒绝新连接）。
attempt=0
while ! grep -q 'config.published.*reason=frs-update' /tmp/ftun-release.log; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 500 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "FRS background download did not publish" >&2
    sed -n '1,200p' "$temporary/ftun.log" >&2
    exit 1
  fi
  sleep 0.02
done
if [ ! -s "$temporary/rules.frs" ] ||
   ! cmp -s "$temporary/source.frs" "$temporary/rules.frs"; then
  echo "FRS startup download was not atomically published" >&2
  exit 1
fi
if ! grep -q 'http-rules-redirect' "$temporary/peer.log"; then
  echo "FRS relative redirect was not followed" >&2
  exit 1
fi

# LAN 转发路由由部署者显式提供；FTUN 的保护 mark 规则优先绕过捕获表。
ip rule add priority 11002 iif lan0 lookup 18004

attempt=0
while ! grep -q 'http-health' "$temporary/peer.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "URL-Test production probe was not observed" >&2
    exit 1
  fi
  sleep 0.01
done
# Seeing the probe request does not mean its worker completion has already
# published the URL-Test choice.  Wait for the selected route rather than
# racing the owner-side completion callback.
attempt=0
while ! "$helper_binary" --socks-domain-client 11081 \
  health.release.test:18080 >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "URL-Test production route did not become ready" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --socks-domain-client 11081 remote.release.test:18080
if ! grep -q 'socks-domain-target' "$temporary/peer.log"; then
  echo "SOCKS target domain was not delegated to the remote proxy" >&2
  exit 1
fi

"$helper_binary" --socks-client 11081 192.0.2.2:18080
load_runs=${FTUN_RELEASE_LOAD_RUNS:-1}
load_index=0
while [ "$load_index" -lt "$load_runs" ]; do
  "$helper_binary" --socks-load-client 11081 192.0.2.2:18080 8388608
  load_index=$((load_index + 1))
done
"$helper_binary" --socks-udp-client 11081 192.0.2.2:18081
"$helper_binary" --socks-udp-client 11082 192.0.2.2:18081
if [ "${FTUN_TEST_UDP_CONTROL_CLOSE:-0}" = 1 ]; then
  stage=socks5-udp-control-recovery
  "$helper_binary" --socks-udp-recovery-client 11081 192.0.2.2:18081
  if ! grep -q 'udp-control-closed' "$temporary/peer.log"; then
    echo "SOCKS5 UDP control-close fault was not injected" >&2
    exit 1
  fi
  stage=socks5-udp-reconnect-backoff
  "$helper_binary" --socks-udp-backoff-client 11081 192.0.2.2:18081
  backoff_attempts=$(awk '/udp-control-backoff-attempt/ {count++} END {print count+0}' \
    "$temporary/peer.log")
  if [ "$backoff_attempts" -lt 3 ] || [ "$backoff_attempts" -gt 5 ]; then
    echo "SOCKS5 UDP reconnect backoff was not bounded: attempts=$backoff_attempts" >&2
    exit 1
  fi
  # Let the final bounded retry window expire before unrelated UDP acceptance
  # checks exercise the same proxy leaf.
  sleep 1
fi
udp_load_packets=${FTUN_RELEASE_UDP_LOAD_PACKETS:-0}
if [ "$udp_load_packets" -ne 0 ]; then
  "$helper_binary" --socks-udp-load-client 11081 192.0.2.2:18081 \
    "$udp_load_packets"
fi
"$helper_binary" --mixed-connect-client 11082 192.0.2.2:18080
"$helper_binary" --mixed-forward-client 11082 192.0.2.2:18080
"$helper_binary" --client tcp release-local-tcp
"$helper_binary" --client udp release-local-udp
ip netns exec ftun-lan "$helper_binary" --client tcp release-lan-tcp
ip netns exec ftun-lan "$helper_binary" --client udp release-lan-udp
if [ -n "${FTUN_TEST_SEND_EAGAIN_PORT:-}" ] &&
   ! grep -q 'ftun-test-send-eagain' "$temporary/ftun.log"; then
  echo "UDP EAGAIN fault was not injected" >&2
  exit 1
fi
tun_load_runs=${FTUN_RELEASE_TUN_LOAD_RUNS:-1}
tun_load_bytes=${FTUN_RELEASE_TUN_LOAD_BYTES:-1048576}
tun_load_label=${FTUN_RELEASE_TUN_LOAD_LABEL:-tun}
netem_delay=${FTUN_RELEASE_NETEM_DELAY:-0ms}
netem_loss=${FTUN_RELEASE_NETEM_LOSS:-0%}
if [ "$netem_delay" != 0ms ] || [ "$netem_loss" != 0% ]; then
  ip netns exec ftun-peer tc qdisc replace dev peer0 root handle 1: prio
  ip netns exec ftun-peer tc qdisc replace dev peer0 parent 1:3 handle 30: \
    netem delay "$netem_delay" loss "$netem_loss"
  ip netns exec ftun-peer tc filter add dev peer0 protocol ip parent 1: \
    prio 3 u32 match ip sport 18080 0xffff flowid 1:3
fi
tun_load_index=0
while [ "$tun_load_index" -lt "$tun_load_runs" ]; do
  "$helper_binary" --load-client 192.0.2.2:18080 "$tun_load_bytes" \
    "$tun_load_label-local"
  ip netns exec ftun-lan "$helper_binary" \
    --load-client 192.0.2.2:18080 "$tun_load_bytes" "$tun_load_label-lan"
  tun_load_index=$((tun_load_index + 1))
done
if [ "$netem_delay" != 0ms ] || [ "$netem_loss" != 0% ]; then
  ip netns exec ftun-peer tc qdisc del dev peer0 root
fi
"$helper_binary" --dns-client 127.0.0.1 15353 192.0.2.2
"$helper_binary" --dns-client 127.0.0.1 15354 198.18.0.1
"$helper_binary" --dns-client 127.0.0.1 15355 192.0.2.2
"$helper_binary" --dns-tcp-client 127.0.0.1 15353 192.0.2.2
"$helper_binary" --dns-tcp-client 127.0.0.1 15354 198.18.0.1
"$helper_binary" --dns-tcp-pipeline 127.0.0.1 15353 192.0.2.2
if [ "${FTUN_TEST_FAKEIP_BOUNDARY_COUNT:-0}" -ne 0 ]; then
  stage=fakeip-runtime-reservation
  "$helper_binary" --dns-fakeip-sequence 127.0.0.1 15354 \
    "$FTUN_TEST_FAKEIP_BOUNDARY_COUNT"
fi
# Both transports to port 53 traverse the TUN policy DNS hijack.
"$helper_binary" --dns-client 192.0.2.53 53 192.0.2.2
"$helper_binary" --dns-tcp-client 192.0.2.53 53 192.0.2.2
ip netns exec ftun-lan "$helper_binary" --dns-client 192.0.2.53 53 192.0.2.2
ip netns exec ftun-lan "$helper_binary" --dns-tcp-client 192.0.2.53 53 192.0.2.2
"$helper_binary" --client-to tcp release-fakeip-tcp 198.18.0.1

# Bounded connection pressure: exercise independent concurrent Session/Relay
# ownership without serial helper startup hiding admission or cleanup defects.
stage=concurrent-streams
stress_flows=${FTUN_RELEASE_STRESS_FLOWS:-32}
stress_expect_rejections=${FTUN_RELEASE_STRESS_EXPECT_REJECTIONS:-0}
stress_hold_ms=${FTUN_RELEASE_STRESS_HOLD_MS:-500}
stress_sample_delay=${FTUN_RELEASE_STRESS_SAMPLE_DELAY:-0.1}
stress_pids=
stress_index=0
while [ "$stress_index" -lt "$stress_flows" ]; do
  "$helper_binary" --socks-hold-client 11081 192.0.2.2:18080 \
    "$stress_hold_ms" &
  stress_pids="$stress_pids $!"
  stress_index=$((stress_index + 1))
done
sleep "$stress_sample_delay"
stress_rss=$(awk '/^Rss:/ {print $2}' "/proc/$ftun_pid/smaps_rollup")
stress_pss=$(awk '/^Pss:/ {print $2}' "/proc/$ftun_pid/smaps_rollup")
stress_fds=$(find "/proc/$ftun_pid/fd" -mindepth 1 -maxdepth 1 | wc -l)
resource_limit_kib=${FTUN_RELEASE_RESOURCE_LIMIT_KIB:-65536}
fd_limit=${FTUN_RELEASE_FD_LIMIT:-256}
echo "production-concurrency flows=$stress_flows rss-kib=$stress_rss "\
"pss-kib=$stress_pss fds=$stress_fds"
if [ "$stress_rss" -gt "$resource_limit_kib" ] ||
   [ "$stress_pss" -gt "$resource_limit_kib" ] ||
   [ "$stress_fds" -gt "$fd_limit" ]; then
  echo "production concurrency resource threshold exceeded" >&2
  exit 1
fi
stress_failures=0
for stress_pid in $stress_pids; do
  if ! wait "$stress_pid"; then
    stress_failures=$((stress_failures + 1))
  fi
done
if [ "$stress_failures" -ne "$stress_expect_rejections" ]; then
  echo "unexpected connection admission result: failures=$stress_failures "\
"expected=$stress_expect_rejections" >&2
  exit 1
fi

# CI runs a short soak; release qualification can raise this without changing
# the scenario (the v1.0 evidence run uses FTUN_RELEASE_SOAK_SECONDS=60).
soak_seconds=${FTUN_RELEASE_SOAK_SECONDS:-5}
stage=bounded-soak
soak_start=$(date +%s)
while [ "$(($(date +%s) - soak_start))" -lt "$soak_seconds" ]; do
  "$helper_binary" --socks-client 11081 192.0.2.2:18080
  "$helper_binary" --socks-udp-client 11082 192.0.2.2:18081
  "$helper_binary" --dns-client 127.0.0.1 15353 192.0.2.2
  sleep 0.05
done

# A rejected reload must leave listeners and the active Runtime usable.
stage=invalid-reload-rollback
cp "$temporary/config.json" "$temporary/config.good"
sed 's/"expected-status":204/"expected-status":999/' \
  "$temporary/config.good" >"$temporary/config.next"
mv "$temporary/config.next" "$temporary/config.json"
kill -HUP "$ftun_pid"
attempt=0
while ! grep -q 'reload rejected' "$temporary/ftun.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "invalid reload was not rejected" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --socks-client 11081 192.0.2.2:18080
mv "$temporary/config.good" "$temporary/config.json"

# The first periodic update starts only after a complete interval and reuses
# the accepted baseline through If-None-Match/304.
stage=conditional-frs-update
attempt=0
while ! grep -q 'http-rules-conditional' "$temporary/peer.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 300 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "FRS conditional update was not observed" >&2
    exit 1
  fi
  sleep 0.01
done

# 普通 DNS 定义在 Runtime commit 前准备；保留地址复用 socket，同时允许
# 候选代先绑定新增地址并在提交后关闭已移除地址。
stage=dns-reload
sed -e 's/"default-server":"real"/"default-server":"fake"/' \
    -e 's/{"listen":"127.0.0.1:15355"}/{"listen":"127.0.0.1:15356"}/' \
  "$temporary/config.json" >"$temporary/config.next"
mv "$temporary/config.next" "$temporary/config.json"
kill -HUP "$ftun_pid"
attempt=0
while ! grep -q 'reload committed' "$temporary/ftun.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    sed -n '1,200p' "$temporary/ftun.log" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --dns-client 127.0.0.1 15356 198.18.0.1

if [ "${FTUN_RELEASE_ALLOW_FRS_RETRY_WARNINGS:-0}" != 1 ] &&
   grep -q 'FRS update failed' /tmp/ftun-release.log 2>/dev/null; then
  echo "conditional FRS update was reported as a failure" >&2
  exit 1
fi

stage=first-shutdown
kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

# 持久映射必须在优雅停止时快照，并在重启后保持同一域名地址身份。
stage=persistence-restart
"$ftun_binary" run -c "$temporary/config.json" \
  >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
attempt=0
while ! ip link show ftun-prod0 >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    sed -n '1,200p' "$temporary/ftun.log" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --dns-client 127.0.0.1 15354 198.18.0.1
stage=second-shutdown
kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

if ip link show ftun-prod0 >/dev/null 2>&1; then
  echo "production TUN leaked after shutdown" >&2
  exit 1
fi

# An existing corrupt local FRS is authoritative failure input and must not be
# silently repaired from the configured URL.
stage=corrupt-local-frs
: >"$temporary/rules.frs"
if "$ftun_binary" run -c "$temporary/config.json" \
    >"$temporary/ftun.log" 2>&1; then
  echo "corrupt local FRS unexpectedly started" >&2
  exit 1
fi

# 本地规则文件缺失且下载失败：不再启动失败（断网不退出），服务以 NOT_READY
# 持续运行并按退避重试，不产生半成品规则文件；SIGTERM 能正常停止。
stage=missing-frs-download-failure
rm -f "$temporary/rules.frs"
sed 's#http://frs.release.test:18082/redirect#http://frs.release.test:9/unavailable#' \
  "$temporary/config.json" >"$temporary/config.next"
mv "$temporary/config.next" "$temporary/config.json"
"$ftun_binary" run -c "$temporary/config.json" \
  >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 3
if ! kill -0 "$ftun_pid" 2>/dev/null; then
  echo "FRS download failure must not stop the service" >&2
  sed -n '1,200p' "$temporary/ftun.log" >&2
  exit 1
fi
if [ -e "$temporary/rules.frs" ]; then
  echo "failed FRS download left a rule file" >&2
  exit 1
fi
kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

# With FTUN DNS disabled, a required local DIRECT resolution uses the bounded
# SystemResolver path.  No TUN route is active in this scenario, so libc/NSS
# sockets cannot be captured back into FTUN.
stage=dns-disabled-system-resolver
"$helper_binary" --echo-server 127.0.0.1:18083 \
  "$temporary/local.ready" >"$temporary/local.log" 2>&1 &
local_pid=$!
attempt=0
while [ ! -f "$temporary/local.ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$local_pid" 2>/dev/null; then
    echo "local echo server did not become ready" >&2
    exit 1
  fi
  sleep 0.01
done
cat >"$temporary/config.json" <<EOF
{
  "base":{"state-cache":false},
  "log":{"level":"debug","file":"$temporary/ftun.log"},
  "dns":{"enable":false},
  "inbounds":[
    {"name":"system-socks","type":"socks5","listen":"127.0.0.1:11083","udp":true}
  ],
  "outbounds":[],
  "rules":["MATCH,DIRECT"]
}
EOF
"$ftun_binary" run -c "$temporary/config.json" \
  >>"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
attempt=0
while ! "$helper_binary" --socks-domain-client 11083 localhost:18083 \
    >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "DNS-disabled SystemResolver data path did not become ready" >&2
    exit 1
  fi
  sleep 0.01
done
kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=
kill -TERM "$local_pid"
wait "$local_pid"
local_pid=

#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 TEST_BINARY" >&2
  exit 2
fi

test_binary=$1

if [ "${FTUN_INTEGRATION_NAMESPACE:-0}" != 1 ]; then
  if ! unshare -Urn true >/dev/null 2>&1; then
    echo "isolated user/network namespaces unavailable" >&2
    exit 77
  fi
  exec env FTUN_INTEGRATION_NAMESPACE=1 unshare -Urnm sh "$0" "$test_binary"
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-integration.XXXXXX")
peer_pid=

cleanup()
{
  status=$?
  if [ -n "$peer_pid" ]; then
    kill -TERM "$peer_pid" >/dev/null 2>&1 || true
    wait "$peer_pid" || status=1
  fi
  umount /etc/resolv.conf >/dev/null 2>&1 || true
  ip netns del ftun-lan >/dev/null 2>&1 || true
  ip netns del ftun-peer >/dev/null 2>&1 || true
  rm -f "$temporary/ready" "$temporary/resolv.conf" "$temporary/peer.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

mount --make-rprivate /
ip link set lo up
ip netns add ftun-peer
ip netns add ftun-lan

ip link add phys0 type veth peer name peer0
ip link set peer0 netns ftun-peer
ip address add 192.0.2.1/24 dev phys0
ip -6 address add 2001:db8:1::1/64 dev phys0
ip link set phys0 up
ip netns exec ftun-peer ip link set lo up
ip netns exec ftun-peer ip link set peer0 up
ip netns exec ftun-peer ip address add 192.0.2.2/24 dev peer0
ip netns exec ftun-peer ip address add 192.0.2.53/24 dev peer0
ip netns exec ftun-peer ip -6 address add 2001:db8:1::2/64 dev peer0

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

printf 'nameserver 192.0.2.53\noptions timeout:1 attempts:1\n' \
  > "$temporary/resolv.conf"
mount --bind "$temporary/resolv.conf" /etc/resolv.conf

# libc/NSS 的隐藏 socket 不能继承 SO_MARK；为唯一 DNS 地址安装更高优先级的
# 专用 main-table 路径。后面的快照确认 FTUN 路由事务不会删除该外部资源。
ip rule add priority 12339 to 192.0.2.53/32 lookup main protocol 186

before_v4=$(ip -4 rule show)
before_v6=$(ip -6 rule show)
before_table=$(ip -4 route show table 100 2>/dev/null || true)

ip netns exec ftun-peer "$test_binary" --peer "$temporary/ready" \
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

"$test_binary" --run

after_v4=$(ip -4 rule show)
after_v6=$(ip -6 rule show)
after_table=$(ip -4 route show table 100 2>/dev/null || true)
[ "$after_v4" = "$before_v4" ]
[ "$after_v6" = "$before_v6" ]
[ "$after_table" = "$before_table" ]
if ip link show ftun-it0 >/dev/null 2>&1; then
  echo "TUN device leaked after integration shutdown" >&2
  exit 1
fi

#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FTUN INTEGRATION_HELPER" >&2
  exit 2
fi

ftun_binary=$1
helper_binary=$2
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-dns-fairness.XXXXXX")
hot_pid=
cold_pid=
echo_pid=
ftun_pid=
flood_pid=

cleanup()
{
  status=$?
  for process in "$flood_pid" "$ftun_pid" "$hot_pid" "$cold_pid" "$echo_pid"; do
    if [ -n "$process" ]; then
      kill -TERM "$process" >/dev/null 2>&1 || true
      wait "$process" >/dev/null 2>&1 || true
    fi
  done
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,80p' "$temporary/hot.log" >&2 || true
    sed -n '1,80p' "$temporary/cold.log" >&2 || true
    sed -n '1,80p' "$temporary/echo.log" >&2 || true
  fi
  rm -rf "$temporary"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

cat >"$temporary/config.json" <<EOF
{
  "base":{"state-cache":false},
  "log":{"level":"silent"},
  "dns":{
    "enable":true,
    "cache":true,
    "default-server":"cold",
    "listeners":[
      {"listen":"127.0.0.1:22557","server":"hot"},
      {"listen":"127.0.0.1:22558","server":"cold"},
      {"listen":"127.0.0.1:22559","server":"cold"}
    ],
    "servers":[
      {"name":"hot","type":"udp","address":["127.0.0.1:22057"],"outbound":"DIRECT"},
      {"name":"cold","type":"udp","address":["127.0.0.1:22058"],"outbound":"DIRECT"}
    ]
  },
  "inbounds":[{
    "name":"socks",
    "type":"socks5",
    "listen":"127.0.0.1:22685",
    "udp":true
  }],
  "rules":["MATCH,DIRECT"]
}
EOF

"$helper_binary" --dns-concurrency-server 127.0.0.1 22057 \
  "$temporary/hot.ready" "$temporary/hot.result" \
  >"$temporary/hot.log" 2>&1 &
hot_pid=$!
"$helper_binary" --dns-concurrency-server 127.0.0.1 22058 \
  "$temporary/cold.ready" "$temporary/cold.result" \
  >"$temporary/cold.log" 2>&1 &
cold_pid=$!
"$helper_binary" --echo-server 127.0.0.1:18085 \
  "$temporary/echo.ready" >"$temporary/echo.log" 2>&1 &
echo_pid=$!

attempt=0
while [ ! -f "$temporary/hot.ready" ] ||
      [ ! -f "$temporary/cold.ready" ] ||
      [ ! -f "$temporary/echo.ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] ||
     ! kill -0 "$hot_pid" 2>/dev/null ||
     ! kill -0 "$cold_pid" 2>/dev/null ||
     ! kill -0 "$echo_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done

"$ftun_binary" run -c "$temporary/config.json" >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"

"$helper_binary" --dns-flood-client 127.0.0.1 22557 6500 &
flood_pid=$!
sleep 0.1

# 第一监听器持续积压且达到每监听器上限时，冷监听器和 Proxy 仍需前进。
timeout 1 "$helper_binary" --dns-client 127.0.0.1 22558 127.0.0.4
timeout 1 "$helper_binary" --dns-client 127.0.0.1 22558 127.0.0.4
timeout 1 "$helper_binary" --dns-tcp-client 127.0.0.1 22558 127.0.0.4
timeout 1 "$helper_binary" --dns-isolation-client 127.0.0.1 22558 22559
timeout 1 "$helper_binary" --socks-client 22685 127.0.0.1:18085

# 首批 5 秒绝对截止时间到期后，持续热输入不能阻塞后续小流。
sleep 5.2
timeout 1 "$helper_binary" --dns-client 127.0.0.1 22558 127.0.0.4
timeout 1 "$helper_binary" --socks-client 22685 127.0.0.1:18085

wait "$flood_pid"
flood_pid=
kill -0 "$ftun_pid"

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=
kill -TERM "$hot_pid"
wait "$hot_pid"
hot_pid=
kill -TERM "$cold_pid"
wait "$cold_pid"
cold_pid=
kill -TERM "$echo_pid"
wait "$echo_pid"
echo_pid=

grep -q 'status=0$' "$temporary/hot.result"
grep -q '^slow=0 fast=0 shared=0 timeout=0 isolate=2 status=0$' \
  "$temporary/cold.result"

#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FTUN INTEGRATION_HELPER" >&2
  exit 2
fi

ftun_binary=$1
helper_binary=$2
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-dns-concurrency.XXXXXX")
server_pid=
ftun_pid=

cleanup()
{
  status=$?
  if [ -n "$ftun_pid" ]; then
    kill -TERM "$ftun_pid" >/dev/null 2>&1 || true
    wait "$ftun_pid" >/dev/null 2>&1 || status=1
  fi
  if [ -n "$server_pid" ]; then
    kill -TERM "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || status=1
  fi
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/server.log" >&2 || true
    sed -n '1,40p' "$temporary/result" >&2 || true
  fi
  rm -f "$temporary/config.json" "$temporary/ready" "$temporary/result" \
    "$temporary/ftun.log" "$temporary/server.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

cat >"$temporary/config.json" <<EOF
{
  "base":{"state-cache":false},
  "log":{"level":"silent"},
  "dns":{
    "enable":true,
    "cache":false,
    "default-server":"async",
    "listeners":[{"listen":"127.0.0.1:22553","server":"async"}],
    "servers":[{
      "name":"async",
      "type":"udp",
      "address":["127.0.0.1:22053"],
      "outbound":"DIRECT"
    }]
  },
  "inbounds":[{
    "name":"socks",
    "type":"socks5",
    "listen":"127.0.0.1:22681",
    "udp":true
  }],
  "rules":["MATCH,DIRECT"]
}
EOF

"$helper_binary" --dns-concurrency-server 127.0.0.1 22053 \
  "$temporary/ready" "$temporary/result" >"$temporary/server.log" 2>&1 &
server_pid=$!

attempt=0
while [ ! -f "$temporary/ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$server_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done

"$ftun_binary" run -c "$temporary/config.json" >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"

"$helper_binary" --dns-concurrency-client 127.0.0.1 22553

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=

grep -q '^slow=1 fast=1 shared=1 timeout=0 isolate=0 status=0$' \
  "$temporary/result"

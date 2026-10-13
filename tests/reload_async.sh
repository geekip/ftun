#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FTUN INTEGRATION_HELPER" >&2
  exit 2
fi

ftun_binary=$1
helper_binary=$2
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-reload-async.XXXXXX")
dns_pid=
echo_pid=
ftun_pid=

cleanup()
{
  status=$?
  if [ -n "$ftun_pid" ]; then
    kill -TERM "$ftun_pid" >/dev/null 2>&1 || true
    wait "$ftun_pid" >/dev/null 2>&1 || status=1
  fi
  if [ -n "$dns_pid" ]; then
    kill -TERM "$dns_pid" >/dev/null 2>&1 || true
    wait "$dns_pid" >/dev/null 2>&1 || status=1
  fi
  if [ -n "$echo_pid" ]; then
    kill -TERM "$echo_pid" >/dev/null 2>&1 || true
    wait "$echo_pid" >/dev/null 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/dns.log" >&2 || true
    sed -n '1,40p' "$temporary/result" >&2 || true
  fi
  rm -f "$temporary/config.json" "$temporary/config.next" \
    "$temporary/dns.ready" "$temporary/echo.ready" "$temporary/result" \
    "$temporary/ftun.log" "$temporary/dns.log" "$temporary/echo.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

write_config()
{
  upstream=$1
  cat >"$temporary/config.next" <<EOF
{
  "base":{"state-cache":false},
  "log":{"level":"silent"},
  "dns":{
    "enable":true,
    "cache":false,
    "bootstrap":["127.0.0.1:22054"],
    "default-server":"reload",
    "listeners":[{"listen":"127.0.0.1:22554","server":"reload"}],
    "servers":[{
      "name":"reload",
      "type":"udp",
      "address":["$upstream"],
      "outbound":"DIRECT"
    }]
  },
  "inbounds":[{
    "name":"socks",
    "type":"socks5",
    "listen":"127.0.0.1:22682",
    "udp":true
  }],
  "rules":["MATCH,DIRECT"]
}
EOF
  mv "$temporary/config.next" "$temporary/config.json"
}

"$helper_binary" --dns-concurrency-server 127.0.0.1 22054 \
  "$temporary/dns.ready" "$temporary/result" >"$temporary/dns.log" 2>&1 &
dns_pid=$!
"$helper_binary" --echo-server 127.0.0.1:22080 "$temporary/echo.ready" \
  >"$temporary/echo.log" 2>&1 &
echo_pid=$!

attempt=0
while [ ! -f "$temporary/dns.ready" ] || [ ! -f "$temporary/echo.ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$dns_pid" 2>/dev/null ||
     ! kill -0 "$echo_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done

write_config 127.0.0.1:22054
"$ftun_binary" run -c "$temporary/config.json" >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"
"$helper_binary" --socks-client 22682 127.0.0.1:22080

# Resolving slow.example deliberately takes 700 ms in the bootstrap server.
# Existing data-plane work must continue while the reload worker prepares it.
write_config slow.example:22054
"$ftun_binary" reload "$ftun_pid"
sleep 0.05
started=$(date +%s%3N)
"$helper_binary" --socks-client 22682 127.0.0.1:22080
finished=$(date +%s%3N)
elapsed=$((finished - started))
if [ "$elapsed" -ge 500 ]; then
  echo "data plane stalled during reload prepare: elapsed-ms=$elapsed" >&2
  exit 1
fi

attempt=0
while ! grep -q 'reload committed' "$temporary/ftun.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "asynchronous reload did not commit" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --dns-client 127.0.0.1 22554 127.0.0.4

# A timed-out candidate is also prepared off-owner.  It must neither stall the
# old data plane nor replace the committed DNS/Runtime generation.
write_config timeout.example:22054
"$ftun_binary" reload "$ftun_pid"
sleep 0.05
started=$(date +%s%3N)
"$helper_binary" --socks-client 22682 127.0.0.1:22080
finished=$(date +%s%3N)
elapsed=$((finished - started))
if [ "$elapsed" -ge 500 ]; then
  echo "data plane stalled during failed reload prepare: elapsed-ms=$elapsed" >&2
  exit 1
fi
attempt=0
while ! grep -q 'reload rejected' "$temporary/ftun.log"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 700 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "timed-out asynchronous reload was not rejected" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --dns-client 127.0.0.1 22554 127.0.0.4

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=
kill -TERM "$dns_pid"
wait "$dns_pid"
dns_pid=
kill -TERM "$echo_pid"
wait "$echo_pid" >/dev/null 2>&1 || true
echo_pid=

grep -q '^slow=1 fast=0 shared=0 timeout=1 status=0$' "$temporary/result"

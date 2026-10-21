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
dns_client_pid=
echo_pid=
ftun_pid=

# Reserve distinct loopback ports for this process instead of relying on
# machine-global fixed ports.  The previous fixed echo port could collide with
# unrelated services and fail before the test created its FTUN log.
ports=$(python3 - <<'PY'
import socket

sockets = []
ports = []
try:
    # DNS upstream and FTUN DNS listener need UDP ports.
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
        ports.append(sock.getsockname()[1])
    # The echo fixture uses TCP and UDP on one port.
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    echo_port = tcp.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", echo_port))
    sockets.extend((tcp, udp))
    ports.append(echo_port)
    # SOCKS uses TCP.
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.bind(("127.0.0.1", 0))
    sockets.append(socks)
    ports.append(socks.getsockname()[1])
    print(*ports)
finally:
    for sock in sockets:
        sock.close()
PY
)
set -- $ports
dns_upstream_port=$1
dns_listener_port=$2
echo_port=$3
socks_port=$4

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
  if [ -n "$dns_client_pid" ]; then
    kill -TERM "$dns_client_pid" >/dev/null 2>&1 || true
    wait "$dns_client_pid" >/dev/null 2>&1 || true
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
    "bootstrap":["127.0.0.1:$dns_upstream_port"],
    "default-server":"reload",
    "listeners":[{"listen":"127.0.0.1:$dns_listener_port","server":"reload"}],
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
    "listen":"127.0.0.1:$socks_port",
    "udp":true
  }],
  "rules":["MATCH,DIRECT"]
}
EOF
  mv "$temporary/config.next" "$temporary/config.json"
}

"$helper_binary" --dns-concurrency-server 127.0.0.1 "$dns_upstream_port" \
  "$temporary/dns.ready" "$temporary/result" >"$temporary/dns.log" 2>&1 &
dns_pid=$!
"$helper_binary" --echo-server "127.0.0.1:$echo_port" "$temporary/echo.ready" \
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

write_config "127.0.0.1:$dns_upstream_port"
"$ftun_binary" run -c "$temporary/config.json" >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"
"$helper_binary" --socks-client "$socks_port" "127.0.0.1:$echo_port"

# Resolving slow.example deliberately takes 700 ms in the bootstrap server.
# Existing data-plane work must continue while the reload worker prepares it.
write_config "slow.example:$dns_upstream_port"
"$ftun_binary" reload "$ftun_pid"
sleep 0.05
started=$(date +%s%3N)
"$helper_binary" --socks-client "$socks_port" "127.0.0.1:$echo_port"
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
"$helper_binary" --dns-client 127.0.0.1 "$dns_listener_port" 127.0.0.4

# A slow DNS request accepted by the old generation crosses a second reload.
# The new listener is published immediately; the quiesced old DNS instance
# retains its UDP reply socket until that request completes under the old
# configuration, then it is reclaimed before the client sends the shared pair.
committed_before=$(grep -c 'reload committed' "$temporary/ftun.log" || true)
"$helper_binary" --dns-concurrency-client 127.0.0.1 "$dns_listener_port" &
dns_client_pid=$!
sleep 0.1
write_config "127.0.0.1:$dns_upstream_port"
"$ftun_binary" reload "$ftun_pid"
attempt=0
while [ "$(grep -c 'reload committed' "$temporary/ftun.log" || true)" \
        -le "$committed_before" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "reload with an old in-flight DNS request did not commit" >&2
    kill "$dns_client_pid" >/dev/null 2>&1 || true
    wait "$dns_client_pid" >/dev/null 2>&1 || true
    exit 1
  fi
  sleep 0.01
done
if ! wait "$dns_client_pid"; then
  echo "old-generation DNS request did not finish after reload" >&2
  exit 1
fi
dns_client_pid=

# A timed-out candidate is also prepared off-owner.  It must neither stall the
# old data plane nor replace the committed DNS/Runtime generation.
write_config "timeout.example:$dns_upstream_port"
"$ftun_binary" reload "$ftun_pid"
sleep 0.05
started=$(date +%s%3N)
"$helper_binary" --socks-client "$socks_port" "127.0.0.1:$echo_port"
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
"$helper_binary" --dns-client 127.0.0.1 "$dns_listener_port" 127.0.0.4

# A FIFO keeps the production config loader blocked in open() indefinitely.
# The owner and the committed data plane belong to a separate execution domain,
# so a real SOCKS exchange must still finish before the latency bound.
# Opening and closing the FIFO writer releases the worker; the reader rejects
# the non-regular file before parsing, so no payload write can race a closed
# read end and terminate this harness with SIGPIPE.
rejected_before=$(grep -c 'reload rejected' "$temporary/ftun.log" || true)
rm -f "$temporary/config.json"
mkfifo "$temporary/config.json"
"$ftun_binary" reload "$ftun_pid"
sleep 0.05
started=$(date +%s%3N)
"$helper_binary" --socks-client "$socks_port" "127.0.0.1:$echo_port"
finished=$(date +%s%3N)
elapsed=$((finished - started))
if [ "$elapsed" -ge 500 ]; then
  echo "data plane stalled during stuck file reload: elapsed-ms=$elapsed" >&2
  exit 1
fi
: >"$temporary/config.json"
write_config "127.0.0.1:$dns_upstream_port"
attempt=0
while [ "$(grep -c 'reload rejected' "$temporary/ftun.log" || true)" \
        -le "$rejected_before" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 200 ] || ! kill -0 "$ftun_pid" 2>/dev/null; then
    echo "late stuck-file reload result was not rejected" >&2
    exit 1
  fi
  sleep 0.01
done
"$helper_binary" --socks-client "$socks_port" "127.0.0.1:$echo_port"

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=
kill -TERM "$dns_pid"
wait "$dns_pid"
dns_pid=
kill -TERM "$echo_pid"
wait "$echo_pid" >/dev/null 2>&1 || true
echo_pid=

grep -q '^slow=2 fast=1 shared=1 timeout=1 isolate=0 status=0$' \
  "$temporary/result"

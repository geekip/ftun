#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 FTUN INTEGRATION_HELPER" >&2
  exit 2
fi

ftun_binary=$1
helper_binary=$2
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config_file=$script_directory/fixtures/socket-inbounds.json
tun_config_file=$script_directory/fixtures/tun-no-capability.json
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-socket.XXXXXX")
echo_pid=
dns_pid=
stall_pid=
ftun_pid=

cleanup()
{
  status=$?
  if [ -n "$ftun_pid" ]; then
    kill -TERM "$ftun_pid" >/dev/null 2>&1 || true
    wait "$ftun_pid" || status=1
  fi
  if [ -n "$echo_pid" ]; then
    kill -TERM "$echo_pid" >/dev/null 2>&1 || true
    wait "$echo_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$dns_pid" ]; then
    kill -TERM "$dns_pid" >/dev/null 2>&1 || true
    wait "$dns_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$stall_pid" ]; then
    kill -TERM "$stall_pid" >/dev/null 2>&1 || true
    wait "$stall_pid" >/dev/null 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/echo.log" >&2 || true
  fi
  rm -f "$temporary/ready" "$temporary/dns.ready" "$temporary/ftun.log" \
    "$temporary/echo.log" "$temporary/dns.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$helper_binary" --echo-server 127.0.0.1:18080 "$temporary/ready" \
  >"$temporary/echo.log" 2>&1 &
echo_pid=$!

"$helper_binary" --dns-server 127.0.0.1 18053 "$temporary/dns.ready" \
  >"$temporary/dns.log" 2>&1 &
dns_pid=$!

attempt=0
while [ ! -f "$temporary/ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$echo_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done
attempt=0
while [ ! -f "$temporary/dns.ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$dns_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done

ordinary_user=0
if [ "$(id -u)" -eq 0 ] && command -v setpriv >/dev/null 2>&1; then
  ordinary_user=1
  setpriv --reuid=nobody --regid=nogroup --clear-groups --no-new-privs \
    sh -c 'ulimit -n 48; exec "$1" run -c "$2"' sh \
    "$ftun_binary" "$config_file" \
    >"$temporary/ftun.log" 2>&1 &
else
  sh -c 'ulimit -n 48; exec "$1" run -c "$2"' sh \
    "$ftun_binary" "$config_file" \
    >"$temporary/ftun.log" 2>&1 &
fi
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"
if [ "$ordinary_user" -eq 1 ]; then
  if [ "$(awk '/^Uid:/ {print $2}' "/proc/$ftun_pid/status")" -ne 65534 ] ||
     ! grep -q '^CapEff:[[:space:]]*0000000000000000$' \
       "/proc/$ftun_pid/status"; then
    echo "socket-only FTUN did not run as an unprivileged process" >&2
    exit 1
  fi
fi

"$helper_binary" --socks-client 21081 127.0.0.1:18080
"$helper_binary" --socks-udp-client 21081 127.0.0.1:18080
"$helper_binary" --socks-udp-client 21082 127.0.0.1:18080
"$helper_binary" --mixed-connect-client 21082 127.0.0.1:18080
"$helper_binary" --mixed-forward-client 21082 127.0.0.1:18080
"$helper_binary" --dns-client 127.0.0.1 21553 127.0.0.1

# A partial SOCKS greeting must not retain a shared flow slot forever.  Keep a
# healthy connection moving while the absolute 10 s handshake deadline fires.
"$helper_binary" --socks-stall-client 21081 11000 &
stall_pid=$!
sleep 0.1
"$helper_binary" --socks-client 21081 127.0.0.1:18080
wait "$stall_pid"
stall_pid=

# Fill the daemon's deliberately low FD limit with incomplete connections.
# EMFILE must pause accept, preserve the process, and recover after release.
"$helper_binary" --tcp-hold-clients 21081 64 1000
kill -0 "$ftun_pid"
sleep 2
"$helper_binary" --socks-client 21081 127.0.0.1:18080

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

if [ "$ordinary_user" -eq 1 ]; then
  set +e
  timeout 5 setpriv --reuid=nobody --regid=nogroup --clear-groups \
    --no-new-privs "$ftun_binary" run -c "$tun_config_file" \
    >>"$temporary/ftun.log" 2>&1
  tun_status=$?
  set -e
  if [ "$tun_status" -eq 0 ] || [ "$tun_status" -eq 124 ]; then
    echo "unprivileged TUN did not fail during startup" >&2
    exit 1
  fi
fi

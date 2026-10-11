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
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-socket.XXXXXX")
echo_pid=
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
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/echo.log" >&2 || true
  fi
  rm -f "$temporary/ready" "$temporary/ftun.log" "$temporary/echo.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$helper_binary" --echo-server 127.0.0.1:18080 "$temporary/ready" \
  >"$temporary/echo.log" 2>&1 &
echo_pid=$!

attempt=0
while [ ! -f "$temporary/ready" ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ] || ! kill -0 "$echo_pid" 2>/dev/null; then
    exit 1
  fi
  sleep 0.01
done

"$ftun_binary" run -c "$config_file" \
  >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.1
kill -0 "$ftun_pid"

"$helper_binary" --socks-client 21081 127.0.0.1:18080
"$helper_binary" --socks-udp-client 21081 127.0.0.1:18080
"$helper_binary" --socks-udp-client 21082 127.0.0.1:18080
"$helper_binary" --mixed-connect-client 21082 127.0.0.1:18080
"$helper_binary" --mixed-forward-client 21082 127.0.0.1:18080

kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

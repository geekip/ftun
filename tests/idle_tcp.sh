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
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ftun-idle.XXXXXX")
echo_pid=
ftun_pid=
client_pid=

cleanup()
{
  status=$?
  for process in "$client_pid" "$ftun_pid" "$echo_pid"; do
    if [ -n "$process" ]; then
      kill -TERM "$process" >/dev/null 2>&1 || true
      wait "$process" >/dev/null 2>&1 || true
    fi
  done
  if [ "$status" -ne 0 ]; then
    sed -n '1,200p' "$temporary/ftun.log" >&2 || true
    sed -n '1,200p' "$temporary/echo.log" >&2 || true
  fi
  rm -f "$temporary/ready" "$temporary/ftun.log" "$temporary/echo.log"
  rmdir "$temporary" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

process_ticks()
{
  awk '{print $14 + $15}' "/proc/$1/stat"
}

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

"$ftun_binary" run -c "$config_file" >"$temporary/ftun.log" 2>&1 &
ftun_pid=$!
sleep 0.2
kill -0 "$ftun_pid"

baseline_start=$(process_ticks "$ftun_pid")
sleep 2
baseline_end=$(process_ticks "$ftun_pid")
baseline_ticks=$((baseline_end - baseline_start))

"$helper_binary" --socks-hold-client 21081 127.0.0.1:18080 65000 &
client_pid=$!
sleep 0.2
kill -0 "$client_pid"
idle_start=$(process_ticks "$ftun_pid")
sleep 60
idle_end=$(process_ticks "$ftun_pid")
idle_ticks=$((idle_end - idle_start))
kill -0 "$ftun_pid"

# 允许相对空载基线每秒多 0.5% 单核 CPU，且至少留两个 tick 的采样余量。
clock_ticks=$(getconf CLK_TCK)
allowed_ticks=$((baseline_ticks * 30 + clock_ticks * 60 / 200 + 2))
echo "idle-tcp baseline-2s-ticks=$baseline_ticks idle-60s-ticks=$idle_ticks allowed=$allowed_ticks"
if [ "$idle_ticks" -gt "$allowed_ticks" ]; then
  echo "idle TCP CPU exceeded the no-connection baseline" >&2
  exit 1
fi

kill -TERM "$client_pid" >/dev/null 2>&1 || true
wait "$client_pid" >/dev/null 2>&1 || true
client_pid=
kill -TERM "$ftun_pid"
wait "$ftun_pid"
ftun_pid=

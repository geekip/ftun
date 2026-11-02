#!/bin/sh
set -eu

ftun_binary=$1
test_directory=$(mktemp -d /tmp/ftun-cli-v05.XXXXXX)
process_id=

cleanup() {
  if [ -n "$process_id" ] && kill -0 "$process_id" 2>/dev/null; then
    kill -TERM "$process_id" 2>/dev/null || true
    wait "$process_id" 2>/dev/null || true
  fi
  rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

config_path=$test_directory/run.json
cache_path=$test_directory/state.cache
sed \
  -e "s|@CACHE@|$cache_path|g" \
  "$2" > "$config_path"

"$ftun_binary" check -c "$config_path" > "$test_directory/check.out"
grep -q "configuration OK" "$test_directory/check.out"
if "$ftun_binary" check -c "$test_directory/missing.json" >/dev/null 2>&1; then
  exit 1
fi

"$ftun_binary" run -c "$config_path" -p "$config_path.pid" \
  > "$test_directory/run.out" 2> "$test_directory/run.err" &
process_id=$!
sleep 0.1
kill -0 "$process_id" || { cat "$test_directory/run.err" >&2; exit 1; }
"$ftun_binary" reload -p "$config_path.pid" 2> "$test_directory/reload.err"
grep -q "committed" "$test_directory/reload.err"

"$ftun_binary" stop -p "$config_path.pid"
wait "$process_id"
process_id=

#!/bin/sh
set -eu

ftun_binary=$1
dns_enabled=$2
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
  "$3" > "$config_path"

"$ftun_binary" check -c "$config_path" > "$test_directory/check.out"
grep -q "configuration OK" "$test_directory/check.out"
if "$ftun_binary" check -c "$test_directory/missing.json" >/dev/null 2>&1; then
  exit 1
fi

"$ftun_binary" run -c "$config_path" \
  > "$test_directory/run.out" 2> "$test_directory/run.err" &
process_id=$!
sleep 0.1
kill -0 "$process_id"
"$ftun_binary" reload "$process_id"

attempt=0
while ! grep -q "reload committed" "$test_directory/run.err"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    exit 1
  fi
  sleep 0.02
done

"$ftun_binary" stop "$process_id"
wait "$process_id"
process_id=

if [ "$dns_enabled" = 1 ]; then
  fake_config=$test_directory/fakeip.json
  fake_cache=$test_directory/fake.cache
  sed \
    -e "s|@CACHE@|$fake_cache|g" \
    "$4" > "$fake_config"
  "$ftun_binary" fakeip init -c "$fake_config" \
    > "$test_directory/fakeip.out"
  test -s "$fake_cache.fakeip/identity"
  test -s "$fake_cache.fakeip/reservations"
  test -s "$fake_cache.fakeip/mappings"
  test -f "$fake_cache.fakeip/lock"
  if "$ftun_binary" fakeip init -c "$fake_config" >/dev/null 2>&1; then
    exit 1
  fi
fi

#!/usr/bin/env bash
set -euo pipefail

binary=${1:?binary path required}
config=${2:?config path required}
log=${3:-/tmp/ipm-mysql-smoke.log}

"$binary" --config "$config" >"$log" 2>&1 &
pid=$!
cleanup() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:18787/login >/dev/null; then
    echo MYSQL_SMOKE_HTTP_OK
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo MYSQL_SMOKE_PROCESS_EXITED
    sed -n '1,160p' "$log"
    exit 1
  fi
  sleep 1
done

echo MYSQL_SMOKE_TIMEOUT
sed -n '1,160p' "$log"
exit 1

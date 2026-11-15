#!/usr/bin/env bash
# Disposable database only. Never uses or migrates a configured development DB.
set -euo pipefail
cd "$(dirname "$0")/.."
container="android-engine-tests-$$"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
docker run --rm -d --name "$container" -e POSTGRES_PASSWORD=fixture-only \
  -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
for attempt in {1..60}; do
  if docker exec "$container" pg_isready -U postgres >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$container" pg_isready -U postgres >/dev/null
docker exec "$container" createdb -U postgres assessment_tests
address=$(docker port "$container" 5432/tcp)
export ANDROIDLAB_PG_DSN="postgres://postgres:fixture-only@${address}/assessment_tests?sslmode=disable"
export ANDROIDLAB_TEST_PG_DSN="$ANDROIDLAB_PG_DSN"
if (( $# == 0 )); then set -- ./...; fi
go test -p 1 -count=1 "$@"

#!/usr/bin/env bash
# Runs the integration test against a real Vaultwarden on each database engine:
# Vaultwarden runs its migrations (real schema), its API produces the events,
# the exporter reads them back. Requires docker and go; run it from the
# repository root. Usage: integration.sh [postgresql|mysql|sqlite]...
set -euo pipefail

VAULTWARDEN_IMAGE="${VAULTWARDEN_IMAGE:-vaultwarden/server:1.37.5-alpine}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:17-alpine}"
MARIADB_IMAGE="${MARIADB_IMAGE:-mariadb:11}"
engines=("$@")
[ ${#engines[@]} -eq 0 ] && engines=(postgresql mysql sqlite)

net="vwexp-it-$$"
work=$(mktemp -d)
cleanup() {
  docker rm -f "vw-$$" "db-$$" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  # sqlite data written by the container user
  docker run --rm -v "$work:/w" alpine:3 rm -rf /w/data >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
docker network create "$net" >/dev/null

wait_http() {
  local url=$1
  for _ in $(seq 1 90); do
    curl -fsS "$url" >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "timeout waiting for $url" >&2
  docker logs "vw-$$" 2>&1 | tail -30 >&2 || true
  return 1
}

wait_db() {
  for _ in $(seq 1 60); do
    if docker exec "db-$$" sh -c "$1" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "database did not start" >&2
  return 1
}

for engine in "${engines[@]}"; do
  echo "== $engine"
  docker rm -f "vw-$$" "db-$$" >/dev/null 2>&1 || true
  vw_env=(-e ORG_EVENTS_ENABLED=true -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false -e DOMAIN=http://localhost
          -e I_REALLY_WANT_VOLATILE_STORAGE=true)
  vw_args=()
  case "$engine" in
    postgresql)
      docker run -d --name "db-$$" --network "$net" -p 127.0.0.1::5432 \
        -e POSTGRES_USER=vw -e POSTGRES_PASSWORD=vw -e POSTGRES_DB=vaultwarden "$POSTGRES_IMAGE" >/dev/null
      wait_db "pg_isready -U vw -d vaultwarden"
      port=$(docker port "db-$$" 5432/tcp | head -n1 | cut -d: -f2)
      vw_env+=(-e "DATABASE_URL=postgresql://vw:vw@db-$$:5432/vaultwarden")
      db_url="postgresql://vw:vw@127.0.0.1:${port}/vaultwarden"
      ;;
    mysql)
      docker run -d --name "db-$$" --network "$net" -p 127.0.0.1::3306 \
        -e MARIADB_USER=vw -e MARIADB_PASSWORD=vw -e MARIADB_DATABASE=vaultwarden \
        -e MARIADB_RANDOM_ROOT_PASSWORD=1 "$MARIADB_IMAGE" >/dev/null
      wait_db "mariadb-admin ping -h 127.0.0.1 -uvw -pvw"
      port=$(docker port "db-$$" 3306/tcp | head -n1 | cut -d: -f2)
      vw_env+=(-e "DATABASE_URL=mysql://vw:vw@db-$$:3306/vaultwarden")
      db_url="mysql://vw:vw@127.0.0.1:${port}/vaultwarden"
      ;;
    sqlite)
      mkdir -p "$work/data" && chmod 777 "$work/data"
      vw_args+=(-v "$work/data:/data")
      db_url="sqlite://$work/data/db.sqlite3"
      ;;
    *) echo "unknown engine $engine" >&2; exit 2 ;;
  esac

  docker run -d --name "vw-$$" --network "$net" -p 127.0.0.1::80 "${vw_env[@]}" "${vw_args[@]}" "$VAULTWARDEN_IMAGE" >/dev/null
  vw_port=$(docker port "vw-$$" 80/tcp | head -n1 | cut -d: -f2)
  wait_http "http://127.0.0.1:${vw_port}/alive"

  if [ "$engine" = postgresql ]; then
    # The exporter runs with the documented read-only role, not the owner: a
    # missing grant fails the test (up=0 / ERROR logs)
    docker cp deployments/sql/postgresql-readonly.sql "db-$$:/tmp/readonly.sql"
    docker exec "db-$$" psql -q -v ON_ERROR_STOP=1 -U vw -d vaultwarden -v password="'readonly'" -f /tmp/readonly.sql
    db_url="postgresql://vw_exporter:readonly@127.0.0.1:${port}/vaultwarden"
    echo "exporter connects as the read-only role vw_exporter"
  fi

  IT_VAULTWARDEN_URL="http://127.0.0.1:${vw_port}" IT_DATABASE_URL="$db_url" \
    go test -tags integration -count=1 -run TestIntegration -v ./cmd/vaultwarden-exporter/ 2>&1 | tail -40
  test "${PIPESTATUS[0]}" -eq 0
done
echo "integration tests passed: ${engines[*]}"

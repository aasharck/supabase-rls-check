#!/bin/sh
# Starts a throwaway Postgres in a temp folder, loads demo/seed.sql, runs the given
# command with DATABASE_URL set, then stops and deletes it. Needs initdb/pg_ctl on PATH
# (e.g. `brew install postgresql@16`). Nothing touches a real database.
set -eu
# macOS Postgres refuses to start without a valid locale ("postmaster became multithreaded").
export LC_ALL=C

if ! command -v initdb >/dev/null 2>&1; then
  for d in /opt/homebrew/opt/postgresql@16/bin /usr/local/opt/postgresql@16/bin /usr/lib/postgresql/16/bin; do
    [ -x "$d/initdb" ] && PATH="$d:$PATH" && break
  done
fi
command -v initdb >/dev/null 2>&1 || { echo "initdb not found. Install Postgres 15+ (brew install postgresql@16)."; exit 2; }

# Short path: Unix socket paths are limited to ~100 characters.
DIR=$(mktemp -d "${TMPDIR:-/tmp}/rls.XXXXXX" 2>/dev/null || mktemp -d /tmp/rls.XXXXXX)
[ ${#DIR} -gt 80 ] && DIR=$(mktemp -d /tmp/rls.XXXXXX)
PORT=${PGPORT_DEMO:-54329}
cleanup() { pg_ctl -D "$DIR/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$DIR"; }
trap cleanup EXIT INT TERM

initdb -D "$DIR/data" -U postgres -A trust --no-locale -E UTF8 >/dev/null
pg_ctl -D "$DIR/data" -o "-p $PORT -k $DIR -c listen_addresses=''" -l "$DIR/log" -w start >/dev/null || { cat "$DIR/log"; exit 1; }
psql -h "$DIR" -p "$PORT" -U postgres -q -v ON_ERROR_STOP=1 -f demo/seed.sql postgres >/dev/null

export DATABASE_URL="postgresql://postgres@localhost/postgres?host=$DIR&port=$PORT"
"$@"

#!/usr/bin/env sh
set -eu

if [ -n "${WATCHTOWER_NEO4J_PASSWORD_FILE:-}" ]; then
  if [ ! -r "$WATCHTOWER_NEO4J_PASSWORD_FILE" ]; then
    echo "WatchTower Neo4j password secret is unavailable" >&2
    exit 64
  fi
  export NEO4J_AUTH="neo4j/$(tr -d '\r\n' < "$WATCHTOWER_NEO4J_PASSWORD_FILE")"
fi

exec /startup/docker-entrypoint.sh neo4j

#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-start}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$command_name" in
  start|restart|stop|status|logs|repair) ;;
  *)
    printf 'Usage: ./watchtower.sh {start|stop|restart|status|logs|repair}\n' >&2
    exit 2
    ;;
esac

cd "$root"

run_container() {
  ./scripts/container.sh "$1" --with-mesh --linux-sensor
}

case "$command_name" in
  start)
    run_container init
    run_container up
    printf '\nWatchTower is ready at http://127.0.0.1:4173\n'
    printf 'Select a capture interface in the UI or use .venv/bin/tower.\n'
    ;;
  stop)
    run_container down
    ;;
  restart)
    run_container down
    run_container up
    printf '\nWatchTower restarted at http://127.0.0.1:4173\n'
    ;;
  status)
    run_container status
    ;;
  logs)
    run_container logs
    ;;
  repair)
    run_container down
    run_container init
    run_container up
    printf '\nWatchTower runtime configuration was rebuilt.\n'
    ;;
esac

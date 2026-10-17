#!/usr/bin/env bash

watchtower_assert_stopped() {
  local requested_root="${1:-}"
  if [[ "$requested_root" != /* ]]; then
    echo "Setup could not safely inspect running processes: repository root is unavailable. Setup made no changes." >&2
    return 1
  fi
  local root="${requested_root%/}"

  if ! command -v ps >/dev/null 2>&1; then
    echo "Setup could not safely inspect running processes: 'ps' is unavailable. Close WatchTower and rerun setup. Setup made no changes." >&2
    return 1
  fi

  local processes
  if ! processes="$(ps -eo pid=,args= 2>&1)"; then
    echo "Setup could not safely inspect running processes: ps failed (${processes}). Close WatchTower and rerun setup. Setup made no changes." >&2
    return 1
  fi
  if [[ -z "${processes//[[:space:]]/}" ]]; then
    echo "Setup could not safely inspect running processes: ps returned no process records. Close WatchTower and rerun setup. Setup made no changes." >&2
    return 1
  fi

  local line pid args
  local -a active_pids=()
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r pid args <<< "$line"
    [[ -n "${pid:-}" && -n "${args:-}" ]] || continue
    case "$args" in
      *"$root/ui/.output/server/index.mjs"*|\
      *"$root/ui/node_modules/.bin/vite"*|\
      *"$root/ui/node_modules/vite/bin/vite.js"*|\
      *"$root/.venv/bin/tower ui"*|\
      *"$root/.venv/bin/python"*"core.api.server"*|\
      *"$root/.venv/bin/python"*"core.daemon.server"*|\
      *"$root/rust/watchtower-sensor/target/"*|\
      *"$root/watchtower-sensor"*)
        active_pids+=("$pid")
        ;;
    esac
  done <<< "$processes"

  if ((${#active_pids[@]} > 0)); then
    local joined
    printf -v joined '%s, ' "${active_pids[@]}"
    joined="${joined%, }"
    echo "WatchTower processes from this checkout are still running (PID(s): $joined). Close WatchTower and rerun setup. Setup made no changes." >&2
    return 1
  fi
  return 0
}

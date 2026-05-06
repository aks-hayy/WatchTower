#!/usr/bin/env bash
# =============================================================================
#  dev_cleanup.sh — Kill orphaned dev processes, daemons, and stale listeners
#
#  Usage:
#    ./dev_cleanup.sh           # interactive (asks before killing each group)
#    ./dev_cleanup.sh --dry-run # print what would be killed, touch nothing
#    ./dev_cleanup.sh --force   # kill everything matched, no prompts
#    ./dev_cleanup.sh --port 3000 5173   # only clean specific ports
#
#  What it hunts:
#    • Dev servers     : vite, webpack-dev-server, react-scripts, next dev,
#                        parcel, snowpack, esbuild serve, turbopack
#    • Runtime servers : node, nodemon, ts-node, tsx, bun dev, deno
#    • Language daemons: Python servers (uvicorn, gunicorn, flask, django, fastapi)
#    • Build watchers  : tsc --watch, sass --watch, postcss --watch, rollup -w
#    • Test runners    : jest --watch, vitest, mocha, pytest-watch, karma
#    • Tunnel/proxy    : ngrok, localtunnel, caddy, mitmproxy
#    • DB dev servers  : redis-server (non-system), mongod (non-system)
#    • Misc orphans    : any process whose parent is PID 1 (re-parented to init)
#                        and matches known dev binary patterns
#    • Stale port listeners on common dev ports
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Colour palette ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YLW='\033[0;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; DIM='\033[2m';    BLD='\033[1m';    RST='\033[0m'

# ── Flags ─────────────────────────────────────────────────────────────────────
DRY_RUN=false
FORCE=false
SPECIFIC_PORTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true ;;
    --force)   FORCE=true ;;
    --port)    shift; while [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; do SPECIFIC_PORTS+=("$1"); shift; done; continue ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \?//' | head -20
      exit 0 ;;
  esac
  shift
done

# ── Helpers ───────────────────────────────────────────────────────────────────
KILLED=0
SKIPPED=0
LOG_FILE="/tmp/dev_cleanup_$(date +%Y%m%d_%H%M%S).log"

log()  { echo -e "$1" | tee -a "$LOG_FILE"; }
info() { log "${CYN}  →${RST} $1"; }
ok()   { log "${GRN}  ✓${RST} $1"; }
warn() { log "${YLW}  !${RST} $1"; }
die()  { log "${RED}  ✗${RST} $1"; }
sep()  { log "${DIM}──────────────────────────────────────────────────${RST}"; }

# Check if we're on macOS or Linux
OS="$(uname -s)"
MY_PID=$$
MY_PPID=$PPID

# Safe kill: never kill this script, its parent, or PID 1
safe_kill() {
  local pid="$1"
  local sig="${2:-TERM}"
  [[ "$pid" == "$MY_PID" || "$pid" == "$MY_PPID" || "$pid" == "1" ]] && return 0
  if $DRY_RUN; then
    warn "[DRY-RUN] Would send SIG${sig} to PID ${pid}"
    return 0
  fi
  if kill "-${sig}" "$pid" 2>/dev/null; then
    (( KILLED++ )) || true
    return 0
  fi
  return 1
}

# Ask user if not in force mode
ask_kill() {
  local label="$1"; shift
  local pids=("$@")
  [[ ${#pids[@]} -eq 0 ]] && return

  log ""
  log "${BLD}${YLW}  Found: ${label}${RST}"
  for pid in "${pids[@]}"; do
    local cmd
    if [[ "$OS" == "Darwin" ]]; then
      cmd=$(ps -p "$pid" -o pid=,command= 2>/dev/null || echo "gone")
    else
      cmd=$(ps -p "$pid" -o pid=,cmd= 2>/dev/null || echo "gone")
    fi
    info "  PID ${pid}  ${DIM}${cmd}${RST}"
  done

  if $FORCE || $DRY_RUN; then
    kill_group "$label" "${pids[@]}"
    return
  fi

  printf "${YLW}  Kill these? [y/N] ${RST}"
  read -r answer </dev/tty
  if [[ "$answer" =~ ^[Yy] ]]; then
    kill_group "$label" "${pids[@]}"
  else
    (( SKIPPED += ${#pids[@]} )) || true
    warn "Skipped ${#pids[@]} process(es)"
  fi
}

kill_group() {
  local label="$1"; shift
  local pids=("$@")
  for pid in "${pids[@]}"; do
    if safe_kill "$pid" TERM; then
      ok "Sent SIGTERM → PID ${pid}"
      # Give it 2s to die gracefully, then SIGKILL
      if ! $DRY_RUN; then
        sleep 0.3
        if kill -0 "$pid" 2>/dev/null; then
          sleep 1.7
          if kill -0 "$pid" 2>/dev/null; then
            warn "PID ${pid} still alive after SIGTERM — sending SIGKILL"
            safe_kill "$pid" KILL
          fi
        fi
      fi
    else
      die "Could not kill PID ${pid} (already gone, or permission denied)"
    fi
  done
}

# Find PIDs matching a pattern in command line, excluding self and system paths
find_pids_by_pattern() {
  local pattern="$1"
  local exclude_system="${2:-true}"
  local pids=()

  if [[ "$OS" == "Darwin" ]]; then
    while IFS= read -r line; do
      local pid cmd
      pid=$(echo "$line" | awk '{print $1}')
      cmd=$(echo "$line" | cut -d' ' -f2-)
      [[ "$pid" == "$MY_PID" || "$pid" == "$MY_PPID" ]] && continue
      # Exclude system daemons running from /System, /usr/sbin, /sbin
      if $exclude_system; then
        [[ "$cmd" =~ ^/System || "$cmd" =~ ^/usr/sbin || "$cmd" =~ ^/sbin ]] && continue
      fi
      pids+=("$pid")
    done < <(pgrep -f "$pattern" -l 2>/dev/null | grep -v "^${MY_PID} " || true)
  else
    while IFS= read -r line; do
      local pid cmd
      pid=$(echo "$line" | awk '{print $1}')
      cmd=$(echo "$line" | cut -d' ' -f2-)
      [[ "$pid" == "$MY_PID" || "$pid" == "$MY_PPID" ]] && continue
      if $exclude_system; then
        [[ "$cmd" =~ ^/usr/sbin || "$cmd" =~ ^/sbin || "$cmd" =~ ^/lib/systemd ]] && continue
      fi
      pids+=("$pid")
    done < <(pgrep -f "$pattern" -a 2>/dev/null | grep -v "^${MY_PID} " || true)
  fi

  echo "${pids[@]:-}"
}

# Find PID listening on a given TCP port
find_pid_on_port() {
  local port="$1"
  local pid=""
  if command -v lsof &>/dev/null; then
    pid=$(lsof -ti TCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1 || true)
  elif command -v ss &>/dev/null; then
    pid=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  elif command -v fuser &>/dev/null; then
    pid=$(fuser "${port}/tcp" 2>/dev/null | awk '{print $1}' | head -1 || true)
  fi
  echo "${pid:-}"
}

# ── Banner ────────────────────────────────────────────────────────────────────
log ""
log "${BLD}${CYN}  ╔══════════════════════════════════════╗${RST}"
log "${BLD}${CYN}  ║      DEV CLEANUP  v1.0               ║${RST}"
log "${BLD}${CYN}  ║  Orphaned processes & stale ports    ║${RST}"
log "${BLD}${CYN}  ╚══════════════════════════════════════╝${RST}"
log "${DIM}  Log: ${LOG_FILE}${RST}"
$DRY_RUN && log "${YLW}  DRY-RUN mode — nothing will be killed${RST}"
$FORCE   && log "${RED}  FORCE mode — killing all matches without prompts${RST}"
log ""

# =============================================================================
#  SECTION 1 — Stale port listeners
# =============================================================================
sep
log "${BLD}  [1/6] Stale port listeners${RST}"
sep

# Default dev ports + any user-specified ones
DEFAULT_DEV_PORTS=(
  3000 3001 3002 3003          # React / Express / generic
  4000 4001                    # GraphQL / misc
  4200                         # Angular
  5000 5001                    # Flask / misc
  5173 5174 5175               # Vite
  6006                         # Storybook
  7000                         # misc
  8000 8001 8080 8081 8090     # Django / Python / misc
  8443                         # HTTPS dev
  8888                         # Jupyter
  9000 9001 9002               # PHP / misc
  9229                         # Node inspector / debugger
  19006                        # Expo
  24678                        # Vite HMR
  35729                        # LiveReload
)

if [[ ${#SPECIFIC_PORTS[@]} -gt 0 ]]; then
  PORTS_TO_CHECK=("${SPECIFIC_PORTS[@]}")
else
  PORTS_TO_CHECK=("${DEFAULT_DEV_PORTS[@]}")
fi

for port in "${PORTS_TO_CHECK[@]}"; do
  pid=$(find_pid_on_port "$port")
  [[ -z "$pid" ]] && continue
  [[ "$pid" == "$MY_PID" || "$pid" == "$MY_PPID" || "$pid" == "1" ]] && continue

  local_cmd=""
  if [[ "$OS" == "Darwin" ]]; then
    local_cmd=$(ps -p "$pid" -o command= 2>/dev/null || echo "unknown")
  else
    local_cmd=$(ps -p "$pid" -o cmd= 2>/dev/null || echo "unknown")
  fi

  ask_kill "Port :${port} — ${local_cmd}" "$pid"
done

# =============================================================================
#  SECTION 2 — JavaScript / Node dev servers
# =============================================================================
sep
log "${BLD}  [2/6] JS / Node dev servers & watchers${RST}"
sep

declare -A JS_PATTERNS=(
  ["Vite"]="vite.*dev|vite.*serve|vite.*preview"
  ["webpack-dev-server"]="webpack.*dev-server|webpack-dev-server"
  ["React Scripts"]="react-scripts start"
  ["Next.js dev"]="next dev|next-server"
  ["Parcel"]="parcel serve|parcel watch"
  ["Snowpack"]="snowpack dev"
  ["esbuild serve"]="esbuild.*--serve"
  ["Turbopack"]="turbopack"
  ["Nodemon"]="nodemon"
  ["ts-node watch"]="ts-node.*--watch|ts-node-dev"
  ["tsx watch"]="tsx watch"
  ["Bun dev"]="bun.*dev|bun.*run"
  ["Deno dev"]="deno.*run.*--watch|deno.*dev"
  ["tsc watch"]="tsc.*--watch"
  ["Rollup watch"]="rollup.*-w|rollup.*--watch"
  ["Sass watch"]="sass.*--watch"
  ["PostCSS watch"]="postcss.*--watch"
  ["Storybook"]="storybook dev|start-storybook"
  ["Expo"]="expo start|expo-cli"
  ["Node inspector"]="node.*--inspect"
)

for label in "${!JS_PATTERNS[@]}"; do
  pattern="${JS_PATTERNS[$label]}"
  read -ra pids <<< "$(find_pids_by_pattern "$pattern")"
  [[ ${#pids[@]} -eq 0 || -z "${pids[0]:-}" ]] && continue
  ask_kill "$label" "${pids[@]}"
done

# =============================================================================
#  SECTION 3 — Python dev servers & daemons
# =============================================================================
sep
log "${BLD}  [3/6] Python dev servers & daemons${RST}"
sep

declare -A PY_PATTERNS=(
  ["Uvicorn"]="uvicorn.*--reload|uvicorn"
  ["Gunicorn"]="gunicorn"
  ["Flask dev"]="flask run|flask.*development"
  ["Django runserver"]="manage.py runserver"
  ["FastAPI/Hypercorn"]="hypercorn"
  ["aiohttp dev"]="aiohttp.*--reload"
  ["Jupyter"]="jupyter.*notebook|jupyter.*lab|jupyter.*server"
  ["pytest-watch"]="ptw|pytest-watch"
  ["Python http.server"]="python.*http.server|python.*SimpleHTTP"
  ["Python -m http"]="python.*-m http"
)

for label in "${!PY_PATTERNS[@]}"; do
  pattern="${PY_PATTERNS[$label]}"
  read -ra pids <<< "$(find_pids_by_pattern "$pattern")"
  [[ ${#pids[@]} -eq 0 || -z "${pids[0]:-}" ]] && continue
  ask_kill "$label" "${pids[@]}"
done

# =============================================================================
#  SECTION 4 — Test runners in watch mode
# =============================================================================
sep
log "${BLD}  [4/6] Test runners (watch mode)${RST}"
sep

declare -A TEST_PATTERNS=(
  ["Jest watch"]="jest.*--watch|jest.*--watchAll"
  ["Vitest"]="vitest.*--watch|vitest watch"
  ["Mocha watch"]="mocha.*--watch"
  ["Karma"]="karma start"
  ["Jasmine"]="jasmine.*--watch"
  ["Playwright"]="playwright.*dev"
  ["Cypress open"]="cypress open"
)

for label in "${!TEST_PATTERNS[@]}"; do
  pattern="${TEST_PATTERNS[$label]}"
  read -ra pids <<< "$(find_pids_by_pattern "$pattern")"
  [[ ${#pids[@]} -eq 0 || -z "${pids[0]:-}" ]] && continue
  ask_kill "$label" "${pids[@]}"
done

# =============================================================================
#  SECTION 5 — Tunnel / proxy / local HTTPS
# =============================================================================
sep
log "${BLD}  [5/6] Tunnels, proxies & local HTTPS${RST}"
sep

declare -A TUNNEL_PATTERNS=(
  ["ngrok"]="ngrok"
  ["localtunnel"]="lt --port|localtunnel"
  ["Caddy (dev)"]="caddy.*run|caddy.*start"
  ["mitmproxy"]="mitmproxy|mitmdump"
  ["Cloudflare tunnel"]="cloudflared.*tunnel"
  ["Telepresence"]="telepresence"
)

for label in "${!TUNNEL_PATTERNS[@]}"; do
  pattern="${TUNNEL_PATTERNS[$label]}"
  read -ra pids <<< "$(find_pids_by_pattern "$pattern")"
  [[ ${#pids[@]} -eq 0 || -z "${pids[0]:-}" ]] && continue
  ask_kill "$label" "${pids[@]}"
done

# =============================================================================
#  SECTION 6 — Orphaned processes (reparented to init, matching dev patterns)
# =============================================================================
sep
log "${BLD}  [6/6] Orphaned dev processes (PPID=1, not system)${RST}"
sep

DEV_BINARY_PATTERN="node|python|bun|deno|ruby|php|java.*spring|gradle.*daemon|cargo.*watch"
orphan_pids=()

if [[ "$OS" == "Darwin" ]]; then
  while IFS= read -r line; do
    pid=$(echo "$line"  | awk '{print $1}')
    ppid=$(echo "$line" | awk '{print $2}')
    cmd=$(echo "$line"  | cut -d' ' -f3-)
    [[ "$ppid" != "1" ]] && continue
    [[ "$pid" == "$MY_PID" ]] && continue
    [[ "$cmd" =~ $DEV_BINARY_PATTERN ]] || continue
    # Skip actual system paths
    [[ "$cmd" =~ ^/System || "$cmd" =~ ^/usr/libexec || "$cmd" =~ ^/usr/sbin ]] && continue
    orphan_pids+=("$pid")
  done < <(ps -eo pid=,ppid=,command= 2>/dev/null || true)
else
  while IFS= read -r line; do
    pid=$(echo "$line"  | awk '{print $1}')
    ppid=$(echo "$line" | awk '{print $2}')
    cmd=$(echo "$line"  | cut -d' ' -f3-)
    [[ "$ppid" != "1" ]] && continue
    [[ "$pid" == "$MY_PID" ]] && continue
    [[ "$cmd" =~ $DEV_BINARY_PATTERN ]] || continue
    [[ "$cmd" =~ ^/usr/sbin || "$cmd" =~ ^/sbin || "$cmd" =~ ^/lib/systemd ]] && continue
    orphan_pids+=("$pid")
  done < <(ps -eo pid=,ppid=,cmd= 2>/dev/null || true)
fi

if [[ ${#orphan_pids[@]} -gt 0 ]]; then
  ask_kill "Orphaned dev processes (PPID=1)" "${orphan_pids[@]}"
else
  ok "No orphaned dev processes found"
fi

# =============================================================================
#  SUMMARY
# =============================================================================
sep
log ""
log "${BLD}  Summary${RST}"
log "  Processes killed : ${GRN}${KILLED}${RST}"
log "  Processes skipped: ${YLW}${SKIPPED}${RST}"
log "  Log written to   : ${DIM}${LOG_FILE}${RST}"
$DRY_RUN && log "${YLW}  (Dry-run — nothing was actually killed)${RST}"
log ""

if [[ $KILLED -gt 0 ]] && ! $DRY_RUN; then
  log "${GRN}  Done. Your dev environment is clean.${RST}"
else
  log "${DIM}  Nothing to do.${RST}"
fi
log ""
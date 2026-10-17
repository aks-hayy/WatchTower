#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1,30p' "$0"
  exit 0
fi
command="${1:-up}"
shift || true
with_ollama=0
with_neo4j=0
with_mesh=0
linux_sensor=0
prune=0
role="controller"

usage() {
  cat <<'EOF'
Usage: scripts/container.sh {init|build|up|down|status|logs|config|reset} [options]

Options:
  --with-ollama       Start the local Ollama profile
  --with-neo4j        Start the Neo4j graph profile
  --with-mesh         Publish the mesh controller listeners
  --linux-sensor      Start the Linux sensor profile
  --prune             Allow Docker system prune for reset
  --role ROLE         Set controller or offline analysis role
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --with-ollama) with_ollama=1; shift ;;
    --with-neo4j) with_neo4j=1; shift ;;
    --with-mesh) with_mesh=1; shift ;;
    --linux-sensor) linux_sensor=1; shift ;;
    --prune) prune=1; shift ;;
    --role)
      [[ $# -ge 2 ]] || { echo "--role requires controller or offline." >&2; exit 2; }
      role="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$command" in init|build|up|down|status|logs|config|reset) ;; *)
  echo "Usage: scripts/container.sh {init|build|up|down|status|logs|config|reset} [--with-ollama] [--with-neo4j] [--with-mesh] [--linux-sensor]" >&2
  exit 2 ;;
esac

case "$role" in controller|offline) ;; *) echo "Role must be controller or offline." >&2; exit 2 ;; esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container_dir="$root/deploy/container"
env_file="$container_dir/.env.container"
secret_dir="$container_dir/secrets"
master_key="$secret_dir/watchtower_master_key"
neo4j_key="$secret_dir/watchtower_neo4j_password"

require_docker() {
  command -v docker >/dev/null 2>&1 || { echo "Docker with Compose is required." >&2; exit 1; }
  docker compose version >/dev/null
}

new_secret() {
  local destination="$1" bytes="${2:-32}"
  [[ -f "$destination" ]] && return
  umask 077
  openssl rand -base64 "$bytes" | tr -d '\n' > "$destination"
}

ensure_env_value() {
  local name="$1" value="$2"
  grep -q "^${name}=" "$env_file" && return
  printf '\n%s=%s\n' "$name" "$value" >> "$env_file"
}

set_env_value() {
  local name="$1" value="$2"
  if grep -q "^${name}=" "$env_file"; then
    sed -i "s#^${name}=.*#${name}=${value}#" "$env_file"
  else
    ensure_env_value "$name" "$value"
  fi
}

initialize() {
  mkdir -p "$secret_dir"
  [[ -f "$env_file" ]] || cp "$container_dir/.env.container.example" "$env_file"
  new_secret "$master_key"
  if [[ "$with_neo4j" == 1 ]]; then
    new_secret "$neo4j_key" 36
    ensure_env_value WATCHTOWER_NEO4J_PASSWORD_FILE deploy/container/secrets/watchtower_neo4j_password
  fi
  echo "Container configuration is ready: $env_file"
}

compose=(compose --env-file "$env_file" -f compose.yaml)
[[ "$with_neo4j" == 1 ]] && compose+=(-f deploy/compose.neo4j.yaml --profile graph)
[[ "$with_mesh" == 1 ]] && compose+=(-f deploy/compose.mesh.yaml)
[[ "$with_ollama" == 1 ]] && compose+=(--profile ai-local)
[[ "$linux_sensor" == 1 ]] && compose+=(--profile linux-sensor)

cd "$root"
if [[ "$command" == init ]]; then
  initialize
  set_env_value WATCHTOWER_DEPLOYMENT_ROLE "$role"
  echo "Container role: $role"
  exit 0
fi
require_docker
[[ -f "$env_file" && -f "$master_key" ]] || initialize
if [[ "$with_neo4j" == 1 ]]; then
  new_secret "$neo4j_key" 36
  ensure_env_value WATCHTOWER_NEO4J_PASSWORD_FILE deploy/container/secrets/watchtower_neo4j_password
fi
set_env_value WATCHTOWER_DEPLOYMENT_ROLE "$role"

case "$command" in
  build) docker "${compose[@]}" build ;;
  up) docker "${compose[@]}" up --detach --build --remove-orphans ;;
  down) docker "${compose[@]}" down ;;
  status) docker "${compose[@]}" ps ;;
  logs) docker "${compose[@]}" logs --tail 200 --follow ;;
  config) docker "${compose[@]}" config ;;
  reset)
    docker "${compose[@]}" down --volumes --remove-orphans
    [[ "$prune" == 1 ]] && docker system prune --force
    ;;
esac

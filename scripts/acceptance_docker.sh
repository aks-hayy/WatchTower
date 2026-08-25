#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="watchtower-acceptance-$(date +%s)-$$"
RUN_ROOT="$ROOT/.acceptance-$PROJECT"
ENV_FILE="$RUN_ROOT/.env"
SECRET_DIR="$RUN_ROOT/secrets"
MASTER_KEY="$SECRET_DIR/watchtower_master_key"
UI_PORT=${WATCHTOWER_ACCEPTANCE_UI_PORT-43817}
mkdir -p "$SECRET_DIR" "$RUN_ROOT/logs"

docker compose version >/dev/null
openssl rand -hex 32 > "$MASTER_KEY"
cat > "$ENV_FILE" <<EOF
WATCHTOWER_MASTER_KEY_FILE=$MASTER_KEY
WATCHTOWER_UI_PORT=$UI_PORT
WATCHTOWER_CONTROLLER_IMAGE=watchtower/controller:$PROJECT
WATCHTOWER_UI_IMAGE=watchtower/ui:$PROJECT
EOF

status=failed
error=""
compose() {
  docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$ROOT/compose.yaml" "$@"
}
cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  echo "# WatchTower Docker Acceptance" > "$RUN_ROOT/acceptance.md"
  echo "" >> "$RUN_ROOT/acceptance.md"
  echo "- Project: $PROJECT" >> "$RUN_ROOT/acceptance.md"
  echo "- Status: **$status**" >> "$RUN_ROOT/acceptance.md"
  echo "- Artifacts: $RUN_ROOT" >> "$RUN_ROOT/acceptance.md"
  printf '{"project":"%s","status":"%s","error":"%s"}\n' "$PROJECT" "$status" "$error" > "$RUN_ROOT/acceptance.json"
}
trap cleanup EXIT

if ! compose build; then
  error="Docker image build failed"
  exit 1
fi
if ! compose up --detach --remove-orphans; then
  error="Docker Compose startup failed"
  exit 1
fi

for service in controller ui; do
  deadline=$((SECONDS + 180))
  state=""
  while (( SECONDS < deadline )); do
    state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$PROJECT-$service-1" 2>/dev/null || true)"
    [[ "$state" == healthy || "$state" == running ]] && break
    sleep 2
  done
  [[ "$state" == healthy || "$state" == running ]] || { error="$service did not become healthy"; exit 1; }
done

curl --fail --silent "http://127.0.0.1:$UI_PORT/" >/dev/null
compose exec -T controller test -x /opt/watchtower/bin/watchtower-sensor
compose exec -T controller python -m core.packet_engine.main doctor --json > "$RUN_ROOT/doctor.json"
compose exec -T controller python -m core.packet_engine.main graph status > "$RUN_ROOT/graph-status.json"
compose logs --no-color > "$RUN_ROOT/logs/compose.log"
docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "$PROJECT-controller-1" "$PROJECT-ui-1" > "$RUN_ROOT/resources.txt" || true
find "$RUN_ROOT" -type f -print0 | sort -z | xargs -0 sha256sum > "$RUN_ROOT/SHA256SUMS"
status=passed
echo "Docker acceptance passed: $RUN_ROOT"

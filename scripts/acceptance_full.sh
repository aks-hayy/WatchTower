#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="all"
OUTPUT_ROOT=""
RESUME=0
FULL_PERFORMANCE=0
EXCLUDE_SIGMA_E2E=0

usage() {
  cat <<'EOF'
WatchTower comprehensive acceptance runner for Linux/container stages.

Usage: scripts/acceptance_full.sh [options]

Options:
  --stage NAME             preflight|source|offline|docker|all
  --output-root DIR        Reuse this isolated acceptance directory
  --resume                 Reuse completed stage markers
  --full-performance       Run the 1 GiB PCAP benchmark
  --exclude-sigma-e2e      Exclude Sigma synchronization/install/hunt workflows
  -h, --help               Show this help
EOF
}

while (($#)); do
  case "$1" in
    --stage) STAGE="${2:?--stage requires a value}"; shift 2 ;;
    --output-root) OUTPUT_ROOT="${2:?--output-root requires a value}"; shift 2 ;;
    --resume) RESUME=1; shift ;;
    --full-performance) FULL_PERFORMANCE=1; shift ;;
    --exclude-sigma-e2e) EXCLUDE_SIGMA_E2E=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$STAGE" in
  preflight|source|offline|docker|all) ;;
  *) echo "Invalid stage: $STAGE" >&2; exit 2 ;;
esac

if [[ -z "$OUTPUT_ROOT" ]]; then
  OUTPUT_ROOT="$ROOT/.acceptance-full-$(date -u +%Y%m%d-%H%M%S)-$$"
fi
mkdir -p "$OUTPUT_ROOT/logs" "$OUTPUT_ROOT/artifacts"
export WATCHTOWER_HOME="$OUTPUT_ROOT/watchtower-home"
mkdir -p "$WATCHTOWER_HOME"

run_step() {
  local name="$1" timeout_seconds="$2"; shift 2
  local log="$OUTPUT_ROOT/logs/$name.log"
  local marker="$OUTPUT_ROOT/$name.status"
  if ((RESUME)) && [[ -f "$marker" ]] && [[ "$(<"$marker")" == passed ]]; then
    echo "reused $name"
    return 0
  fi
  echo "running $name"
  if timeout --signal=TERM --kill-after=30s "${timeout_seconds}s" "$@" >"$log" 2>&1; then
    echo passed >"$marker"
    echo "passed $name"
    return 0
  fi
  local code=$?
  echo "failed:$code" >"$marker"
  echo "failed $name (see $log)" >&2
  return 1
}

run_stage() {
  local stage="$1"
  local marker="$OUTPUT_ROOT/stage-$stage.status"
  if ((RESUME)) && [[ -f "$marker" ]] && [[ "$(<"$marker")" == passed ]]; then
    echo "reused stage $stage"
    return 0
  fi
  local failed=0
  case "$stage" in
    preflight)
      command -v python >/dev/null || { echo "python missing" >&2; failed=1; }
      command -v cargo >/dev/null || { echo "cargo missing" >&2; failed=1; }
      command -v npm >/dev/null || { echo "npm missing" >&2; failed=1; }
      command -v docker >/dev/null || { echo "docker missing" >&2; failed=1; }
      df -h "$ROOT" >"$OUTPUT_ROOT/logs/disk.txt" 2>&1 || failed=1
      ip -br link >"$OUTPUT_ROOT/logs/interfaces.txt" 2>&1 || true
      ;;
    source)
      run_step ruff 900 python -m ruff check core tests scripts || failed=1
      run_step compileall 900 python -m compileall -q core scripts tests || failed=1
      run_step python-tests 3600 python -m pytest -q || failed=1
      run_step plugin-contracts 900 python -m core.packet_engine.main plugins test || failed=1
      run_step calibration-verify 900 python -m core.packet_engine.main plugins calibration verify || failed=1
      run_step rust-tests 1800 cargo test --locked --manifest-path rust/watchtower-sensor/Cargo.toml || failed=1
      run_step ui-npm-ci 1800 npm --prefix ui ci --ignore-scripts || failed=1
      run_step ui-lint 900 npm --prefix ui run lint || failed=1
      run_step ui-typecheck 900 npm --prefix ui run typecheck || failed=1
      run_step ui-build 1200 npm --prefix ui run build || failed=1
      ;;
    offline)
      local fixture="$OUTPUT_ROOT/artifacts/acceptance-25MiB.pcap"
      run_step generate-25m 900 python scripts/generate_acceptance_pcaps.py --output "$fixture" --size 25MiB || failed=1
      run_step forensic-tests 3600 python -m pytest tests/forensics -q || failed=1
      run_step rust-parity 1800 python -m pytest tests/forensics/test_rust_analysis_parity.py tests/forensics/test_rust_fast_analysis.py -q || failed=1
      if ((FULL_PERFORMANCE)); then
        run_step pcap-1g 7200 python scripts/benchmark_large_pcap.py --size-gib 1.0 --path "$OUTPUT_ROOT/artifacts/benchmark-1g.pcap" || failed=1
      else
        echo not_applicable >"$OUTPUT_ROOT/pcap-1g.status"
      fi
      ;;
    docker)
      run_step docker-acceptance 3600 scripts/acceptance_docker.sh || failed=1
      ;;
  esac
  if ((failed)); then echo failed >"$marker"; else echo passed >"$marker"; fi
  return "$failed"
}

stages=(preflight source offline docker)
if [[ "$STAGE" != all ]]; then stages=("$STAGE"); fi
overall=0
for stage in "${stages[@]}"; do
  run_stage "$stage" || overall=1
done

find "$OUTPUT_ROOT" -type f ! -name artifact-manifest.sha256 -print0 | sort -z | xargs -0 sha256sum >"$OUTPUT_ROOT/artifact-manifest.sha256" 2>/dev/null || true
status=passed
((overall)) && status=failed
cat >"$OUTPUT_ROOT/acceptance.md" <<EOF
# WatchTower Comprehensive Acceptance

- Status: **$status**
- Sigma end-to-end excluded: **$EXCLUDE_SIGMA_E2E**
- Isolated state: **true**
- Artifacts: `$OUTPUT_ROOT`
EOF
printf '{"status":"%s","output_root":"%s","sigma_end_to_end_excluded":%s}\n' "$status" "$OUTPUT_ROOT" "$EXCLUDE_SIGMA_E2E" >"$OUTPUT_ROOT/acceptance.json"
exit "$overall"

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_PREREQUISITES=0
WITH_NEO4J=0
SKIP_UI=0
SKIP_RUST=0
DEVELOPMENT=0
DISABLE_AUTH=0
SKIP_DIAGNOSTICS=0
GRANT_CAPTURE=0
NON_INTERACTIVE=0
PYTHON_CMD=""

usage() {
  cat <<'EOF'
WatchTower setup

Usage: ./scripts/setup.sh [options]

Options:
  --install-prerequisites  Install supported Ubuntu/Debian prerequisites
  --with-neo4j             Start the optional local Neo4j graph
  --skip-ui                Do not install or build the UI
  --skip-rust              Do not build the Rust sensor
  --development            Install development dependencies
  --disable-auth           Disable operator authentication during setup
  --non-interactive        Fail instead of prompting for first-run auth
  --skip-diagnostics       Skip the final tower doctor check
  --grant-capture          Grant the Rust binary Linux capture capabilities
  -h, --help               Show this help
EOF
}

for argument in "$@"; do
  case "$argument" in
    -h|--help) usage; exit 0 ;;
    --install-prerequisites) INSTALL_PREREQUISITES=1 ;;
    --with-neo4j) WITH_NEO4J=1 ;;
    --skip-ui) SKIP_UI=1 ;;
    --skip-rust) SKIP_RUST=1 ;;
    --development) DEVELOPMENT=1 ;;
    --disable-auth) DISABLE_AUTH=1 ;;
    --non-interactive) NON_INTERACTIVE=1 ;;
    --skip-diagnostics) SKIP_DIAGNOSTICS=1 ;;
    --grant-capture) GRANT_CAPTURE=1 ;;
    *) echo "Unknown setup option: $argument" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$1"; }
require() { command -v "$1" >/dev/null 2>&1 || { echo "$1 is required. $2" >&2; exit 1; }; }

install_prerequisites() {
  if [[ "$INSTALL_PREREQUISITES" != 1 ]]; then
    return
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Automatic prerequisite installation currently supports Debian and Ubuntu." >&2
    echo "Install Python 3.12 or 3.13, Rust, Node.js 20+, npm, pkg-config, a C compiler, and libpcap headers." >&2
    exit 1
  fi
  local distro_id="" distro_version=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distro_id="${ID:-}"
    distro_version="${VERSION_ID:-}"
  fi
  local sudo_command=()
  if [[ "$(id -u)" -ne 0 ]]; then
    require sudo "Install sudo or run setup as root for --install-prerequisites."
    sudo_command=(sudo)
  fi
  step "Installing operating-system prerequisites"
  "${sudo_command[@]}" apt-get update
  "${sudo_command[@]}" apt-get install -y \
    python3 python3-pip build-essential pkg-config libpcap-dev \
    ca-certificates curl gnupg libcap2-bin software-properties-common
  if [[ "$distro_id" == "ubuntu" && "$distro_version" == "22.04" ]]; then
    step "Installing Python 3.12 for Ubuntu 22.04"
    "${sudo_command[@]}" add-apt-repository --yes ppa:deadsnakes/ppa
    "${sudo_command[@]}" apt-get update
  fi
  "${sudo_command[@]}" apt-get install -y python3.12 python3.12-venv python3.12-dev

  local node_major=0
  if command -v node >/dev/null 2>&1; then
    node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
  fi
  if [[ "$node_major" -lt 20 ]]; then
    step "Installing Node.js 22 LTS from the signed NodeSource repository"
    local key_file
    key_file="$(mktemp)"
    curl --fail --silent --show-error --location \
      https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key --output "$key_file"
    if [[ "$(id -u)" -eq 0 ]]; then
      gpg --dearmor --yes --output /usr/share/keyrings/nodesource.gpg "$key_file"
      printf '%s\n' 'deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main' \
        > /etc/apt/sources.list.d/nodesource.list
    else
      sudo gpg --dearmor --yes --output /usr/share/keyrings/nodesource.gpg "$key_file"
      printf '%s\n' 'deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main' \
        | sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
    fi
    rm -f "$key_file"
    "${sudo_command[@]}" apt-get update
    "${sudo_command[@]}" apt-get install -y nodejs
  fi
}

ensure_rust() {
  if [[ "$SKIP_RUST" == 1 ]]; then
    return
  fi
  local version=""
  if command -v rustc >/dev/null 2>&1; then
    version="$(rustc --version | sed -nE 's/^rustc ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')"
  fi
  if command -v rustup >/dev/null 2>&1; then
    rustup toolchain install 1.86.0 --profile minimal --component rustfmt --component clippy >/dev/null
    export PATH="$HOME/.cargo/bin:$PATH"
    return
  fi
  if [[ "$version" == 1.86.* ]]; then
    return
  fi
  require curl "Install curl so setup can install the pinned Rust toolchain."
  step "Installing the pinned Rust 1.86 toolchain"
  curl --proto '=https' --tlsv1.2 --silent --show-error --fail https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain 1.86.0 --profile minimal
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
  rustup component add rustfmt clippy
}

select_python() {
  for candidate in python3.13 python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if (sys.version_info >= (3,12) and sys.version_info < (3,14)) else 1)' >/dev/null 2>&1; then
      PYTHON_CMD="$candidate"
      return
    fi
  done
  echo "Python 3.12 or 3.13 is required. Install it or rerun with --install-prerequisites." >&2
  exit 1
}

cd "$ROOT"
echo "WatchTower 2.0 setup"
echo "Repository: $ROOT"

install_prerequisites

ensure_rust

select_python

if [[ "$SKIP_RUST" == 0 ]]; then
  require cargo "Install Rust stable with rustup or your package manager."
  require pkg-config "Install pkg-config."
  pkg-config --exists libpcap || {
    echo "libpcap development headers are required (for example: apt install libpcap-dev)." >&2
    exit 1
  }
fi

if [[ "$SKIP_UI" == 0 ]]; then
  require node "Install Node.js 20 LTS or newer."
  require npm "Install npm with Node.js."
  NODE_MAJOR="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
  if [[ "$NODE_MAJOR" -lt 20 ]]; then
    echo "WatchTower requires Node.js 20 or newer; found $(node --version)." >&2
    echo "Install a current Node.js LTS release from https://nodejs.org/ and rerun setup." >&2
    exit 1
  fi
fi

step "Creating the isolated Python environment"
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_CMD" -m venv .venv
fi
PYTHON="$ROOT/.venv/bin/python"
"$PYTHON" -m pip install --upgrade pip
if [[ "$DEVELOPMENT" == 1 ]]; then
  "$PYTHON" -m pip install -c requirements/runtime.lock -e '.[dev]'
else
  "$PYTHON" -m pip install -c requirements/runtime.lock -e .
fi

if [[ "$SKIP_RUST" == 0 ]]; then
  step "Building the Rust capture and replay engine"
  cargo build --locked --release --manifest-path rust/watchtower-sensor/Cargo.toml
  if [[ "$GRANT_CAPTURE" == 1 ]]; then
    require setcap "Install libcap2-bin to grant capture capability."
    step "Granting packet-capture capability to the Rust sensor"
    if [[ "$(id -u)" -eq 0 ]]; then
      setcap cap_net_raw,cap_net_admin=eip rust/watchtower-sensor/target/release/watchtower-sensor
    else
      require sudo "Install sudo or run setcap as root."
      sudo setcap cap_net_raw,cap_net_admin=eip rust/watchtower-sensor/target/release/watchtower-sensor
    fi
  fi
fi

if [[ "$SKIP_UI" == 0 ]]; then
  step "Building the production UI"
  (
    cd ui
    npm ci
    npm run lint
    npm run typecheck
    npm run build
  )
fi

if [[ "$WITH_NEO4J" == 1 ]]; then
  step "Starting the optional loopback Neo4j evidence graph"
  require docker "Install Docker with the Compose plugin."
  : "${WATCHTOWER_NEO4J_PASSWORD:?set WATCHTOWER_NEO4J_PASSWORD before using --with-neo4j}"
  docker compose -f deploy/neo4j.compose.yml up -d
  CONFIG_ROOT="$($PYTHON -c 'from core.runtime_paths import RuntimePaths; print(RuntimePaths.from_environment().config)')"
  mkdir -p "$CONFIG_ROOT"
  printf '%s\n' \
    'neo4j:' \
    '  enabled: true' \
    '  uri: bolt://127.0.0.1:7687' \
    '  username: neo4j' \
    '  database: neo4j' > "$CONFIG_ROOT/evidence_graph.yaml"
fi

TOWER="$ROOT/.venv/bin/tower"
step "Configuring local operator access"
set +e
AUTH_STATUS="$("$TOWER" auth status 2>&1)"
AUTH_STATUS_EXIT=$?
set -e
if [[ "$AUTH_STATUS_EXIT" -eq 0 && "$AUTH_STATUS" != *"SETUP_REQUIRED"* ]]; then
  printf '%s\n' 'Operator access is already configured; keeping the existing trust settings.'
elif [[ "$DISABLE_AUTH" == 1 ]]; then
  "$TOWER" auth setup --disable
elif [[ "$NON_INTERACTIVE" == 1 ]]; then
  echo "First-run authentication is not configured. Rerun with --disable-auth or run tower auth setup interactively." >&2
  exit 4
else
  "$TOWER" auth setup
fi

if [[ "$SKIP_DIAGNOSTICS" == 0 ]]; then
  step "Running installation diagnostics"
  "$TOWER" doctor
fi

printf '\nWatchTower setup completed.\n'
printf 'Launch UI:  %s ui\n' "$TOWER"
printf 'CLI shell:  %s\n' "$TOWER"
printf 'List input devices: %s sources\n' "$TOWER"

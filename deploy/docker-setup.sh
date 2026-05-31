#!/usr/bin/env bash
# contacc node setup — installs dependencies, configures and starts nodes,
# then prints setup tokens for each one.
#
# Usage (run from any directory):
#   curl -fsSL https://raw.githubusercontent.com/casseveritt/stor/main/deploy/docker-setup.sh | bash
# or, from a local clone:
#   bash deploy/docker-setup.sh
#
# Environment overrides (set before running):
#   CONTACC_DOMAIN          public hostname (required if not in .env)
#   CONTACC_DATA_DIR        data root  (default: ~/contacc)
#   CONTACC_REPO_DIR        repo clone (default: ~/stor)
#   CONTACC_NODES           how many nodes to start (default: 1)
#   CONTACC_REGISTRY_URL    shared registry (default: https://strk.xyzw.us:8421)
#   CONTACC_GOOGLE_CLIENT_ID / CONTACC_GOOGLE_CLIENT_SECRET

set -euo pipefail

# ── colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[1m' N='\033[0m'
info()   { echo -e "${G}==>${N} $*"; }
warn()   { echo -e "${Y}warn:${N} $*"; }
die()    { echo -e "${R}error:${N} $*" >&2; exit 1; }
section(){ echo -e "\n${B}── $* ──${N}"; }

# ── helpers ───────────────────────────────────────────────────────────────────
need_sudo_docker() {
    docker info &>/dev/null && echo "" || echo "sudo"
}

dc() { $(need_sudo_docker) docker compose "$@"; }

# ── 1. install prerequisites ──────────────────────────────────────────────────
section "Prerequisites"

if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    warn "Added $USER to the docker group. You may need to log out and back in."
    warn "For now, the script will use sudo for docker commands."
else
    info "Docker: $(docker --version 2>/dev/null | head -1)"
fi

if ! docker compose version &>/dev/null && ! sudo docker compose version &>/dev/null; then
    die "Docker Compose v2 not found. Please update Docker."
fi

if ! command -v git &>/dev/null; then
    info "Installing git..."
    sudo apt-get update -qq && sudo apt-get install -y -qq git
fi

# ── 2. clone / update repo ────────────────────────────────────────────────────
section "Repository"

CONTACC_REPO_DIR="${CONTACC_REPO_DIR:-${HOME}/stor}"
REPO_URL="${REPO_URL:-https://github.com/casseveritt/stor.git}"

if [ -d "${CONTACC_REPO_DIR}/.git" ]; then
    info "Updating existing repo at ${CONTACC_REPO_DIR}..."
    git -C "${CONTACC_REPO_DIR}" pull --ff-only
else
    info "Cloning repo to ${CONTACC_REPO_DIR}..."
    git clone "${REPO_URL}" "${CONTACC_REPO_DIR}"
fi

cd "${CONTACC_REPO_DIR}"

# ── 3. gather configuration ───────────────────────────────────────────────────
section "Configuration"

# Load existing .env if present
[ -f .env ] && { set -a; source .env; set +a; info "Loaded existing .env"; }

# Domain
if [ -z "${CONTACC_DOMAIN:-}" ]; then
    read -rp "  Public domain name (e.g. mypi.example.com): " CONTACC_DOMAIN
    [ -z "${CONTACC_DOMAIN}" ] && die "Domain is required."
fi
info "Domain: ${CONTACC_DOMAIN}"

# Data directory
CONTACC_DATA_DIR="${CONTACC_DATA_DIR:-${HOME}/contacc}"
read -rp "  Data directory [${CONTACC_DATA_DIR}]: " _d
CONTACC_DATA_DIR="${_d:-${CONTACC_DATA_DIR}}"

# Number of nodes
CONTACC_NODES="${CONTACC_NODES:-1}"
read -rp "  Number of nodes [${CONTACC_NODES}]: " _n
CONTACC_NODES="${_n:-${CONTACC_NODES}}"
[[ "${CONTACC_NODES}" =~ ^[0-9]+$ ]] || die "CONTACC_NODES must be a number."

# Registry
CONTACC_REGISTRY_URL="${CONTACC_REGISTRY_URL:-https://strk.xyzw.us:8421}"
read -rp "  Registry URL [${CONTACC_REGISTRY_URL}]: " _r
CONTACC_REGISTRY_URL="${_r:-${CONTACC_REGISTRY_URL}}"

# Google OAuth (optional but needed for login)
if [ -z "${CONTACC_GOOGLE_CLIENT_ID:-}" ]; then
    echo "  Google OAuth credentials (leave blank to skip — login will not work):"
    read -rp "    Client ID:     " CONTACC_GOOGLE_CLIENT_ID
    read -rp "    Client Secret: " CONTACC_GOOGLE_CLIENT_SECRET
fi

# ── 4. write .env ─────────────────────────────────────────────────────────────
section "Writing .env"

# Build COMPOSE_PROFILES
PROFILES="registry"
for i in $(seq 2 "${CONTACC_NODES}"); do
    PROFILES="${PROFILES},node${i}"
done

cat > .env <<EOF
CONTACC_DATA_DIR=${CONTACC_DATA_DIR}
CONTACC_DOMAIN=${CONTACC_DOMAIN}
CONTACC_IDENTITY_PROXY_URL=${CONTACC_REGISTRY_URL}
COMPOSE_PROFILES=${PROFILES}
EOF

[ -n "${CONTACC_GOOGLE_CLIENT_ID:-}"     ] && echo "CONTACC_GOOGLE_CLIENT_ID=${CONTACC_GOOGLE_CLIENT_ID}"         >> .env
[ -n "${CONTACC_GOOGLE_CLIENT_SECRET:-}" ] && echo "CONTACC_GOOGLE_CLIENT_SECRET=${CONTACC_GOOGLE_CLIENT_SECRET}" >> .env

chmod 600 .env
info ".env written."

# ── 5. data directories ───────────────────────────────────────────────────────
section "Data directories"

mkdir -p "${CONTACC_DATA_DIR}/caddy" "${CONTACC_DATA_DIR}/caddy-config" "${CONTACC_DATA_DIR}/registry"
for i in $(seq 0 $((CONTACC_NODES - 1))); do
    mkdir -p "${CONTACC_DATA_DIR}/node-${i}-me" "${CONTACC_DATA_DIR}/node-${i}-them"
done
info "Data directories ready under ${CONTACC_DATA_DIR}."

# ── 6. build image ────────────────────────────────────────────────────────────
section "Building image"
info "Building contacc image (first build may take a few minutes — compiles sqlcipher)..."
$(need_sudo_docker) docker compose build node-0-me

# ── 7. start services ─────────────────────────────────────────────────────────
section "Starting services"

PROFILE_FLAGS=""
for i in $(seq 2 "${CONTACC_NODES}"); do
    PROFILE_FLAGS="${PROFILE_FLAGS} --profile node${i}"
done

$(need_sudo_docker) docker compose --profile registry ${PROFILE_FLAGS} up -d
info "Services started."

# ── 8. setup tokens ───────────────────────────────────────────────────────────
section "Setup tokens"
sleep 3   # give containers a moment to start

echo
echo -e "${B}Your nodes are ready. Visit each URL and enter the setup token to initialize.${N}"
echo
printf "  %-8s  %-40s  %s\n" "Node" "Web URL" "Setup Token"
printf "  %-8s  %-40s  %s\n" "----" "-------" "-----------"

for i in $(seq 0 $((CONTACC_NODES - 1))); do
    web_port=$((6443 + i))
    token=$($(need_sudo_docker) docker logs "$($(need_sudo_docker) docker compose ps -q node-${i}-me)" 2>&1 \
            | grep "SETUP TOKEN" | tail -1 | awk '{print $NF}')
    printf "  %-8s  %-40s  %s\n" "node-${i}" "https://${CONTACC_DOMAIN}:${web_port}" "${token:-<starting…>}"
done

echo
echo -e "${B}Ports to open in your router/firewall:${N}"
echo "  80               (TLS certificate issuance)"
for i in $(seq 0 $((CONTACC_NODES - 1))); do
    echo "  $((6443 + i)) / $((8443 + i))    (node ${i} web / API)"
done
[ "${PROFILES}" = "registry"* ] && echo "  8421             (registry)"
echo
info "Done. Logs: sudo docker compose logs -f"

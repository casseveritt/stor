#!/usr/bin/env bash
# First-time contacc setup with Docker.
# Run from the repo root: bash setup.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}"

echo "==> contacc Docker setup"
echo

# ── prerequisites ──────────────────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "Error: docker not found. Install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi
if ! docker compose version &>/dev/null; then
    echo "Error: 'docker compose' not found. Install Docker Compose v2."
    exit 1
fi

# ── gather config ──────────────────────────────────────────────────────────────

if [ -f .env ]; then
    echo "Found existing .env — loading values as defaults."
    set -a; source .env; set +a
fi

read -rp "Data directory [${CONTACC_DATA_DIR:-${HOME}/contacc}]: " _datadir
CONTACC_DATA_DIR="${_datadir:-${CONTACC_DATA_DIR:-${HOME}/contacc}}"

read -rp "Domain name [${CONTACC_DOMAIN:-your.domain.example}]: " _domain
CONTACC_DOMAIN="${_domain:-${CONTACC_DOMAIN:-}}"
if [ -z "${CONTACC_DOMAIN}" ]; then
    echo "Error: domain is required."; exit 1
fi

# ── write .env ─────────────────────────────────────────────────────────────────

cat > .env <<EOF
CONTACC_DATA_DIR=${CONTACC_DATA_DIR}
CONTACC_DOMAIN=${CONTACC_DOMAIN}
EOF
chmod 600 .env
echo "==> .env written."

# ── data directories ───────────────────────────────────────────────────────────

mkdir -p "${CONTACC_DATA_DIR}/server" "${CONTACC_DATA_DIR}/client" "${CONTACC_DATA_DIR}/caddy" "${CONTACC_DATA_DIR}/caddy-config"
echo "==> Data directories ready."

# ── build image ────────────────────────────────────────────────────────────────

echo "==> Building contacc image (first build compiles sqlcipher — may take a few minutes)..."
docker compose build server

# ── initialize client ──────────────────────────────────────────────────────────

if [ ! -f "${CONTACC_DATA_DIR}/client/client_config.json" ]; then
    echo "==> Initializing client..."
    docker compose run --rm client \
        python tools/init_client.py \
            --config /data/client_config.json \
            --own-server "http://server:9443"
else
    echo "==> Client already initialized — skipping."
fi

python3 -c "
import json
p = '${CONTACC_DATA_DIR}/client/client_config.json'
c = json.load(open(p))
c['own_server'] = 'http://server:9443'
c.pop('passphrase_hash', None)
json.dump(c, open(p, 'w'), indent=2)
print('==> own_server set to http://server:9443')
"

# ── start services ─────────────────────────────────────────────────────────────

echo "==> Starting services..."
docker compose up -d

echo
echo "==> Done!"
echo
echo "    Next: open the server URL to complete setup:"
echo "    https://${CONTACC_DOMAIN}:8443"
echo
echo "    You will be prompted to create a new identity or restore from a backup."
echo
echo "    Client: https://${CONTACC_DOMAIN}:8444"
echo "    Logs:   docker compose logs -f"
echo
echo "    Tip: add CONTACC_PASSPHRASE=<your-passphrase> to .env for auto-unlock on restart."

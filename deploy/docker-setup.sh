#!/usr/bin/env bash
# First-time contacc setup with Docker.
# Run from the repo root: bash deploy/docker-setup.sh
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

read -rp "Domain name [${CONTACC_DOMAIN:-your.domain.example}]: " _domain
CONTACC_DOMAIN="${_domain:-${CONTACC_DOMAIN:-}}"
if [ -z "${CONTACC_DOMAIN}" ]; then
    echo "Error: domain is required."; exit 1
fi

read -rp "Google OAuth2 client ID [${CONTACC_GOOGLE_CLIENT_ID:-}]: " _gcid
CONTACC_GOOGLE_CLIENT_ID="${_gcid:-${CONTACC_GOOGLE_CLIENT_ID:-}}"
if [ -z "${CONTACC_GOOGLE_CLIENT_ID}" ]; then
    echo "Error: Google client ID is required."; exit 1
fi

read -rsp "Google OAuth2 client secret: " _gcs; echo
CONTACC_GOOGLE_CLIENT_SECRET="${_gcs:-${CONTACC_GOOGLE_CLIENT_SECRET:-}}"
if [ -z "${CONTACC_GOOGLE_CLIENT_SECRET}" ]; then
    echo "Error: Google client secret is required."; exit 1
fi

read -rp "Owner Google identity (e.g. google:you@gmail.com) [${CONTACC_OWNER_IDENTITY:-}]: " _oid
CONTACC_OWNER_IDENTITY="${_oid:-${CONTACC_OWNER_IDENTITY:-}}"
if [ -z "${CONTACC_OWNER_IDENTITY}" ]; then
    echo "Error: owner identity is required."; exit 1
fi

if [ -z "${CONTACC_PASSPHRASE:-}" ]; then
    read -rsp "Node passphrase (encrypts database and private key): " CONTACC_PASSPHRASE; echo
    read -rsp "Confirm passphrase: " _confirm; echo
    if [ "${CONTACC_PASSPHRASE}" != "${_confirm}" ]; then
        echo "Error: passphrases do not match."; exit 1
    fi
fi

# ── write .env ─────────────────────────────────────────────────────────────────

cat > .env <<EOF
CONTACC_DOMAIN=${CONTACC_DOMAIN}
CONTACC_PASSPHRASE=${CONTACC_PASSPHRASE}
CONTACC_GOOGLE_CLIENT_ID=${CONTACC_GOOGLE_CLIENT_ID}
CONTACC_GOOGLE_CLIENT_SECRET=${CONTACC_GOOGLE_CLIENT_SECRET}
CONTACC_OWNER_IDENTITY=${CONTACC_OWNER_IDENTITY}
EOF
chmod 600 .env
echo "==> .env written."

# ── data directories ───────────────────────────────────────────────────────────

mkdir -p data/server data/client data/caddy data/caddy-config
echo "==> Data directories ready."

# ── build image ────────────────────────────────────────────────────────────────

echo "==> Building contacc image (first build compiles sqlcipher — may take a few minutes)..."
docker compose build server

# ── initialize server node ─────────────────────────────────────────────────────

if [ ! -f data/server/node_config.json ]; then
    echo "==> Initializing server node..."
    docker compose run --rm \
        -e CONTACC_PASSPHRASE="${CONTACC_PASSPHRASE}" \
        -e CONTACC_GOOGLE_CLIENT_ID="${CONTACC_GOOGLE_CLIENT_ID}" \
        -e CONTACC_GOOGLE_CLIENT_SECRET="${CONTACC_GOOGLE_CLIENT_SECRET}" \
        server \
        python tools/init_node.py \
            --store /data \
            --address "https://${CONTACC_DOMAIN}:8443"
else
    echo "==> Server node already initialized — skipping."
fi

# ── configure SSO credentials and owner identity ───────────────────────────────

echo "==> Configuring SSO and owner identity..."
docker compose run --rm \
    -e CONTACC_GOOGLE_CLIENT_ID="${CONTACC_GOOGLE_CLIENT_ID}" \
    -e CONTACC_GOOGLE_CLIENT_SECRET="${CONTACC_GOOGLE_CLIENT_SECRET}" \
    server \
    python tools/configure_sso.py \
        --config /data/node_config.json \
        --owner-identity "${CONTACC_OWNER_IDENTITY}"

# ── initialize client ──────────────────────────────────────────────────────────

if [ ! -f data/client/client_config.json ]; then
    echo "==> Initializing client..."
    docker compose run --rm client \
        python tools/init_client.py \
            --config /data/client_config.json \
            --own-server "http://server:9443"
else
    echo "==> Client already initialized — skipping."
fi

# ── patch configs for Docker ───────────────────────────────────────────────────
# store_path and own_server may point to old host paths when restoring from backup.

python3 -c "
import json, sys
p = 'data/server/node_config.json'
c = json.load(open(p))
c['store_path'] = '/data'
json.dump(c, open(p, 'w'), indent=2)
print('==> store_path set to /data')
"

python3 -c "
import json
p = 'data/client/client_config.json'
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
echo "    Server: https://${CONTACC_DOMAIN}:8443"
echo "    Client: https://${CONTACC_DOMAIN}:8444"
echo
echo "    First login: open the client URL and sign in with Google."
echo "    Logs: docker compose logs -f"

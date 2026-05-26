#!/usr/bin/env bash
# First-time contac setup with Docker.
# Run from the repo root: bash deploy/docker-setup.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}"

echo "==> contac Docker setup"
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

read -rp "Domain name [${CONTAC_DOMAIN:-your.domain.example}]: " _domain
CONTAC_DOMAIN="${_domain:-${CONTAC_DOMAIN:-}}"
if [ -z "${CONTAC_DOMAIN}" ]; then
    echo "Error: domain is required."; exit 1
fi

read -rp "Google OAuth2 client ID [${CONTAC_GOOGLE_CLIENT_ID:-}]: " _gcid
CONTAC_GOOGLE_CLIENT_ID="${_gcid:-${CONTAC_GOOGLE_CLIENT_ID:-}}"
if [ -z "${CONTAC_GOOGLE_CLIENT_ID}" ]; then
    echo "Error: Google client ID is required."; exit 1
fi

read -rsp "Google OAuth2 client secret: " _gcs; echo
CONTAC_GOOGLE_CLIENT_SECRET="${_gcs:-${CONTAC_GOOGLE_CLIENT_SECRET:-}}"
if [ -z "${CONTAC_GOOGLE_CLIENT_SECRET}" ]; then
    echo "Error: Google client secret is required."; exit 1
fi

read -rp "Owner Google identity (e.g. google:you@gmail.com) [${CONTAC_OWNER_IDENTITY:-}]: " _oid
CONTAC_OWNER_IDENTITY="${_oid:-${CONTAC_OWNER_IDENTITY:-}}"
if [ -z "${CONTAC_OWNER_IDENTITY}" ]; then
    echo "Error: owner identity is required."; exit 1
fi

if [ -z "${CONTAC_PASSPHRASE:-}" ]; then
    read -rsp "Node passphrase (encrypts database and private key): " CONTAC_PASSPHRASE; echo
    read -rsp "Confirm passphrase: " _confirm; echo
    if [ "${CONTAC_PASSPHRASE}" != "${_confirm}" ]; then
        echo "Error: passphrases do not match."; exit 1
    fi
fi

# ── write .env ─────────────────────────────────────────────────────────────────

cat > .env <<EOF
CONTAC_DOMAIN=${CONTAC_DOMAIN}
CONTAC_PASSPHRASE=${CONTAC_PASSPHRASE}
CONTAC_GOOGLE_CLIENT_ID=${CONTAC_GOOGLE_CLIENT_ID}
CONTAC_GOOGLE_CLIENT_SECRET=${CONTAC_GOOGLE_CLIENT_SECRET}
CONTAC_OWNER_IDENTITY=${CONTAC_OWNER_IDENTITY}
EOF
chmod 600 .env
echo "==> .env written."

# ── data directories ───────────────────────────────────────────────────────────

mkdir -p data/server data/client data/caddy data/caddy-config
echo "==> Data directories ready."

# ── build image ────────────────────────────────────────────────────────────────

echo "==> Building contac image (first build compiles sqlcipher — may take a few minutes)..."
docker compose build server

# ── initialize server node ─────────────────────────────────────────────────────

if [ ! -f data/server/node_config.json ]; then
    echo "==> Initializing server node..."
    docker compose run --rm \
        -e CONTAC_PASSPHRASE="${CONTAC_PASSPHRASE}" \
        -e CONTAC_GOOGLE_CLIENT_ID="${CONTAC_GOOGLE_CLIENT_ID}" \
        -e CONTAC_GOOGLE_CLIENT_SECRET="${CONTAC_GOOGLE_CLIENT_SECRET}" \
        server \
        python tools/init_node.py \
            --store /data \
            --address "https://${CONTAC_DOMAIN}:8443"
else
    echo "==> Server node already initialized — skipping."
fi

# ── configure SSO credentials and owner identity ───────────────────────────────

echo "==> Configuring SSO and owner identity..."
docker compose run --rm \
    -e CONTAC_GOOGLE_CLIENT_ID="${CONTAC_GOOGLE_CLIENT_ID}" \
    -e CONTAC_GOOGLE_CLIENT_SECRET="${CONTAC_GOOGLE_CLIENT_SECRET}" \
    server \
    python tools/configure_sso.py \
        --config /data/node_config.json \
        --owner-identity "${CONTAC_OWNER_IDENTITY}"

# ── initialize client ──────────────────────────────────────────────────────────

if [ ! -f data/client/client_config.json ]; then
    echo "==> Initializing client..."
    docker compose run --rm client \
        python tools/init_client.py \
            --config /data/client_config.json \
            --own-server "https://${CONTAC_DOMAIN}:8443"
else
    echo "==> Client already initialized — skipping."
fi

# ── start services ─────────────────────────────────────────────────────────────

echo "==> Starting services..."
docker compose up -d

echo
echo "==> Done!"
echo
echo "    Server: https://${CONTAC_DOMAIN}:8443"
echo "    Client: https://${CONTAC_DOMAIN}:9876"
echo
echo "    First login: open the client URL and sign in with Google."
echo "    Logs: docker compose logs -f"

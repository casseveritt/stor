#!/usr/bin/env bash
# Activate a new instance slot (2-10).
# Usage: bash deploy/new-slot.sh <slot>
# Example: bash deploy/new-slot.sh 2
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}"

SLOT="${1:-}"
if [ -z "${SLOT}" ] || [ "${SLOT}" -lt 2 ] || [ "${SLOT}" -gt 10 ] 2>/dev/null; then
    echo "Usage: $0 <slot>   (slot must be 2-10)"
    exit 1
fi

if [ -f .env ]; then
    set -a; source .env; set +a
fi

if [ -z "${CONTACC_DATA_DIR:-}" ] || [ -z "${CONTACC_DOMAIN:-}" ]; then
    echo "Error: CONTACC_DATA_DIR and CONTACC_DOMAIN must be set in .env"
    exit 1
fi

SERVER_PORT=$((8443 + 2 * (SLOT - 1)))
CLIENT_PORT=$((8444 + 2 * (SLOT - 1)))

echo "==> Activating slot ${SLOT}"
echo "    Server: https://${CONTACC_DOMAIN}:${SERVER_PORT}"
echo "    Client: https://${CONTACC_DOMAIN}:${CLIENT_PORT}"
echo

mkdir -p "${CONTACC_DATA_DIR}/server-${SLOT}" "${CONTACC_DATA_DIR}/client-${SLOT}"

# Initialize the client config if needed
if [ ! -f "${CONTACC_DATA_DIR}/client-${SLOT}/client_config.json" ]; then
    echo "==> Initializing client for slot ${SLOT}..."
    docker compose run --rm \
        -e CONTACC_CLIENT_URL="https://${CONTACC_DOMAIN}:${CLIENT_PORT}" \
        -v "${CONTACC_DATA_DIR}/client-${SLOT}:/data" \
        client \
        python tools/init_client.py \
            --config /data/client_config.json \
            --own-server "http://server-${SLOT}:9443"
fi

echo "==> Starting slot ${SLOT}..."
COMPOSE_PROFILES="slot${SLOT}" docker compose up -d "server-${SLOT}" "client-${SLOT}"

echo
echo "==> Done! Get the setup token:"
echo "    docker compose logs server-${SLOT} | grep 'SETUP TOKEN'"
echo
echo "    Then open: https://${CONTACC_DOMAIN}:${SERVER_PORT}"

#!/usr/bin/env bash
# contacc node setup script
# Run once after cloning the repo to set up the virtual environment,
# initialize the node store, and optionally install the systemd service.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STORE_DIR="${HOME}/.local/share/contacc"
CONFIG_DIR="${HOME}/.config/contacc"
VENV="${REPO_DIR}/.venv"

echo "==> contacc setup"
echo "    repo:   ${REPO_DIR}"
echo "    store:  ${STORE_DIR}"

# 1. Python virtual environment
if [ ! -f "${VENV}/bin/python" ]; then
    echo "==> Creating virtual environment..."
    python3 -m venv "${VENV}"
fi
echo "==> Installing Python dependencies..."
"${VENV}/bin/pip" install --quiet -r "${REPO_DIR}/requirements.txt"

# 2. Initialize node store (skip if already exists)
CONFIG_FILE="${STORE_DIR}/node_config.json"
if [ ! -f "${CONFIG_FILE}" ]; then
    read -rp "Node public address (e.g. https://your.domain.example): " NODE_ADDR
    echo "==> Initializing node store at ${STORE_DIR}..."
    "${VENV}/bin/python" "${REPO_DIR}/tools/init_node.py" \
        --store "${STORE_DIR}" \
        --address "${NODE_ADDR}"
    echo "==> Store initialized."
else
    echo "==> Store already exists at ${STORE_DIR}, skipping init."
fi

# 3. Environment file for passphrase
mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"
ENV_FILE="${CONFIG_DIR}/env"
if [ ! -f "${ENV_FILE}" ]; then
    echo "==> Creating ${ENV_FILE} ..."
    read -rsp "Passphrase (for CONTACC_PASSPHRASE in env file): " PASSPHRASE
    echo
    printf 'CONTACC_PASSPHRASE=%s\n' "${PASSPHRASE}" > "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    echo "==> Written to ${ENV_FILE} (chmod 600)."
else
    echo "==> ${ENV_FILE} already exists, skipping."
fi

# 4. Owner token
echo
echo "==> Issuing an owner token (you will be prompted for your passphrase)..."
"${VENV}/bin/python" "${REPO_DIR}/tools/issue_token.py" "${CONFIG_FILE}"

# 5. Optionally install systemd service
echo
read -rp "Install systemd service? [y/N] " INSTALL_SERVICE
if [[ "${INSTALL_SERVICE}" =~ ^[Yy]$ ]]; then
    SERVICE_SRC="${REPO_DIR}/deploy/contacc.service"
    # Patch WorkingDirectory and ExecStart to point at this repo
    sed "s|/home/cass/src/stor|${REPO_DIR}|g; s|/home/cass/.config/contacc|${CONFIG_DIR}|g; s|/home/cass/.local/share/contacc|${STORE_DIR}|g; s|User=cass|User=$(id -un)|g" \
        "${SERVICE_SRC}" > /tmp/contacc.service
    sudo cp /tmp/contacc.service /etc/systemd/system/contacc.service
    sudo systemctl daemon-reload
    sudo systemctl enable contacc
    sudo systemctl start contacc
    echo "==> Service installed and started."
    echo "    Logs: journalctl -u contacc -f"
else
    echo
    echo "==> To start manually:"
    echo "    CONTACC_PASSPHRASE=\$(grep CONTACC_PASSPHRASE ${ENV_FILE} | cut -d= -f2-) \\"
    echo "    ${VENV}/bin/python -m server.main ${CONFIG_FILE} --host 127.0.0.1 --port 8000"
fi

echo
echo "==> Done. Open http://localhost:8000 to access your node."

#!/bin/bash
# Start server (me) and client (them) as a single combined process.
exec python -m node.main \
    /data/node_config.json \
    /data/client_config.json \
    --me-port "${CONTACC_ME_PORT:-28443}" \
    --them-port "${CONTACC_THEM_PORT:-18443}"

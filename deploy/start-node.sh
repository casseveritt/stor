#!/bin/bash
# Start me (node server) and them (aggregator) in the same container.
# Either exiting causes the container to exit; Docker restart policy handles recovery.

python -m server.main /data/node_config.json \
    --host 0.0.0.0 --port "${CONTACC_ME_PORT}" &
ME_PID=$!

python -m client.main /data/client_config.json \
    --host 0.0.0.0 --port "${CONTACC_THEM_PORT}" &
THEM_PID=$!

wait -n
kill "$ME_PID" "$THEM_PID" 2>/dev/null || true
wait

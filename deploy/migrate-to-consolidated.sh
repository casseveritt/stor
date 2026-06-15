#!/bin/bash
# Migrate data from split node-N-me / node-N-them dirs to consolidated node-N.
# Run as root (or with sudo) from the stor repo root.
# Safe to re-run: skips nodes already migrated.

set -euo pipefail
# Load .env from repo root if DATA_DIR not already set
if [ -z "${CONTACC_DATA_DIR:-}" ] && [ -f "$(dirname "$0")/../.env" ]; then
    source "$(dirname "$0")/../.env"
fi
DATA="${CONTACC_DATA_DIR:-/home/cass/src/stor/data}"

for n in $(seq 0 29); do
    me_dir="$DATA/node-$n-me"
    them_dir="$DATA/node-$n-them"
    dest="$DATA/node-$n"

    # Skip nodes that were never split (e.g. node-24 already consolidated)
    if [ ! -d "$me_dir" ] && [ ! -d "$them_dir" ]; then
        echo "node-$n: no split dirs, skipping"
        continue
    fi

    mkdir -p "$dest"

    if [ -d "$me_dir" ]; then
        echo "node-$n: copying me → node-$n"
        cp -a "$me_dir/." "$dest/"
    fi

    if [ -d "$them_dir" ]; then
        echo "node-$n: copying them → node-$n"
        # client_config.json and client data land alongside server data
        cp -a "$them_dir/." "$dest/"
    fi

    echo "node-$n: done"
done

echo ""
echo "Migration complete. Old node-N-me / node-N-them dirs are preserved."
echo "Remove them manually once you've verified everything works:"
echo "  sudo rm -rf \$DATA/node-{0..29}-me \$DATA/node-{0..29}-them"

#!/usr/bin/env python3
"""Configure SSO credentials on an existing contacc node.

Usage:
    python tools/configure_sso.py --config /path/to/node_config.json \\
        --google-client-id <id> --google-client-secret <secret>

Or via environment variables:
    CONTACC_GOOGLE_CLIENT_ID=<id> CONTACC_GOOGLE_CLIENT_SECRET=<secret> \\
        python tools/configure_sso.py --config /path/to/node_config.json

To clear SSO credentials (disable SSO), run with --clear.
"""
import os
import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure SSO on an existing contacc node")
    parser.add_argument("--config", required=True, help="Path to node_config.json")
    parser.add_argument(
        "--google-client-id",
        default=os.environ.get("CONTACC_GOOGLE_CLIENT_ID", ""),
        help="Google OAuth2 client ID (env: CONTACC_GOOGLE_CLIENT_ID)",
    )
    parser.add_argument(
        "--google-client-secret",
        default=os.environ.get("CONTACC_GOOGLE_CLIENT_SECRET", ""),
        help="Google OAuth2 client secret (env: CONTACC_GOOGLE_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--owner-identity",
        default="",
        help="Google identity that receives owner tokens (e.g. google:you@gmail.com)",
    )
    parser.add_argument("--clear", action="store_true", help="Remove all SSO credentials")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    config = NodeConfig.load(config_path)

    if args.clear:
        config.sso_google_client_id = None
        config.sso_google_client_secret = None
        config.sso_owner_identity = None
        config.save(config_path)
        print("SSO credentials cleared.")
        return

    if not args.google_client_id or not args.google_client_secret:
        print(
            "Error: --google-client-id and --google-client-secret are required "
            "(or set CONTACC_GOOGLE_CLIENT_ID / CONTACC_GOOGLE_CLIENT_SECRET)",
            file=sys.stderr,
        )
        sys.exit(1)

    config.sso_google_client_id = args.google_client_id
    config.sso_google_client_secret = args.google_client_secret
    if args.owner_identity:
        config.sso_owner_identity = args.owner_identity
    config.save(config_path)

    print(f"Google SSO configured for node at {config.node_address}")
    print(f"Client ID: {args.google_client_id}")
    if config.sso_owner_identity:
        print(f"Owner identity: {config.sso_owner_identity}")
    print("Restart the server for changes to take effect.")


if __name__ == "__main__":
    main()

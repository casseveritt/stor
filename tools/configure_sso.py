#!/usr/bin/env python3
"""Configure authentication on an existing contacc node.

Usage — identity proxy (recommended, no Google credentials needed):
    python tools/configure_sso.py --config /path/to/node_config.json \\
        --identity-proxy-url https://starkville.hopto.org:8421 \\
        --owner-identity google:you@gmail.com

Usage — direct Google OAuth (advanced, requires your own OAuth credentials):
    python tools/configure_sso.py --config /path/to/node_config.json \\
        --google-client-id <id> --google-client-secret <secret> \\
        --owner-identity google:you@gmail.com

To clear all auth config:
    python tools/configure_sso.py --config /path/to/node_config.json --clear
"""
import os
import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure authentication on an existing contacc node")
    parser.add_argument("--config", required=True, help="Path to node_config.json")
    parser.add_argument(
        "--identity-proxy-url",
        default=os.environ.get("CONTACC_IDENTITY_PROXY_URL", ""),
        help="URL of the shared identity proxy (env: CONTACC_IDENTITY_PROXY_URL)",
    )
    parser.add_argument(
        "--google-client-id",
        default=os.environ.get("CONTACC_GOOGLE_CLIENT_ID", ""),
        help="Google OAuth2 client ID for direct SSO (env: CONTACC_GOOGLE_CLIENT_ID)",
    )
    parser.add_argument(
        "--google-client-secret",
        default=os.environ.get("CONTACC_GOOGLE_CLIENT_SECRET", ""),
        help="Google OAuth2 client secret for direct SSO (env: CONTACC_GOOGLE_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--owner-identity",
        default="",
        help="Google identity that receives owner tokens (e.g. google:you@gmail.com)",
    )
    parser.add_argument("--clear", action="store_true", help="Remove all auth configuration")
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
        config.identity_proxy_url = None
        config.save(config_path)
        print("Auth configuration cleared.")
        return

    if args.identity_proxy_url:
        config.identity_proxy_url = args.identity_proxy_url
        config.sso_google_client_id = None
        config.sso_google_client_secret = None
        print(f"Identity proxy: {args.identity_proxy_url}")
    elif args.google_client_id and args.google_client_secret:
        config.sso_google_client_id = args.google_client_id
        config.sso_google_client_secret = args.google_client_secret
        config.identity_proxy_url = None
        print(f"Direct Google SSO configured (client ID: {args.google_client_id})")
    else:
        print(
            "Error: provide either --identity-proxy-url or both "
            "--google-client-id and --google-client-secret",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.owner_identity:
        config.sso_owner_identity = args.owner_identity

    config.save(config_path)
    print(f"Node: {config.node_address}")
    if config.sso_owner_identity:
        print(f"Owner identity: {config.sso_owner_identity}")
    print("Restart the server for changes to take effect.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Initialize a contacc client configuration.

Usage:
    python tools/init_client.py --config ~/contacc-client/client_config.json \\
        --own-server https://starkville.hopto.org:8443
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.config import ClientConfig


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Initialize a contacc client")
    parser.add_argument("--config", required=True, help="Path to client_config.json")
    parser.add_argument("--own-server", required=True, help="URL of your contacc server node")
    args = parser.parse_args()

    config_path = Path(args.config)
    if config_path.exists():
        print(f"Error: {config_path} already exists", file=sys.stderr)
        sys.exit(1)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config = ClientConfig(own_server=args.own_server.rstrip("/"))
    config.save(config_path)

    print(f"Client config written to {config_path}")
    print(f"Own server: {config.own_server}")
    print(f"\nStart with:")
    print(f"  python -m client.main {config_path} --port 9444")


if __name__ == "__main__":
    main()

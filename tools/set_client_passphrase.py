#!/usr/bin/env python3
"""Set or change the passphrase on an existing contac client config."""
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from argon2 import PasswordHasher


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Set passphrase on an existing client config")
    parser.add_argument("config", help="Path to client_config.json")
    parser.add_argument("--passphrase-stdin", action="store_true",
                        help="Read passphrase from stdin instead of prompting")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: {config_path} does not exist", file=sys.stderr)
        sys.exit(1)

    data = json.loads(config_path.read_text())

    if args.passphrase_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        while True:
            pw = getpass.getpass("New client passphrase: ")
            pw2 = getpass.getpass("Confirm passphrase: ")
            if pw == pw2:
                break
            print("Passphrases do not match, try again.")

    data["passphrase_hash"] = PasswordHasher().hash(pw)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Passphrase set on {config_path}")


if __name__ == "__main__":
    main()

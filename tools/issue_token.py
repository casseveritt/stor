#!/usr/bin/env python3
"""Issue a signed owner token for a running contac node."""
import sys
import getpass
import argparse
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig
from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes
from server.auth import setup as auth_setup, issue_token
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag
from server.db import WrongPassphraseError


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue an owner token for a contac node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--ttl", type=int, default=86400 * 30, help="Token lifetime in seconds (default: 30 days)")
    parser.add_argument("--key-stdin", action="store_true")
    args = parser.parse_args()

    config = NodeConfig.load(args.config)
    passphrase = sys.stdin.readline().rstrip("\n") if args.key_stdin else getpass.getpass("Passphrase: ")

    salt = bytes.fromhex(config.argon2_salt)
    master_key = derive_master_key(
        passphrase, salt,
        config.argon2_time_cost, config.argon2_memory_cost, config.argon2_parallelism,
    )
    encrypted_privkey = base64.b64decode(config.encrypted_private_key)
    try:
        privkey_bytes = decrypt_bytes(encrypted_privkey, master_key)
    except Exception:
        print("Wrong passphrase.", file=sys.stderr)
        sys.exit(1)

    private_key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    auth_setup(private_key)
    token = issue_token(ttl_seconds=args.ttl)
    print(token)


if __name__ == "__main__":
    main()

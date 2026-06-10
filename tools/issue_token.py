#!/usr/bin/env python3
"""Issue auth tokens for a contacc node.

Without --recipient: issues an Ed25519-signed owner token (no DB write).
With --recipient <identity>: issues a DB-backed recipient token (requires
  the recipient to already exist; use --add-recipient to create them first).
"""
import sys
import base64
import getpass
import argparse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlcipher3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from server.config import NodeConfig
from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes
from server.auth import setup as auth_setup, issue_token, issue_node_token
from server.db import open_db


def _load_private_key(config: NodeConfig, passphrase: str) -> Ed25519PrivateKey:
    salt = bytes.fromhex(config.argon2_salt)
    master_key = derive_master_key(
        passphrase, salt,
        config.argon2_time_cost, config.argon2_memory_cost, config.argon2_parallelism,
    )
    try:
        privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    except Exception:
        print("Wrong passphrase.", file=sys.stderr)
        sys.exit(1)
    return Ed25519PrivateKey.from_private_bytes(privkey_bytes), master_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a contacc auth token")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--ttl", type=int, default=86400 * 30, help="Lifetime in seconds (default: 30 days)")
    parser.add_argument("--recipient", help="Recipient identity (provider:identifier) for a DB-backed token")
    parser.add_argument("--add-recipient", help="Display name to use when creating the recipient (requires --recipient)")
    parser.add_argument("--key-stdin", action="store_true")
    args = parser.parse_args()

    config = NodeConfig.load(args.config)
    passphrase = sys.stdin.readline().rstrip("\n") if args.key_stdin else getpass.getpass("Passphrase: ")

    result = _load_private_key(config, passphrase)
    private_key, master_key = result
    auth_setup(private_key)

    if args.recipient is None:
        # Owner token: Ed25519-signed, no DB
        print(issue_token(ttl_seconds=args.ttl))
        return

    # Recipient token: DB-backed
    _, db_key = derive_subkeys(master_key)
    db = open_db(str(Path(config.store_path) / "db"), db_key)

    row = db.execute("SELECT id FROM recipients WHERE identity = ?", (args.recipient,)).fetchone()
    if row is None:
        if args.add_recipient is None:
            print(f"Recipient '{args.recipient}' not found. Use --add-recipient <display_name> to create them.", file=sys.stderr)
            sys.exit(1)
        recipient_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
            (recipient_id, args.recipient, args.add_recipient),
        )
        db.commit()
        print(f"Created recipient: {args.recipient} ({args.add_recipient})", file=sys.stderr)
    else:
        recipient_id = row[0]

    token = issue_node_token(db, recipient_id, ttl_seconds=args.ttl)
    print(token)
    db.close()


if __name__ == "__main__":
    main()

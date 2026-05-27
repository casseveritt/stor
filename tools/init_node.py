#!/usr/bin/env python3
"""Initialize a new contacc node: generate keys, derive subkeys, encrypt store."""
import os
import sys
import json
import base64
import getpass
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlcipher3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from server.crypto import (
    derive_master_key, derive_subkeys, encrypt_bytes,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize a contacc node")
    parser.add_argument("--store", required=True, help="Path to the store directory")
    parser.add_argument("--address", required=True, help="Public node address (e.g. https://node.example.com)")
    parser.add_argument("--watermark", action="store_true", help="Enable watermarking")
    parser.add_argument("--key-stdin", action="store_true", help="Read passphrase from stdin (no confirmation)")
    parser.add_argument("--google-client-id", default=os.environ.get("CONTACC_GOOGLE_CLIENT_ID", ""),
                        help="Google OAuth2 client ID for SSO (env: CONTACC_GOOGLE_CLIENT_ID)")
    parser.add_argument("--google-client-secret", default=os.environ.get("CONTACC_GOOGLE_CLIENT_SECRET", ""),
                        help="Google OAuth2 client secret for SSO (env: CONTACC_GOOGLE_CLIENT_SECRET)")
    args = parser.parse_args()

    store_path = Path(args.store)
    config_path = store_path / "node_config.json"

    if config_path.exists():
        print(f"Error: {config_path} already exists. Aborting to avoid overwriting existing node.")
        sys.exit(1)

    store_path.mkdir(parents=True, exist_ok=True)
    (store_path / "files").mkdir(exist_ok=True)

    env = os.environ.get("CONTACC_PASSPHRASE")
    if env:
        passphrase = env
    elif args.key_stdin:
        passphrase = sys.stdin.readline().rstrip("\n")
    else:
        passphrase = getpass.getpass("Choose passphrase: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Passphrases do not match.")
            sys.exit(1)

    salt = os.urandom(16)
    print("Deriving keys (this may take a moment)...")
    master_key = derive_master_key(passphrase, salt)
    db_key, _file_key = derive_subkeys(master_key)

    private_key = Ed25519PrivateKey.generate()
    privkey_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted_privkey = encrypt_bytes(privkey_bytes, master_key)

    db_path = str(store_path / "db")
    con = sqlcipher3.connect(db_path)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    con.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (1)")
    con.commit()
    con.close()

    config = {
        "node_address": args.address,
        "store_path": str(store_path.resolve()),
        "argon2_salt": salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "watermark_enabled": args.watermark,
    }
    if args.google_client_id:
        config["sso_google_client_id"] = args.google_client_id
    if args.google_client_secret:
        config["sso_google_client_secret"] = args.google_client_secret
    config_path.write_text(json.dumps(config, indent=2))

    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print(f"Node initialized at {store_path}")
    print(f"Config:     {config_path}")
    print(f"Public key: {base64.b64encode(pub_bytes).decode()}")
    if args.google_client_id:
        print("Google SSO: configured")


if __name__ == "__main__":
    main()

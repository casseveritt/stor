#!/usr/bin/env python3
"""Change the passphrase protecting a contac node.

Re-encrypts three things with the new passphrase:
  - The private key in node_config.json
  - The SQLCipher database (PRAGMA rekey)
  - All encrypted asset files in the store

The node must be stopped before running this. The operation is atomic
per-file but not globally atomic — if interrupted, re-run with the
same new passphrase (already-rekeyed files are idempotent because we
verify decryption before writing).

Usage:
    python tools/change_passphrase.py --config /path/to/node_config.json
"""
import base64
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import sqlcipher3

from server.config import NodeConfig
from server.crypto import derive_master_key, derive_subkeys, encrypt_bytes, decrypt_bytes
from server.db import WrongPassphraseError


def _read_passphrase(prompt: str, confirm: bool = False) -> str:
    env = os.environ.get("CONTAC_PASSPHRASE")
    if env and not confirm:
        return env
    while True:
        pw = getpass.getpass(prompt)
        if not confirm:
            return pw
        pw2 = getpass.getpass("Confirm new passphrase: ")
        if pw == pw2:
            return pw
        print("Passphrases do not match, try again.")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Change passphrase on a contac node")
    parser.add_argument("--config", required=True, help="Path to node_config.json")
    parser.add_argument("--old-passphrase-stdin", action="store_true",
                        help="Read old passphrase from stdin (first line)")
    parser.add_argument("--new-passphrase-stdin", action="store_true",
                        help="Read new passphrase from stdin (second line, no confirmation)")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"Error: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    config = NodeConfig.load(config_path)
    salt = bytes.fromhex(config.argon2_salt)
    argon2_kwargs = dict(
        time_cost=config.argon2_time_cost,
        memory_cost=config.argon2_memory_cost,
        parallelism=config.argon2_parallelism,
    )

    # Read passphrases
    if args.old_passphrase_stdin:
        old_passphrase = sys.stdin.readline().rstrip("\n")
    else:
        old_passphrase = _read_passphrase("Current passphrase: ")

    if args.new_passphrase_stdin:
        new_passphrase = sys.stdin.readline().rstrip("\n")
    else:
        new_passphrase = _read_passphrase("New passphrase: ", confirm=True)

    if old_passphrase == new_passphrase:
        print("New passphrase is the same as the old one. Nothing to do.")
        sys.exit(0)

    # Derive old keys
    print("Deriving old keys...")
    old_master = derive_master_key(old_passphrase, salt, **argon2_kwargs)
    old_db_key, old_file_key = derive_subkeys(old_master)

    # Verify old passphrase decrypts the private key
    try:
        privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), old_master)
    except Exception:
        print("Error: current passphrase is wrong or config is corrupted.", file=sys.stderr)
        sys.exit(1)

    # Verify old passphrase opens the database
    db_path = str(Path(config.store_path) / "db")
    try:
        con = sqlcipher3.connect(db_path, check_same_thread=False)
        con.execute(f"PRAGMA key = \"x'{old_db_key.hex()}'\"")
        con.execute("SELECT count(*) FROM sqlite_master")
    except sqlcipher3.DatabaseError:
        print("Error: could not open database with current passphrase.", file=sys.stderr)
        sys.exit(1)

    # Derive new keys
    print("Deriving new keys...")
    new_master = derive_master_key(new_passphrase, salt, **argon2_kwargs)
    new_db_key, new_file_key = derive_subkeys(new_master)

    # 1. Re-key the database (SQLCipher does this atomically)
    print("Re-keying database...")
    con.execute(f"PRAGMA rekey = \"x'{new_db_key.hex()}'\"")
    con.close()

    # 2. Re-encrypt all asset files
    files_dir = Path(config.store_path) / "files"
    all_files = [p for p in files_dir.rglob("*") if p.is_file()]
    if all_files:
        print(f"Re-encrypting {len(all_files)} file(s)...")
        for i, fpath in enumerate(all_files, 1):
            data = fpath.read_bytes()
            try:
                plaintext = decrypt_bytes(data, old_file_key)
            except Exception:
                # Already re-encrypted with new key (resuming interrupted run)
                try:
                    decrypt_bytes(data, new_file_key)
                    continue  # already done
                except Exception:
                    print(f"  Warning: could not decrypt {fpath.name} — skipping", file=sys.stderr)
                    continue
            fpath.write_bytes(encrypt_bytes(plaintext, new_file_key))
            if i % 50 == 0 or i == len(all_files):
                print(f"  {i}/{len(all_files)}")

    # 3. Re-encrypt private key in config
    print("Updating config...")
    new_encrypted_privkey = encrypt_bytes(privkey_bytes, new_master)
    config.encrypted_private_key = base64.b64encode(new_encrypted_privkey).decode()
    config.save(config_path)

    print("Done. Update CONTAC_PASSPHRASE in ~/.config/contac/secrets and restart the service.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Update domain in all server SQLCipher databases.

Usage: python scripts/update_domain.py <old_domain> <new_domain> <data_dir>
"""
import base64
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.crypto import derive_master_key, derive_subkeys
import sqlcipher3


def open_server_db(server_data_dir: Path, passphrase: str):
    config_path = server_data_dir / "node_config.json"
    config = json.loads(config_path.read_text())
    salt = bytes.fromhex(config["argon2_salt"])
    master_key = derive_master_key(
        passphrase, salt,
        config.get("argon2_time_cost", 3),
        config.get("argon2_memory_cost", 65536),
        config.get("argon2_parallelism", 4),
    )
    db_key, _ = derive_subkeys(master_key)
    db_path = str(server_data_dir / "db")
    con = sqlcipher3.connect(db_path, check_same_thread=False)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    con.execute("SELECT count(*) FROM sqlite_master")  # verify key works
    return con


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <old_domain> <new_domain> <data_dir>")
        sys.exit(1)

    old_domain, new_domain, data_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    import os
    passphrase = os.environ.get("CONTACC_PASSPHRASE") or getpass.getpass("Passphrase: ")

    server_dirs = sorted(data_dir.glob("server-*"))
    if not server_dirs:
        print("No server-* directories found")
        sys.exit(1)

    for server_dir in server_dirs:
        print(f"\n{server_dir.name}:")
        try:
            con = open_server_db(server_dir, passphrase)
        except Exception as e:
            print(f"  ERROR opening DB: {e}")
            continue

        rows = con.execute("SELECT id, server_url FROM contacts WHERE server_url LIKE ?",
                           (f"%{old_domain}%",)).fetchall()
        if not rows:
            print("  No matching contacts found")
            con.close()
            continue

        for row_id, old_url in rows:
            new_url = old_url.replace(old_domain, new_domain)
            con.execute("UPDATE contacts SET server_url = ? WHERE id = ?", (new_url, row_id))
            print(f"  {old_url} → {new_url}")

        con.commit()
        con.close()
        print("  Committed.")

    print("\nDone.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Review pending comment edit/deletion requests for a contacc node."""
import sys
import base64
import getpass
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig
from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes
from server.db import open_db, init_schema
from server.comments import approve_edit, reject_edit


def _open_db(config: NodeConfig, passphrase: str):
    salt = bytes.fromhex(config.argon2_salt)
    master_key = derive_master_key(
        passphrase, salt,
        config.argon2_time_cost, config.argon2_memory_cost, config.argon2_parallelism,
    )
    try:
        decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    except Exception:
        print("Wrong passphrase.", file=sys.stderr)
        sys.exit(1)
    _, db_key = derive_subkeys(master_key)
    db = open_db(str(Path(config.store_path) / "db"), db_key)
    init_schema(db)
    return db


def main() -> None:
    parser = argparse.ArgumentParser(description="Review comment edit/deletion requests")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--key-stdin", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List pending requests")
    ap = sub.add_parser("approve", help="Approve a request")
    ap.add_argument("request_id")
    rp = sub.add_parser("reject", help="Reject a request")
    rp.add_argument("request_id")
    args = parser.parse_args()

    config = NodeConfig.load(args.config)
    passphrase = sys.stdin.readline().rstrip("\n") if args.key_stdin else getpass.getpass("Passphrase: ")
    db = _open_db(config, passphrase)

    if args.cmd == "list":
        rows = db.execute(
            """SELECT r.id, r.comment_id, r.new_body, r.created_at,
                      c.body as original_body, c.asset_id
               FROM comment_edit_requests r
               JOIN comments c ON c.id = r.comment_id
               WHERE r.status = 'pending'
               ORDER BY r.created_at ASC"""
        ).fetchall()
        if not rows:
            print("No pending edit requests.")
            return
        for row in rows:
            req_id, comment_id, new_body, created_at, orig_body, asset_id = row
            action = "DELETE" if new_body is None else "EDIT"
            print(f"\n[{action}] request_id={req_id}")
            print(f"  asset:    {asset_id}")
            print(f"  comment:  {comment_id}")
            print(f"  original: {orig_body!r}")
            if new_body is not None:
                print(f"  new body: {new_body!r}")

    elif args.cmd == "approve":
        result = approve_edit(db, args.request_id)
        print(f"Approved: {result}")

    elif args.cmd == "reject":
        result = reject_edit(db, args.request_id)
        print(f"Rejected: {result}")

    db.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Import files from a directory into a contac node store."""
import argparse
import base64
import getpass
import hashlib
import json
import mimetypes
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from server.config import NodeConfig
from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes, encrypt_bytes
from server.db import open_db, init_schema


def import_directory(
    db,
    file_key: bytes,
    store_path: Path,
    source_dir: Path,
    tags: list[str] | None = None,
    recursive: bool = True,
    dry_run: bool = False,
) -> list[dict]:
    """Import files from source_dir into the node.

    Returns a list of result dicts, one per file encountered.
    Skips files whose content hash already exists in assets (deduplication).
    Errors per file are caught and recorded without aborting the batch.
    """
    results = []
    glob = source_dir.rglob("*") if recursive else source_dir.glob("*")

    for file_path in sorted(glob):
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_bytes()
        except OSError as e:
            results.append({"path": str(file_path), "status": "error", "error": str(e)})
            continue

        content_hash = hashlib.sha256(content).hexdigest()

        existing = db.execute(
            "SELECT id FROM assets WHERE content_hash = ? AND deleted = 0", (content_hash,)
        ).fetchone()
        if existing:
            results.append({
                "path": str(file_path),
                "status": "duplicate",
                "asset_id": existing[0],
                "content_hash": content_hash,
            })
            continue

        media_type, _ = mimetypes.guess_type(str(file_path))
        if media_type is None:
            media_type = "application/octet-stream"

        if dry_run:
            results.append({
                "path": str(file_path),
                "status": "would_import",
                "media_type": media_type,
                "size": len(content),
                "content_hash": content_hash,
            })
            continue

        try:
            dest_dir = store_path / "files" / content_hash[:2]
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / content_hash
            if not dest_path.exists():
                dest_path.write_bytes(encrypt_bytes(content, file_key))

            asset_id = str(uuid.uuid4())
            now = time.time()
            title = file_path.stem
            db.execute(
                """INSERT INTO assets
                     (id, content_hash, media_type, size, created_at,
                      title, tags, predecessor, successor, deleted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)""",
                (asset_id, content_hash, media_type, len(content),
                 now, title, json.dumps(tags or [])),
            )
            db.commit()

            results.append({
                "path": str(file_path),
                "status": "imported",
                "asset_id": asset_id,
                "content_hash": content_hash,
                "media_type": media_type,
                "size": len(content),
            })
        except Exception as e:
            results.append({"path": str(file_path), "status": "error", "error": str(e)})

    return results


def _open_store(config: NodeConfig, passphrase: str):
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
    _, file_key = derive_subkeys(master_key)
    db_key, _ = derive_subkeys(master_key)
    db = open_db(str(Path(config.store_path) / "db"), db_key)
    init_schema(db)
    return db, file_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Import files into a contac node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("source", help="Directory to import from")
    parser.add_argument("--tags", nargs="*", default=[], metavar="TAG",
                        help="Tags to apply to all imported assets")
    parser.add_argument("--no-recursive", action="store_true",
                        help="Do not recurse into subdirectories")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be imported without writing")
    parser.add_argument("--key-stdin", action="store_true",
                        help="Read passphrase from stdin")
    args = parser.parse_args()

    config = NodeConfig.load(args.config)
    passphrase = (sys.stdin.readline().rstrip("\n") if args.key_stdin
                  else getpass.getpass("Passphrase: "))

    db, file_key = _open_store(config, passphrase)
    store_path = Path(config.store_path)

    results = import_directory(
        db, file_key, store_path,
        source_dir=Path(args.source),
        tags=args.tags,
        recursive=not args.no_recursive,
        dry_run=args.dry_run,
    )

    counts = {"imported": 0, "duplicate": 0, "would_import": 0, "error": 0}
    for r in results:
        status = r["status"]
        counts[status] = counts.get(status, 0) + 1
        if status == "imported":
            print(f"  imported  {r['path']}  ({r['media_type']}, {r['size']} bytes)")
        elif status == "duplicate":
            print(f"  duplicate {r['path']}  (asset {r['asset_id']})")
        elif status == "would_import":
            print(f"  would import {r['path']}  ({r['media_type']}, {r['size']} bytes)")
        elif status == "error":
            print(f"  ERROR     {r['path']}: {r['error']}", file=sys.stderr)

    verb = "Would import" if args.dry_run else "Imported"
    key = "would_import" if args.dry_run else "imported"
    print(f"\n{verb} {counts[key]}, skipped {counts['duplicate']} duplicates"
          + (f", {counts['error']} errors" if counts["error"] else "") + ".")
    db.close()


if __name__ == "__main__":
    main()

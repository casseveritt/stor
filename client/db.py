import hashlib
import json
import sqlite3
import logging
import time
from pathlib import Path

import sqlcipher3

log = logging.getLogger("contacc")


def open_client_db(data_dir: Path, db_key: bytes) -> sqlcipher3.Connection:
    """Open (or create) the encrypted client DB. Migrates from plaintext if needed."""
    db_path = data_dir / "client.db"

    if db_path.exists():
        try:
            con = _open_encrypted(db_path, db_key)
            _init_schema(con)
            return con
        except Exception:
            log.info("Migrating client DB from plaintext to encrypted")
            _migrate_plaintext_to_encrypted(db_path, db_key)

    con = _open_encrypted(db_path, db_key)
    _init_schema(con)
    return con


def open_client_db_memory() -> sqlite3.Connection:
    """Unencrypted in-memory DB for the pre-setup phase (no node key yet)."""
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.row_factory = sqlite3.Row
    _init_schema(con)
    return con


def _open_encrypted(db_path: Path, db_key: bytes) -> sqlcipher3.Connection:
    con = sqlcipher3.connect(str(db_path), check_same_thread=False)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    con.execute("PRAGMA journal_mode=WAL")
    con.row_factory = sqlcipher3.Row
    con.execute("SELECT count(*) FROM sqlite_master")  # verify key
    return con


def _migrate_plaintext_to_encrypted(db_path: Path, db_key: bytes) -> None:
    rows = []
    try:
        plain = sqlite3.connect(str(db_path))
        try:
            rows = plain.execute("SELECT server_url, tag, updated_at FROM users").fetchall()
        except Exception:
            pass
        plain.close()
    except Exception:
        pass

    tmp_path = db_path.with_suffix(".db.tmp")
    con = sqlcipher3.connect(str(tmp_path), check_same_thread=False)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    con.execute("PRAGMA journal_mode=WAL")
    con.row_factory = sqlcipher3.Row
    _init_schema(con)
    for server_url, tag, updated_at in rows:
        con.execute(
            "INSERT OR REPLACE INTO users (server_url, tag, updated_at) VALUES (?, ?, ?)",
            (server_url, tag, updated_at),
        )
    con.commit()
    con.close()

    db_path.unlink()
    tmp_path.rename(db_path)


def _init_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            server_url  TEXT PRIMARY KEY,
            tag         TEXT,
            updated_at  INTEGER DEFAULT 0
        )
    """)
    # Migrate: convert seconds to nanoseconds
    try:
        db.execute("UPDATE users SET updated_at = updated_at * 1000000000 WHERE updated_at < 1000000000000")
    except Exception:
        pass
    db.execute("""
        CREATE TABLE IF NOT EXISTS contact_tags (
            node_id     TEXT PRIMARY KEY,
            tag         TEXT,
            updated_at  INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS contact_poll (
            node_id     TEXT PRIMARY KEY,
            last_update INTEGER DEFAULT 0,
            last_check  INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS node_lists (
            list_id    TEXT PRIMARY KEY,
            node_ids   TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    db.commit()


def get_tag(db, node_id: str) -> str | None:
    row = db.execute("SELECT tag FROM contact_tags WHERE node_id = ?", (node_id,)).fetchone()
    return row["tag"] if row else None


def set_tag(db, node_id: str, tag: str | None) -> None:
    db.execute(
        "INSERT INTO contact_tags (node_id, tag, updated_at) VALUES (?, ?, ?)"
        " ON CONFLICT(node_id) DO UPDATE SET tag = excluded.tag, updated_at = excluded.updated_at",
        (node_id, tag or None, time.time_ns()),
    )
    db.commit()


def get_all_tags(db) -> dict[str, str | None]:
    rows = db.execute("SELECT node_id, tag FROM contact_tags").fetchall()
    return {row["node_id"]: row["tag"] for row in rows}


def get_contact_poll(db, node_id: str) -> tuple[int, int]:
    """Returns (last_update_ns, last_check_ns). Both 0 if never polled."""
    row = db.execute(
        "SELECT last_update, last_check FROM contact_poll WHERE node_id = ?", (node_id,)
    ).fetchone()
    return (row["last_update"], row["last_check"]) if row else (0, 0)


def set_contact_poll(db, node_id: str, *, last_update: int | None = None, last_check: int | None = None) -> None:
    db.execute(
        "INSERT INTO contact_poll (node_id) VALUES (?) ON CONFLICT(node_id) DO NOTHING", (node_id,)
    )
    if last_update is not None:
        db.execute("UPDATE contact_poll SET last_update = ? WHERE node_id = ?", (last_update, node_id))
    if last_check is not None:
        db.execute("UPDATE contact_poll SET last_check = ? WHERE node_id = ?", (last_check, node_id))
    db.commit()


def node_list_id(node_ids: list[str]) -> str:
    """Canonical content-addressed id for a set of node_ids: sha256 of sorted members."""
    canonical = "\n".join(sorted(set(node_ids)))
    return hashlib.sha256(canonical.encode()).hexdigest()


def store_node_list(db, node_ids: list[str]) -> str:
    """Store a node list (idempotent). Returns the list_id."""
    members = sorted(set(node_ids))
    lid = node_list_id(members)
    db.execute(
        "INSERT OR IGNORE INTO node_lists (list_id, node_ids, created_at) VALUES (?, ?, ?)",
        (lid, json.dumps(members), time.time_ns()),
    )
    db.commit()
    return lid


def get_node_list(db, list_id: str) -> list[str] | None:
    row = db.execute("SELECT node_ids FROM node_lists WHERE list_id = ?", (list_id,)).fetchone()
    return json.loads(row["node_ids"]) if row else None


def get_all_node_lists(db) -> list[dict]:
    rows = db.execute("SELECT list_id, node_ids, created_at FROM node_lists ORDER BY created_at").fetchall()
    return [{"list_id": r["list_id"], "node_ids": json.loads(r["node_ids"]), "created_at": r["created_at"]} for r in rows]

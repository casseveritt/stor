import sqlite3
import logging
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
            updated_at  REAL DEFAULT (unixepoch())
        )
    """)
    db.commit()


def get_tag(db, server_url: str) -> str | None:
    row = db.execute("SELECT tag FROM users WHERE server_url = ?", (server_url,)).fetchone()
    return row["tag"] if row else None


def set_tag(db, server_url: str, tag: str | None) -> None:
    db.execute(
        "INSERT INTO users (server_url, tag, updated_at) VALUES (?, ?, unixepoch())"
        " ON CONFLICT(server_url) DO UPDATE SET tag = excluded.tag, updated_at = unixepoch()",
        (server_url, tag or None),
    )
    db.commit()


def get_all_tags(db) -> dict[str, str | None]:
    rows = db.execute("SELECT server_url, tag FROM users").fetchall()
    return {row["server_url"]: row["tag"] for row in rows}

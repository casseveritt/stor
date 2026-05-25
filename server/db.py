import sqlcipher3


class WrongPassphraseError(Exception):
    pass


def open_db(db_path: str, db_key: bytes) -> sqlcipher3.Connection:
    con = sqlcipher3.connect(db_path, check_same_thread=False)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    try:
        con.execute("SELECT count(*) FROM sqlite_master")
    except sqlcipher3.DatabaseError as e:
        con.close()
        raise WrongPassphraseError("Wrong passphrase or corrupted database") from e
    return con


def init_schema(con: sqlcipher3.Connection) -> None:
    con.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)"
    )
    con.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id           TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            media_type   TEXT NOT NULL,
            size         INTEGER NOT NULL,
            created_at   REAL NOT NULL,
            title        TEXT,
            tags         TEXT,
            predecessor  TEXT,
            successor    TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS recipients (
            id           TEXT PRIMARY KEY,
            identity     TEXT NOT NULL UNIQUE,
            display_name TEXT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS acl (
            asset_id     TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            PRIMARY KEY (asset_id, recipient_id)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id           TEXT PRIMARY KEY,
            recipient_id TEXT,
            expiry       REAL NOT NULL,
            revoked      INTEGER NOT NULL DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS identity_mappings (
            identity     TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS sso_states (
            state    TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            expiry   REAL NOT NULL
        )
    """)
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (4)")
    con.commit()

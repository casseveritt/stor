import time as _time

import sqlcipher3

NS = 1_000_000_000  # nanoseconds per second


def now_ns() -> int:
    """Current time as Unix nanoseconds (int64). Uses time.time_ns() for exact precision."""
    return _time.time_ns()


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
            created_at   INTEGER NOT NULL,
            title        TEXT,
            tags         TEXT,
            predecessor  TEXT,
            successor    TEXT,
            deleted      INTEGER NOT NULL DEFAULT 0,
            is_public    INTEGER NOT NULL DEFAULT 0
        )
    """)
    # migration for existing DBs that predate the deleted column
    try:
        con.execute("ALTER TABLE assets ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0")
        con.commit()
    except Exception:
        pass
    try:
        con.execute("ALTER TABLE assets ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0")
        con.commit()
    except Exception:
        pass
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
            expiry       INTEGER NOT NULL,
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
            state     TEXT PRIMARY KEY,
            provider  TEXT NOT NULL,
            expiry    INTEGER NOT NULL,
            return_to TEXT NOT NULL DEFAULT ''
        )
    """)
    try:
        con.execute("ALTER TABLE sso_states ADD COLUMN return_to TEXT NOT NULL DEFAULT ''")
        con.commit()
    except Exception:
        pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id             TEXT PRIMARY KEY,
            body           TEXT NOT NULL DEFAULT '',
            created_at     INTEGER NOT NULL,
            tags           TEXT,
            is_public      INTEGER NOT NULL DEFAULT 0,
            deleted        INTEGER NOT NULL DEFAULT 0,
            post_type      TEXT NOT NULL DEFAULT 'post',
            visibility     TEXT NOT NULL DEFAULT 'contacts',
            comment_access TEXT NOT NULL DEFAULT 'contacts'
        )
    """)
    try:
        con.execute("ALTER TABLE posts ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0")
        con.commit()
    except Exception:
        pass
    try:
        con.execute("ALTER TABLE posts ADD COLUMN post_type TEXT NOT NULL DEFAULT 'post'")
        con.commit()
    except Exception:
        pass
    try:
        con.execute("ALTER TABLE posts ADD COLUMN visibility TEXT NOT NULL DEFAULT 'contacts'")
        con.commit()
        # migrate: public posts → 'public', private posts → 'private'
        con.execute("UPDATE posts SET visibility = 'public' WHERE is_public = 1 AND visibility = 'contacts'")
        con.execute("UPDATE posts SET visibility = 'private' WHERE is_public = 0 AND visibility = 'contacts'")
        con.commit()
    except Exception:
        pass
    try:
        con.execute("ALTER TABLE posts ADD COLUMN comment_access TEXT NOT NULL DEFAULT 'contacts'")
        con.commit()
    except Exception:
        pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS post_tags (
            post_id TEXT NOT NULL,
            tag     TEXT NOT NULL,
            PRIMARY KEY (post_id, tag)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS post_assets (
            post_id  TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            PRIMARY KEY (post_id, asset_id)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS post_acl (
            post_id      TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            PRIMARY KEY (post_id, recipient_id)
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id                  TEXT PRIMARY KEY,
            content_hash        TEXT NOT NULL,
            asset_id            TEXT,
            post_id             TEXT,
            parent_id           TEXT,
            author_recipient_id TEXT,
            body                TEXT NOT NULL,
            created_at          INTEGER NOT NULL,
            predecessor         TEXT,
            successor           TEXT,
            deleted             INTEGER NOT NULL DEFAULT 0
        )
    """)
    # migrate existing DBs: make asset_id nullable, add post_id
    try:
        con.execute("SELECT post_id FROM comments LIMIT 1")
    except Exception:
        con.execute("ALTER TABLE comments RENAME TO _comments_v1")
        con.execute("""
            CREATE TABLE comments (
                id                  TEXT PRIMARY KEY,
                content_hash        TEXT NOT NULL,
                asset_id            TEXT,
                post_id             TEXT,
                parent_id           TEXT,
                author_recipient_id TEXT,
                body                TEXT NOT NULL,
                created_at          INTEGER NOT NULL,
                predecessor         TEXT,
                successor           TEXT,
                deleted             INTEGER NOT NULL DEFAULT 0
            )
        """)
        con.execute("""
            INSERT INTO comments (id, content_hash, asset_id, post_id, parent_id,
                                  author_recipient_id, body, created_at,
                                  predecessor, successor, deleted)
            SELECT id, content_hash, asset_id, NULL, parent_id,
                   author_recipient_id, body, created_at,
                   predecessor, successor, deleted
            FROM _comments_v1
        """)
        con.execute("DROP TABLE _comments_v1")
        con.commit()
    # migrate: add author_identity column for federated comment attribution
    try:
        con.execute("SELECT author_identity FROM comments LIMIT 1")
    except Exception:
        con.execute("ALTER TABLE comments ADD COLUMN author_identity TEXT")
        con.commit()
    con.execute("""
        CREATE TABLE IF NOT EXISTS comment_edit_requests (
            id                     TEXT PRIMARY KEY,
            comment_id             TEXT NOT NULL,
            requester_recipient_id TEXT,
            new_body               TEXT,
            created_at             INTEGER NOT NULL,
            status                 TEXT NOT NULL DEFAULT 'pending'
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id             TEXT PRIMARY KEY,
            asset_id       TEXT NOT NULL,
            recipient_id   TEXT,
            share_identity TEXT,
            endpoint       TEXT NOT NULL,
            accessed_at    INTEGER NOT NULL
        )
    """)
    con.execute(
        "CREATE INDEX IF NOT EXISTS access_log_asset_idx ON access_log (asset_id, accessed_at DESC)"
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS access_log_recipient_idx ON access_log (recipient_id, accessed_at DESC)"
    )
    con.execute("""
        CREATE TABLE IF NOT EXISTS profile (
            id                INTEGER PRIMARY KEY DEFAULT 1,
            display_name      TEXT,
            photo_content_hash TEXT,
            photo_media_type  TEXT
        )
    """)
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (7)")
    # schema version 9: rename contacts → users, add relationship column
    # Check both tables first to handle partial/failed migration on previous run.
    _contacts_exists = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='contacts'"
    ).fetchone()
    _users_exists = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if _contacts_exists:
        # contacts table still exists — need to rename it.
        # If an empty users shell was created by a failed previous run, drop it first.
        if _users_exists:
            con.execute("DROP TABLE users")
        try:
            con.execute("SELECT public_key FROM contacts LIMIT 1")
        except Exception:
            con.execute("ALTER TABLE contacts ADD COLUMN public_key TEXT")
            con.commit()
        con.execute("ALTER TABLE contacts RENAME TO users")
        con.commit()
    elif not _users_exists:
        # Fresh install: create users table directly.
        con.execute("""
            CREATE TABLE users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                server_url   TEXT NOT NULL UNIQUE,
                name         TEXT,
                handle       TEXT,
                public_key   TEXT,
                relationship TEXT NOT NULL DEFAULT 'contact'
            )
        """)
        con.commit()
    # Add relationship column if missing (upgrade existing users table).
    try:
        con.execute("SELECT relationship FROM users LIMIT 1")
    except Exception:
        con.execute("ALTER TABLE users ADD COLUMN relationship TEXT NOT NULL DEFAULT 'contact'")
        con.commit()
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (9)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id          TEXT NOT NULL,
            comment_id       TEXT NOT NULL DEFAULT '',
            emoji            TEXT NOT NULL,
            reactor_identity TEXT NOT NULL DEFAULT '',
            created_at       INTEGER NOT NULL,
            UNIQUE(post_id, comment_id, emoji, reactor_identity)
        )
    """)
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (8)")
    con.commit()

    # schema version 10: timestamps → int64 nanoseconds
    # Existing values are float seconds (~1.7e9); multiply by 1e9 to convert.
    # The WHERE guard (< 1e12) prevents double-conversion on re-run.
    if not con.execute("SELECT 1 FROM schema_version WHERE version=10").fetchone():
        for _tbl, _col in [
            ("posts",                "created_at"),
            ("assets",               "created_at"),
            ("comments",             "created_at"),
            ("comment_edit_requests","created_at"),
            ("reactions",            "created_at"),
            ("access_log",           "accessed_at"),
            ("tokens",               "expiry"),
            ("sso_states",           "expiry"),
        ]:
            try:
                con.execute(
                    f"UPDATE {_tbl} SET {_col} = CAST({_col} * 1000000000 AS INTEGER)"
                    f" WHERE {_col} < 1000000000000"
                )
            except Exception:
                pass
        con.execute("INSERT OR IGNORE INTO schema_version VALUES (10)")
        con.commit()

    # Add user_id to users table and notifications table
    try:
        con.execute("ALTER TABLE users ADD COLUMN user_id TEXT")
        con.commit()
    except Exception:
        pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS mention_notifications (
            id           TEXT PRIMARY KEY,
            post_id      TEXT NOT NULL,
            author_server TEXT NOT NULL,
            author_handle TEXT,
            received_at  INTEGER NOT NULL,
            seen         INTEGER NOT NULL DEFAULT 0
        )
    """)
    con.commit()

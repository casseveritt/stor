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

    # Add user_id, weight, and node_id to users table
    for _col in ["user_id TEXT", "weight REAL", "node_id TEXT"]:
        try:
            con.execute(f"ALTER TABLE users ADD COLUMN {_col}")
            con.commit()
        except Exception:
            pass
    for _col in ["notif_type TEXT DEFAULT 'mention'", "actor_name TEXT", "emoji TEXT"]:
        try:
            con.execute(f"ALTER TABLE mention_notifications ADD COLUMN {_col}")
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
    con.execute("""
        CREATE TABLE IF NOT EXISTS dm_threads (
            thread_id    TEXT PRIMARY KEY,
            peer_node_id TEXT NOT NULL,
            peer_url     TEXT NOT NULL,
            peer_name    TEXT,
            peer_dh_pub  TEXT,
            last_msg_at  INTEGER NOT NULL DEFAULT 0,
            unread_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Dedup dm_threads by peer_node_id before enforcing uniqueness
    _nid_rows = con.execute("SELECT peer_node_id FROM dm_threads GROUP BY peer_node_id HAVING COUNT(*) > 1").fetchall()
    _changed = False
    for (_nid,) in _nid_rows:
        _threads = con.execute("SELECT thread_id FROM dm_threads WHERE peer_node_id = ? ORDER BY last_msg_at DESC", (_nid,)).fetchall()
        for (_tid,) in _threads[1:]:
            con.execute("DELETE FROM dm_messages WHERE thread_id = ?", (_tid,))
            con.execute("DELETE FROM dm_threads WHERE thread_id = ?", (_tid,))
        _changed = True
    if _changed:
        con.commit()
    con.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS dm_threads_peer_node_id
        ON dm_threads(peer_node_id)
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS dm_messages (
            id           TEXT PRIMARY KEY,
            thread_id    TEXT NOT NULL,
            direction    TEXT NOT NULL CHECK (direction IN ('in', 'out')),
            body_enc     TEXT NOT NULL,
            created_at   INTEGER NOT NULL,
            delivered_at INTEGER,
            seen_at      INTEGER
        )
    """)
    con.commit()

    # Purge anonymous reactions — only attributed reactions are kept.
    con.execute("DELETE FROM reactions WHERE reactor_identity IN ('<anon>', '__anon__')")
    con.commit()

    # Migrate reactions: convert public-key reactor_identity to node_id where possible,
    # and delete any reaction whose identity can't be resolved to a known node_id.
    _special_ids = {"", "<anon>", "__anon__"}
    _nid_set = {r[0] for r in con.execute(
        "SELECT node_id FROM users WHERE node_id IS NOT NULL").fetchall()}
    _pub_to_nid = {r[0]: r[1] for r in con.execute(
        "SELECT public_key, node_id FROM users WHERE public_key IS NOT NULL AND node_id IS NOT NULL"
    ).fetchall()}
    _stale_identities = [
        r[0] for r in con.execute("SELECT DISTINCT reactor_identity FROM reactions").fetchall()
        if r[0] not in _special_ids and r[0] not in _nid_set
    ]
    for _rid in _stale_identities:
        if _rid in _pub_to_nid:
            _nid = _pub_to_nid[_rid]
            # Remove pubkey reaction wherever a node_id reaction already covers the same slot.
            con.execute("""
                DELETE FROM reactions WHERE reactor_identity = ?
                AND EXISTS (
                    SELECT 1 FROM reactions r2
                    WHERE r2.post_id = reactions.post_id
                    AND r2.comment_id = reactions.comment_id
                    AND r2.emoji = reactions.emoji
                    AND r2.reactor_identity = ?
                )
            """, (_rid, _nid))
            con.execute(
                "UPDATE reactions SET reactor_identity = ? WHERE reactor_identity = ?",
                (_nid, _rid))
        else:
            con.execute("DELETE FROM reactions WHERE reactor_identity = ?", (_rid,))
    if _stale_identities:
        con.commit()

    # Migrate recipients.identity and comments.author_identity from server_url to node_id.
    # Only updates rows where a matching users entry has a node_id; leaves the rest unchanged.
    _recipients_migrated = con.execute("""
        UPDATE recipients SET identity = (
            SELECT u.node_id FROM users u WHERE u.server_url = recipients.identity AND u.node_id IS NOT NULL
        )
        WHERE (
            SELECT u.node_id FROM users u WHERE u.server_url = recipients.identity AND u.node_id IS NOT NULL
        ) IS NOT NULL
    """).rowcount
    if _recipients_migrated:
        con.execute("""
            UPDATE comments SET author_identity = (
                SELECT u.node_id FROM users u WHERE u.server_url = comments.author_identity AND u.node_id IS NOT NULL
            )
            WHERE author_identity IS NOT NULL AND author_identity != ''
              AND (
                SELECT u.node_id FROM users u WHERE u.server_url = comments.author_identity AND u.node_id IS NOT NULL
              ) IS NOT NULL
        """)
        con.execute("""
            UPDATE mention_notifications SET author_server = (
                SELECT u.node_id FROM users u WHERE u.server_url = mention_notifications.author_server AND u.node_id IS NOT NULL
            )
            WHERE author_server != ''
              AND (
                SELECT u.node_id FROM users u WHERE u.server_url = mention_notifications.author_server AND u.node_id IS NOT NULL
              ) IS NOT NULL
        """)
        con.commit()

"""contacc registry — global username → {server_url, client_url} directory.

DNS-like: entries carry a TTL; clients cache locally and re-query on expiry.
All writes are authenticated with the node's Ed25519 private key via a
signed canonical message that includes a timestamp to prevent replays.

Signature message format:
  "contacc:{action}:{username}:{server_url}:{client_url}:{timestamp}"
  where action is "register" or "update"
"""
import base64
import re
import sqlite3
import sys
import time
from pathlib import Path

import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DEFAULT_TTL = 14400   # 4 hours
MAX_TTL = 86400       # 24 hours
MIN_TTL = 300         # 5 minutes
TIMESTAMP_TOLERANCE = 300  # ±5 min replay window

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')


def _verify_sig(public_key_b64: str, message: str, signature_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), message.encode())
        return True
    except Exception:
        return False


def _check_timestamp(ts: int) -> None:
    if abs(time.time() - ts) > TIMESTAMP_TOLERANCE:
        raise HTTPException(status_code=400, detail="Timestamp out of range — check clock skew")


def _clamp_ttl(ttl: int) -> int:
    return max(MIN_TTL, min(MAX_TTL, ttl))


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS handles (
            username      TEXT PRIMARY KEY,
            server_url    TEXT NOT NULL,
            client_url    TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            ttl           INTEGER NOT NULL DEFAULT 14400,
            registered_at REAL NOT NULL,
            updated_at    REAL NOT NULL
        )
    """)
    con.commit()

    app = FastAPI(title="contacc registry")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/lookup/{username}")
    def lookup(username: str):
        row = con.execute(
            "SELECT server_url, client_url, public_key, ttl, updated_at "
            "FROM handles WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Username not found")
        server_url, client_url, public_key, ttl, updated_at = row
        return {
            "username": username,
            "server_url": server_url,
            "client_url": client_url,
            "public_key": public_key,
            "ttl": ttl,
            "updated_at": updated_at,
        }

    class RegisterBody(BaseModel):
        server_url: str
        client_url: str
        public_key: str
        ttl: int = DEFAULT_TTL
        timestamp: int
        signature: str

    @app.post("/register/{username}", status_code=201)
    def register(username: str, body: RegisterBody):
        if not USERNAME_RE.match(username):
            raise HTTPException(status_code=400,
                                detail="Username must be 1–32 chars: letters, digits, _ or -")
        _check_timestamp(body.timestamp)
        ttl = _clamp_ttl(body.ttl)
        msg = f"contacc:register:{username}:{body.server_url}:{body.client_url}:{body.timestamp}"
        if not _verify_sig(body.public_key, msg, body.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        if con.execute("SELECT 1 FROM handles WHERE username = ?", (username,)).fetchone():
            raise HTTPException(status_code=409, detail="Username already registered")
        now = time.time()
        con.execute(
            "INSERT INTO handles "
            "(username, server_url, client_url, public_key, ttl, registered_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, body.server_url, body.client_url, body.public_key, ttl, now, now),
        )
        con.commit()
        return {"username": username, "ttl": ttl}

    class UpdateBody(BaseModel):
        server_url: str
        client_url: str
        ttl: int = DEFAULT_TTL
        timestamp: int
        signature: str

    @app.put("/update/{username}")
    def update(username: str, body: UpdateBody):
        _check_timestamp(body.timestamp)
        row = con.execute(
            "SELECT public_key FROM handles WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Username not found")
        ttl = _clamp_ttl(body.ttl)
        msg = f"contacc:update:{username}:{body.server_url}:{body.client_url}:{body.timestamp}"
        if not _verify_sig(row[0], msg, body.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        con.execute(
            "UPDATE handles SET server_url=?, client_url=?, ttl=?, updated_at=? WHERE username=?",
            (body.server_url, body.client_url, ttl, time.time(), username),
        )
        con.commit()
        return {"username": username, "ttl": ttl}

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run the contacc registry")
    parser.add_argument("db", help="Path to registry SQLite database")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9532)
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    app = create_app(args.db)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

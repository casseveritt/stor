"""contacc registry — global username → {server_url, client_url} directory.

DNS-like: entries carry a TTL; clients cache locally and re-query on expiry.
All writes are authenticated with the node's Ed25519 private key via a
signed canonical message that includes a timestamp to prevent replays.

Signature message format:
  "contacc:{action}:{username}:{server_url}:{client_url}:{timestamp}"
  where action is "register" or "update"

This service also acts as a shared identity proxy: nodes that don't have
their own Google OAuth credentials can delegate authentication here.
"""
import base64
import os
import re
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

DEFAULT_TTL = 14400   # 4 hours
MAX_TTL = 86400       # 24 hours
MIN_TTL = 300         # 5 minutes
TIMESTAMP_TOLERANCE = 300  # ±5 min replay window

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]{1,32}$')

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


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
    con.execute("""
        CREATE TABLE IF NOT EXISTS proxy_states (
            state      TEXT PRIMARY KEY,
            return_to  TEXT NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS proxy_tokens (
            token        TEXT PRIMARY KEY,
            identity     TEXT NOT NULL,
            display_name TEXT,
            created_at   REAL NOT NULL
        )
    """)
    con.commit()

    # Identity proxy config — read from environment at startup.
    proxy_client_id = os.environ.get("CONTACC_GOOGLE_CLIENT_ID")
    proxy_client_secret = os.environ.get("CONTACC_GOOGLE_CLIENT_SECRET")
    registry_public_url = os.environ.get("CONTACC_REGISTRY_URL", "").rstrip("/")
    proxy_enabled = bool(proxy_client_id and proxy_client_secret and registry_public_url)

    app = FastAPI(title="contacc registry")

    @app.get("/health")
    def health():
        return {"status": "ok", "proxy": proxy_enabled}

    # ── handle directory ──────────────────────────────────────────────────────

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

    # ── identity proxy ────────────────────────────────────────────────────────

    def _proxy_callback_uri() -> str:
        return registry_public_url + "/auth/callback"

    def _cleanup_proxy_tables(now: float) -> None:
        con.execute("DELETE FROM proxy_states WHERE created_at < ?", (now - 600,))
        con.execute("DELETE FROM proxy_tokens WHERE created_at < ?", (now - 300,))
        con.commit()

    @app.get("/auth/start")
    def proxy_auth_start(return_to: str):
        if not proxy_enabled:
            raise HTTPException(status_code=503, detail="Identity proxy not configured")
        now = time.time()
        _cleanup_proxy_tables(now)
        state = secrets.token_urlsafe(24)
        con.execute("INSERT INTO proxy_states VALUES (?, ?, ?)", (state, return_to, now))
        con.commit()
        params = urlencode({
            "client_id": proxy_client_id,
            "redirect_uri": _proxy_callback_uri(),
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        })
        return RedirectResponse(f"{GOOGLE_AUTH_URL}?{params}", status_code=302)

    @app.get("/auth/callback")
    def proxy_auth_callback(code: str, state: str):
        if not proxy_enabled:
            raise HTTPException(status_code=503, detail="Identity proxy not configured")
        row = con.execute(
            "SELECT return_to, created_at FROM proxy_states WHERE state = ?", (state,)
        ).fetchone()
        if not row or time.time() - row[1] > 600:
            con.execute("DELETE FROM proxy_states WHERE state = ?", (state,))
            con.commit()
            raise HTTPException(status_code=400, detail="Invalid or expired state")
        return_to = row[0]
        con.execute("DELETE FROM proxy_states WHERE state = ?", (state,))

        token_resp = httpx.post(GOOGLE_TOKEN_URL, data={
            "code": code,
            "redirect_uri": _proxy_callback_uri(),
            "client_id": proxy_client_id,
            "client_secret": proxy_client_secret,
            "grant_type": "authorization_code",
        })
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        user_resp = httpx.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_resp.raise_for_status()
        claims = user_resp.json()

        email = claims.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="No email in Google response")
        identity = f"google:{email}"
        display_name = claims.get("name") or email

        token = secrets.token_urlsafe(32)
        now = time.time()
        _cleanup_proxy_tables(now)
        con.execute(
            "INSERT INTO proxy_tokens VALUES (?, ?, ?, ?)",
            (token, identity, display_name, now),
        )
        con.commit()

        sep = "&" if "?" in return_to else "?"
        return RedirectResponse(f"{return_to}{sep}proxy_token={token}", status_code=302)

    @app.get("/auth/verify")
    def proxy_auth_verify(token: str):
        row = con.execute(
            "SELECT identity, display_name, created_at FROM proxy_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        con.execute("DELETE FROM proxy_tokens WHERE token = ?", (token,))
        con.commit()
        if not row or time.time() - row[2] > 300:
            raise HTTPException(status_code=404, detail="Token not found or expired")
        return {"identity": row[0], "display_name": row[1]}

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

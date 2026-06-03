"""contacc registry — global username → server_url directory.

DNS-like: entries carry a TTL; clients cache locally and re-query on expiry.
All writes are authenticated with the node's Ed25519 private key via a
signed canonical message that includes a timestamp to prevent replays.

Signature message format:
  "contacc:{action}:{username}:{server_url}:{timestamp}"
  where action is "register" or "update"

This service also acts as a shared identity proxy: nodes that don't have
their own Google OAuth credentials can delegate authentication here.
"""
import base64
import json
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
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

DEFAULT_TTL = 14400   # 4 hours
MAX_TTL = 86400       # 24 hours
MIN_TTL = 300         # 5 minutes
TIMESTAMP_TOLERANCE = 300  # ±5 min replay window

USERNAME_RE = re.compile(r'^[a-z_][a-z0-9_]{0,31}$')

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


def _verify_delegation_cert(cert: dict, node_pub_b64: str) -> bool:
    """Verify a delegation cert: signature valid, unexpired, authorises node_pub_b64."""
    try:
        if cert.get("node_public_key") != node_pub_b64:
            return False
        if cert.get("expires_at", 0) < time.time_ns():
            return False
        id_pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(cert["identity_public_key"] + "=="))
        canonical = (f"contacc:delegate:{cert['user_id']}:"
                     f"{cert['node_public_key']}:{cert['expires_at']}")
        id_pub.verify(base64.b64decode(cert["signature"] + "=="), canonical.encode())
        return True
    except Exception:
        return False


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS handles (
            username      TEXT PRIMARY KEY,
            server_url    TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            ttl           INTEGER NOT NULL DEFAULT 14400,
            registered_at INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL,
            display_name  TEXT,
            web_url       TEXT
        )
    """)
    # Migrate: drop client_url (was NOT NULL, recreate table to remove it)
    try:
        con.execute(
            "INSERT INTO handles (username, server_url, public_key, ttl, registered_at, updated_at)"
            " VALUES ('__migration_probe__', '', '', 0, 0, 0)"
        )
        con.execute("DELETE FROM handles WHERE username = '__migration_probe__'")
        con.commit()
    except Exception:
        con.execute("ALTER TABLE handles RENAME TO _handles_v1")
        con.execute("""
            CREATE TABLE handles (
                username      TEXT PRIMARY KEY,
                server_url    TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                ttl           INTEGER NOT NULL DEFAULT 14400,
                registered_at INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL,
                display_name  TEXT,
                web_url       TEXT
            )
        """)
        con.execute("""
            INSERT INTO handles
              (username, server_url, public_key, ttl, registered_at, updated_at, display_name)
            SELECT username, server_url, public_key, ttl, registered_at, updated_at, display_name
            FROM _handles_v1
        """)
        con.execute("DROP TABLE _handles_v1")
        con.commit()
    # Add web_url column if missing (upgrade from earlier schema)
    try:
        con.execute("SELECT web_url FROM handles LIMIT 1")
    except Exception:
        con.execute("ALTER TABLE handles ADD COLUMN web_url TEXT")
        con.commit()
    # Add identity/user_id columns if missing
    for col in ["user_id TEXT", "identity_public_key TEXT", "delegation_sig TEXT", "encrypted_identity_key TEXT"]:
        try:
            con.execute(f"ALTER TABLE handles ADD COLUMN {col}")
            con.commit()
        except Exception:
            pass
    try:
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS handles_user_id ON handles (user_id) WHERE user_id IS NOT NULL")
        con.commit()
    except Exception:
        pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS proxy_states (
            state      TEXT PRIMARY KEY,
            return_to  TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS proxy_tokens (
            token        TEXT PRIMARY KEY,
            identity     TEXT NOT NULL,
            display_name TEXT,
            created_at   INTEGER NOT NULL
        )
    """)
    # Migrate: convert timestamps from float seconds to integer nanoseconds
    for _tbl, _col in [("handles", "registered_at"), ("handles", "updated_at"),
                       ("proxy_states", "created_at"), ("proxy_tokens", "created_at")]:
        try:
            con.execute(
                f"UPDATE {_tbl} SET {_col} = CAST({_col} * 1000000000 AS INTEGER)"
                f" WHERE {_col} < 1000000000000"
            )
        except Exception:
            pass
    con.commit()

    # Identity proxy config — read from environment at startup.
    proxy_client_id = os.environ.get("CONTACC_GOOGLE_CLIENT_ID")
    proxy_client_secret = os.environ.get("CONTACC_GOOGLE_CLIENT_SECRET")
    registry_public_url = os.environ.get("CONTACC_REGISTRY_URL", "").rstrip("/")
    proxy_enabled = bool(proxy_client_id and proxy_client_secret and registry_public_url)

    app = FastAPI(title="contacc registry")

    _INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>contacc</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='114.1085 98.626948 11.98291 9.7358322'%3E%3Cpath style='fill:%234285f4;stroke-width:0.199817' d='m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z'/%3E%3Cpath style='fill:%234285f4;stroke-width:0.199817' d='m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z'/%3E%3C/svg%3E">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #111; color: #e0e0e0;
           display: flex; flex-direction: column; align-items: center; justify-content: center;
           min-height: 100vh; gap: 1.5rem; padding: 2rem; }
    .logo { display: flex; align-items: center; gap: 0.6rem; }
    .logo svg { height: 48px; width: auto; }
    .logo span { font-size: 2rem; font-weight: 300; letter-spacing: 0.1em; color: #fff; }
    .row { display: flex; gap: 0.5rem; }
    input { padding: 0.5rem 0.8rem; border-radius: 4px; border: 1px solid #333;
            background: #222; color: #e0e0e0; font-size: 1rem; outline: none; width: 220px; }
    input:focus { border-color: #4285f4; }
    button { padding: 0.5rem 1.2rem; border-radius: 4px; border: none; background: #4285f4;
             color: #fff; font-size: 1rem; cursor: pointer; }
    button:hover { background: #3a78e0; }
    #err { color: #e06c6c; font-size: 0.85rem; min-height: 1.2em; }
    #profile-card { display: none; flex-direction: column; align-items: center; gap: 0.75rem;
                    background: #1e1e1e; border-radius: 10px; padding: 1.5rem 2rem; min-width: 240px; }
    #profile-photo { width: 80px; height: 80px; border-radius: 50%; object-fit: cover;
                     background: #333; border: 2px solid #333; }
    #profile-photo.hidden { display: none; }
    #profile-initials { width: 80px; height: 80px; border-radius: 50%; background: #2a4a7a;
                        display: flex; align-items: center; justify-content: center;
                        font-size: 2rem; color: #aac8ff; font-weight: 300; }
    #profile-initials.hidden { display: none; }
    #profile-name { font-size: 1.1rem; color: #fff; font-weight: 400; }
    #profile-handle { font-size: 0.85rem; color: #666; }
    #go-btn { margin-top: 0.25rem; padding: 0.5rem 1.5rem; border-radius: 4px; border: none;
              background: #4285f4; color: #fff; font-size: 1rem; cursor: pointer; }
    #go-btn:hover { background: #3a78e0; }
  </style>
</head>
<body>
  <div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="114.1085 98.626948 11.98291 9.7358322"><path style="fill:#4285f4;stroke-width:0.199817" d="m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z"/><path style="fill:#4285f4;stroke-width:0.199817" d="m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z"/></svg><span>contacc</span></div>
  <div class="row">
    <input id="handle" type="text" placeholder="your handle" autocomplete="off"
           autocapitalize="none" onkeydown="if(event.key==='Enter')lookup()">
    <button onclick="lookup()">Look up</button>
  </div>
  <div id="err"></div>
  <div id="profile-card">
    <img id="profile-photo" alt="">
    <div id="profile-initials"></div>
    <div id="profile-name"></div>
    <div id="profile-handle"></div>
    <button id="go-btn" onclick="gotoProfile()">Go to profile</button>
  </div>
  <script>
    let _profileUrl = null;

    async function lookup() {
      const handle = document.getElementById("handle").value.trim().toLowerCase();
      const err = document.getElementById("err");
      const card = document.getElementById("profile-card");
      err.textContent = "";
      card.style.display = "none";
      _profileUrl = null;
      if (!handle) return;
      const r = await fetch("/lookup/" + encodeURIComponent(handle));
      if (r.status === 404) { err.textContent = "Handle not found."; return; }
      if (!r.ok) { err.textContent = "Registry error."; return; }
      const d = await r.json();
      _profileUrl = d.server_url || null;
      const name = d.display_name || ("@" + handle);
      document.getElementById("profile-name").textContent = name;
      document.getElementById("profile-handle").textContent = "@" + handle;
      const photo = document.getElementById("profile-photo");
      const initials = document.getElementById("profile-initials");
      if (d.photo_url) {
        photo.src = d.photo_url;
        photo.classList.remove("hidden");
        initials.classList.add("hidden");
      } else {
        photo.classList.add("hidden");
        initials.classList.remove("hidden");
        initials.textContent = name.trim()[0].toUpperCase();
      }
      card.style.display = "flex";
    }

    function gotoProfile() {
      if (_profileUrl) window.location.href = _profileUrl;
    }

    const h = new URLSearchParams(location.search).get("handle");
    if (h) { document.getElementById("handle").value = h; lookup(); }
  </script>
</body>
</html>"""

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _INDEX_HTML

    @app.get("/go/{username}")
    def go(username: str):
        username = username.lower()
        row = con.execute(
            "SELECT server_url, web_url FROM handles WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            return RedirectResponse(f"/?handle={username}", status_code=302)
        return RedirectResponse(row[1] or row[0], status_code=302)

    @app.get("/health")
    def health():
        return {"status": "ok", "proxy": proxy_enabled}

    # ── handle directory ──────────────────────────────────────────────────────

    @app.get("/search")
    def search(q: str, limit: int = 20):
        q = q.strip()
        if not q:
            return {"results": []}
        pattern = "%" + q.lower() + "%"
        rows = con.execute(
            """SELECT username, server_url, display_name, public_key, user_id, identity_public_key
               FROM handles
               WHERE LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?
               ORDER BY username LIMIT ?""",
            (pattern, pattern, limit),
        ).fetchall()
        results = []
        for r in rows:
            entry = {
                "username": r[0], "server_url": r[1], "display_name": r[2],
                "photo_url": r[1].rstrip("/") + "/profile/photo", "public_key": r[3],
            }
            if r[4]:
                entry["user_id"] = r[4]
            if r[5]:
                entry["identity_public_key"] = r[5]
            results.append(entry)
        return {"results": results}

    @app.get("/lookup-by-key")
    def lookup_by_key(public_key: str):
        row = con.execute(
            "SELECT username, server_url, display_name "
            "FROM handles WHERE public_key = ?", (public_key,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found")
        username, server_url, display_name = row
        return {"username": username, "server_url": server_url,
                "display_name": display_name,
                "photo_url": server_url.rstrip("/") + "/profile/photo"}

    @app.get("/lookup/{username}")
    def lookup(username: str):
        username = username.lower()
        row = con.execute(
            "SELECT server_url, public_key, ttl, updated_at, display_name, user_id, identity_public_key "
            "FROM handles WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Username not found")
        server_url, public_key, ttl, updated_at, display_name, user_id, identity_public_key = row
        result = {
            "username": username,
            "server_url": server_url,
            "public_key": public_key,
            "ttl": ttl,
            "updated_at": updated_at,
            "display_name": display_name,
            "photo_url": server_url.rstrip("/") + "/profile/photo",
        }
        if user_id:
            result["user_id"] = user_id
        if identity_public_key:
            result["identity_public_key"] = identity_public_key
        return result

    @app.get("/id/{user_id}")
    def go_by_id(user_id: str):
        row = con.execute(
            "SELECT server_url, web_url FROM handles WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "User ID not found")
        return RedirectResponse(row[1] or row[0], status_code=302)

    class RegisterBody(BaseModel):
        server_url: str
        public_key: str
        ttl: int = DEFAULT_TTL
        timestamp: int
        signature: str
        display_name: str | None = None
        web_url: str | None = None
        delegation_cert: dict | None = None  # replaces user_id/identity_public_key/delegation_sig

    @app.post("/register/{username}", status_code=201)
    def register(username: str, body: RegisterBody):
        username = username.lower()
        if not USERNAME_RE.match(username):
            raise HTTPException(status_code=400,
                                detail="Handle must start with a letter or _, followed by letters, digits, or _ (max 32 chars)")
        _check_timestamp(body.timestamp)
        ttl = _clamp_ttl(body.ttl)
        msg = f"contacc:register:{username}:{body.server_url}:{body.timestamp}"
        if not _verify_sig(body.public_key, msg, body.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        if con.execute("SELECT 1 FROM handles WHERE username = ?", (username,)).fetchone():
            raise HTTPException(status_code=409, detail="Username already registered")
        reg_user_id = reg_identity_public_key = reg_delegation_json = None
        if body.delegation_cert:
            cert = body.delegation_cert
            if not _verify_delegation_cert(cert, body.public_key):
                raise HTTPException(400, "Invalid or expired delegation cert")
            existing = con.execute("SELECT username FROM handles WHERE user_id = ?", (cert.get("user_id"),)).fetchone()
            if existing and existing[0] != username:
                raise HTTPException(409, f"user_id already registered to {existing[0]}")
            reg_user_id = cert.get("user_id")
            reg_identity_public_key = cert.get("identity_public_key")
            reg_delegation_json = json.dumps(cert)
        now = time.time_ns()
        con.execute(
            "INSERT INTO handles "
            "(username, server_url, public_key, ttl, registered_at, updated_at, display_name, web_url, user_id, identity_public_key, delegation_sig) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, body.server_url, body.public_key, ttl, now, now, body.display_name, body.web_url,
             reg_user_id, reg_identity_public_key, reg_delegation_json),
        )
        con.commit()
        return {"username": username, "ttl": ttl}

    class UpdateBody(BaseModel):
        server_url: str
        ttl: int = DEFAULT_TTL
        timestamp: int
        signature: str
        display_name: str | None = None
        web_url: str | None = None
        delegation_cert: dict | None = None  # replaces user_id/identity_public_key/delegation_sig

    @app.put("/update/{username}")
    def update(username: str, body: UpdateBody):
        username = username.lower()
        _check_timestamp(body.timestamp)
        row = con.execute(
            "SELECT public_key FROM handles WHERE username = ?", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Username not found")
        ttl = _clamp_ttl(body.ttl)
        msg = f"contacc:update:{username}:{body.server_url}:{body.timestamp}"
        if not _verify_sig(row[0], msg, body.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        upd_user_id = upd_identity_public_key = upd_delegation_json = None
        if body.delegation_cert:
            cert = body.delegation_cert
            if not _verify_delegation_cert(cert, body.server_url and row[0]):
                raise HTTPException(400, "Invalid or expired delegation cert")
            existing = con.execute("SELECT username FROM handles WHERE user_id = ?", (cert.get("user_id"),)).fetchone()
            if existing and existing[0] != username:
                raise HTTPException(409, f"user_id already registered to {existing[0]}")
            upd_user_id = cert.get("user_id")
            upd_identity_public_key = cert.get("identity_public_key")
            upd_delegation_sig = body.delegation_sig
        if upd_user_id:
            con.execute(
                "UPDATE handles SET server_url=?, ttl=?, updated_at=?, display_name=?, web_url=?, "
                "user_id=?, identity_public_key=?, delegation_sig=? WHERE username=?",
                (body.server_url, ttl, time.time_ns(), body.display_name, body.web_url,
                 upd_user_id, upd_identity_public_key, upd_delegation_json, username),
            )
        else:
            con.execute(
                "UPDATE handles SET server_url=?, ttl=?, updated_at=?, display_name=?, web_url=? "
                "WHERE username=?",
                (body.server_url, ttl, time.time_ns(), body.display_name, body.web_url, username),
            )
        con.commit()
        return {"username": username, "ttl": ttl}

    # ── identity escrow ───────────────────────────────────────────────────────

    class EscrowBody(BaseModel):
        encrypted_identity_key: str  # base64: AES-GCM ciphertext
        argon2_salt: str             # hex, used with recovery passphrase
        argon2_time_cost: int = 3
        argon2_memory_cost: int = 65536
        argon2_parallelism: int = 4
        signature: str               # identity_key signs f"contacc:escrow:{user_id}:{timestamp}"
        timestamp: int

    @app.put("/identity-key/{user_id}", status_code=204)
    def store_escrow(user_id: str, body: EscrowBody):
        row = con.execute(
            "SELECT identity_public_key FROM handles WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "User ID not registered or has no identity key")
        if abs(time.time() - body.timestamp) > TIMESTAMP_TOLERANCE:
            raise HTTPException(401, "Timestamp too skewed")
        try:
            id_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(row[0] + "=="))
            msg = f"contacc:escrow:{user_id}:{body.timestamp}"
            id_pub.verify(base64.b64decode(body.signature + "=="), msg.encode())
        except Exception:
            raise HTTPException(401, "Invalid signature")
        escrow_data = json.dumps({
            "encrypted_identity_key": body.encrypted_identity_key,
            "argon2_salt": body.argon2_salt,
            "argon2_time_cost": body.argon2_time_cost,
            "argon2_memory_cost": body.argon2_memory_cost,
            "argon2_parallelism": body.argon2_parallelism,
        })
        con.execute(
            "UPDATE handles SET encrypted_identity_key = ? WHERE user_id = ?",
            (escrow_data, user_id),
        )
        con.commit()

    @app.post("/identity-key/{user_id}/recover")
    def recover_escrow(user_id: str):
        row = con.execute(
            "SELECT encrypted_identity_key FROM handles WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "No escrow stored for this user ID")
        return json.loads(row[0])

    # ── identity proxy ────────────────────────────────────────────────────────

    def _proxy_callback_uri() -> str:
        return registry_public_url + "/auth/callback"

    def _cleanup_proxy_tables(now: float) -> None:
        con.execute("DELETE FROM proxy_states WHERE created_at < ?", (now - 600 * NS,))
        con.execute("DELETE FROM proxy_tokens WHERE created_at < ?", (now - 300 * NS,))
        con.commit()

    @app.get("/auth/start")
    def proxy_auth_start(return_to: str):
        if not proxy_enabled:
            raise HTTPException(status_code=503, detail="Identity proxy not configured")
        now = time.time_ns()
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
        if not row or time.time_ns() - row[1] > 600 * NS:
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
        now = time.time_ns()
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
        if not row or time.time_ns() - row[2] > 300 * NS:
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

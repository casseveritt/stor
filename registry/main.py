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
NS = 1_000_000_000
from pathlib import Path
from urllib.parse import urlencode

import httpx
import uvicorn
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
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

    # ── registry sessions ─────────────────────────────────────────────────────
    _reg_sessions: dict[str, tuple[str, float]] = {}  # token → (identity, expires_at)
    REG_SESSION_TTL = 3600 * 8  # 8 hours

    def _get_session(request) -> str | None:
        token = request.cookies.get("reg_session")
        if not token:
            return None
        entry = _reg_sessions.get(token)
        if not entry or time.time() > entry[1]:
            _reg_sessions.pop(token, None)
            return None
        return entry[0]

    from fastapi import Cookie
    from fastapi.responses import JSONResponse as _JR

    @app.get("/auth/me")
    def auth_me(request: Request):
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Not authenticated")
        return {"identity": identity}

    @app.post("/auth/session")
    def auth_session(body: dict, request: Request):
        """Exchange a proxy_token for a registry session cookie."""
        proxy_token = body.get("proxy_token", "")
        if not proxy_token:
            raise HTTPException(400, "proxy_token required")
        # Verify via the proxy's own verify endpoint
        r = __import__("httpx").get(
            f"{registry_public_url}/auth/verify",
            params={"token": proxy_token}, timeout=5
        )
        if not r.is_success:
            raise HTTPException(403, "Invalid or expired token")
        data = r.json()
        identity = data.get("identity", "")
        if not identity:
            raise HTTPException(403, "No identity in token")
        session_token = secrets.token_urlsafe(32)
        _reg_sessions[session_token] = (identity, time.time() + REG_SESSION_TTL)
        resp = _JR({"identity": identity})
        resp.set_cookie("reg_session", session_token, httponly=True,
                        samesite="lax", max_age=REG_SESSION_TTL)
        return resp

    @app.post("/auth/logout", status_code=204)
    def auth_logout(request: Request):
        token = request.cookies.get("reg_session")
        if token:
            _reg_sessions.pop(token, None)
        resp = _JR(None, status_code=204)
        resp.delete_cookie("reg_session")
        return resp

    _INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>contacc registry</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #111; color: #e0e0e0;
           min-height: 100vh; padding: 2rem 1rem; }
    .page { max-width: 540px; margin: 0 auto; display: flex; flex-direction: column; gap: 2rem; }
    .logo { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; }
    .logo span { font-size: 1.8rem; font-weight: 300; letter-spacing: 0.1em; color: #fff; }
    .logo small { font-size: 0.8rem; color: #555; margin-left: 0.25rem; align-self: flex-end; margin-bottom: 0.2rem; }
    .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.25rem; }
    .card h2 { font-size: 0.95rem; font-weight: 500; color: #aaa; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.06em; }
    .field { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 0.75rem; }
    input[type=text], input[type=password] {
      padding: 0.45rem 0.7rem; border-radius: 4px; border: 1px solid #333;
      background: #222; color: #e0e0e0; font-size: 0.9rem; outline: none; width: 100%; }
    input:focus { border-color: #4285f4; }
    .btn { padding: 0.45rem 1rem; border-radius: 4px; border: none; cursor: pointer; font-size: 0.88rem; }
    .btn-primary { background: #4285f4; color: #fff; }
    .btn-primary:hover { background: #3a78e0; }
    .btn-muted { background: #2a2a2a; color: #ccc; }
    .btn-muted:hover { background: #333; }
    .msg { font-size: 0.82rem; min-height: 1.1em; margin-top: 0.4rem; }
    .err { color: #e06c6c; }
    .ok  { color: #6cbe6c; }
    .profile-card { display: none; align-items: center; gap: 0.75rem; margin-top: 0.75rem;
                    background: #222; border-radius: 6px; padding: 0.75rem; }
    .avatar { width: 48px; height: 48px; border-radius: 50%; object-fit: cover; background: #333; flex-shrink: 0; }
    .avatar-init { width: 48px; height: 48px; border-radius: 50%; background: #2a4a7a;
                   display: flex; align-items: center; justify-content: center;
                   font-size: 1.2rem; color: #aac8ff; flex-shrink: 0; }
    .profile-info { flex: 1; }
    .profile-name { font-size: 0.95rem; color: #fff; }
    .profile-handle { font-size: 0.78rem; color: #666; }
    .profile-uuid { font-size: 0.7rem; color: #444; margin-top: 0.2rem; font-family: monospace; }
    .key-box { background: #111; border: 1px solid #333; border-radius: 4px; padding: 0.6rem;
               font-family: monospace; font-size: 0.72rem; color: #60a5fa;
               word-break: break-all; margin-top: 0.5rem; display: none; }
    .warn { color: #e06c6c; font-size: 0.8rem; margin-top: 0.4rem; }
  </style>
</head>
<body>
<div class="page">
  <div class="logo">
    <span>contacc</span><small>registry</small>
  </div>

  <!-- Find a person -->
  <div id="lookup-card" class="card" style="display:none">
    <h2>Find a person</h2>
    <div class="field">
      <input id="lookup-handle" type="text" placeholder="handle" autocomplete="off"
             autocapitalize="none" onkeydown="if(event.key==='Enter')doLookup()">
    </div>
    <button class="btn btn-primary" onclick="doLookup()">Look up</button>
    <div id="lookup-msg" class="msg err"></div>
    <div id="profile-card" class="profile-card">
      <img id="profile-photo" class="avatar" alt="" style="display:none">
      <div id="profile-init" class="avatar-init" style="display:none"></div>
      <div class="profile-info">
        <div id="profile-name" class="profile-name"></div>
        <div id="profile-handle" class="profile-handle"></div>
        <div id="profile-uuid" class="profile-uuid"></div>
      </div>
      <button class="btn btn-muted" onclick="gotoProfile()">Open ↗</button>
    </div>
  </div>

  <!-- Auth gate — shown when not signed in -->
  <div id="auth-gate" style="display:none;text-align:center;padding:3rem 1rem;display:flex;flex-direction:column;align-items:center;gap:1.25rem">
    <p style="color:#888;font-size:1rem">Please sign in to continue.</p>
    <button class="btn btn-primary" onclick="signIn()">Sign in with Google</button>
  </div>

  <!-- Recover identity key — shown when signed in -->
  <div id="recover-card" class="card" style="display:none">
    <h2>Recover identity key</h2>
    <p style="font-size:0.82rem;color:#666;margin-bottom:0.75rem">
      If you've lost access to your node, enter your handle and recovery passphrase
      to retrieve your identity private key.
    </p>
    <div class="field">
      <input id="rec-handle" type="text" placeholder="handle" autocomplete="off" autocapitalize="none">
    </div>
    <div class="field">
      <input id="rec-pass" type="password" placeholder="Recovery passphrase">
    </div>
    <button class="btn btn-primary" onclick="doRecover()">Retrieve key</button>
    <div id="rec-msg" class="msg"></div>
    <div id="rec-key" class="key-box"></div>
    <div id="rec-warn" class="warn" style="display:none">
      ⚠ Save this key immediately. Close this page when done.
    </div>
  </div>

  <!-- Change recovery passphrase — shown when signed in -->
  <div id="chgpass-card" class="card" style="display:none">
    <h2>Change recovery passphrase</h2>
    <div class="field">
      <input id="chg-handle" type="text" placeholder="handle" autocomplete="off" autocapitalize="none">
    </div>
    <div class="field">
      <input id="chg-old" type="password" placeholder="Current recovery passphrase">
    </div>
    <div class="field">
      <input id="chg-new" type="password" placeholder="New recovery passphrase">
    </div>
    <button class="btn btn-primary" onclick="doChangePass()">Update</button>
    <div id="chg-msg" class="msg"></div>
  </div>

  <!-- Signed-in footer -->
  <div id="auth-footer" style="display:none;font-size:0.8rem;color:#555;text-align:center">
    Signed in as <span id="auth-identity" style="color:#888"></span>
    &nbsp;·&nbsp;
    <a href="#" onclick="signOut();return false" style="color:#555">Sign out</a>
  </div>
</div>
<script>
  let _webUrl = null;
  let _authed = false;

  async function checkAuth() {
    // Exchange proxy_token from query param if present (registry proxy pattern)
    const params = new URLSearchParams(location.search);
    const token = params.get("proxy_token");
    if (token) {
      history.replaceState(null, "", location.pathname);
      const r = await fetch("/auth/session", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({proxy_token: token}),
      });
      if (!r.ok) { showAuth(false); return; }
      const d = await r.json();
      showAuth(true, d.identity);
      return;
    }
    // Check existing session
    const r = await fetch("/auth/me");
    if (r.ok) { const d = await r.json(); showAuth(true, d.identity); }
    else showAuth(false);
  }

  function showAuth(authed, identity) {
    _authed = authed;
    document.getElementById("auth-gate").style.display = authed ? "none" : "";
    document.getElementById("lookup-card").style.display = authed ? "" : "none";
    document.getElementById("recover-card").style.display = authed ? "" : "none";
    document.getElementById("chgpass-card").style.display = authed ? "" : "none";
    document.getElementById("auth-footer").style.display = authed ? "" : "none";
    if (authed && identity) document.getElementById("auth-identity").textContent = identity;
  }

  function signIn() {
    window.location.href = "/auth/start?return_to=" + encodeURIComponent(location.origin + "/");
  }

  async function signOut() {
    await fetch("/auth/logout", {method: "POST"});
    showAuth(false);
  }

  async function doLookup() {
    if (!_authed) { document.getElementById("lookup-msg").textContent = "Sign in first."; document.getElementById("lookup-msg").className = "msg err"; return; }
    const handle = document.getElementById("lookup-handle").value.trim().toLowerCase();
    const msg = document.getElementById("lookup-msg");
    const card = document.getElementById("profile-card");
    msg.textContent = ""; card.style.display = "none"; _webUrl = null;
    if (!handle) return;
    const r = await fetch("/lookup/" + encodeURIComponent(handle));
    if (r.status === 404) { msg.textContent = "Handle not found."; return; }
    if (!r.ok) { msg.textContent = "Registry error."; return; }
    const d = await r.json();
    _webUrl = d.web_url || d.server_url || null;
    const name = d.display_name || ("@" + handle);
    document.getElementById("profile-name").textContent = name;
    document.getElementById("profile-handle").textContent = "@" + handle;
    document.getElementById("profile-uuid").textContent = d.user_id ? "id: " + d.user_id : "";
    const photo = document.getElementById("profile-photo");
    const init = document.getElementById("profile-init");
    if (d.photo_url) {
      photo.src = d.photo_url; photo.style.display = ""; init.style.display = "none";
    } else {
      init.textContent = name.trim()[0].toUpperCase();
      init.style.display = ""; photo.style.display = "none";
    }
    card.style.display = "flex";
  }

  function gotoProfile() { if (_webUrl) window.open(_webUrl, "_blank"); }

  async function doRecover() {
    const handle = document.getElementById("rec-handle").value.trim().toLowerCase();
    const pass = document.getElementById("rec-pass").value;
    const msg = document.getElementById("rec-msg");
    const keyBox = document.getElementById("rec-key");
    const warn = document.getElementById("rec-warn");
    msg.textContent = ""; keyBox.style.display = "none"; warn.style.display = "none";
    if (!handle || !pass) { msg.className = "msg err"; msg.textContent = "Handle and passphrase required."; return; }
    msg.className = "msg"; msg.textContent = "Decrypting…";
    const r = await fetch("/identity/recover", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({handle, recovery_passphrase: pass}),
    });
    const d = await r.json();
    if (!r.ok) { msg.className = "msg err"; msg.textContent = d.detail || "Failed."; return; }
    msg.textContent = "";
    keyBox.textContent = d.identity_private_key;
    keyBox.style.display = "block";
    warn.style.display = "block";
  }

  async function doChangePass() {
    const handle = document.getElementById("chg-handle").value.trim().toLowerCase();
    const oldPass = document.getElementById("chg-old").value;
    const newPass = document.getElementById("chg-new").value;
    const msg = document.getElementById("chg-msg");
    msg.textContent = "";
    if (!handle || !oldPass || !newPass) { msg.className = "msg err"; msg.textContent = "All fields required."; return; }
    msg.className = "msg"; msg.textContent = "Updating…";
    const r = await fetch("/identity/change-passphrase", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({handle, old_recovery_passphrase: oldPass, new_recovery_passphrase: newPass}),
    });
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ Passphrase updated."; }
    else { const d = await r.json(); msg.className = "msg err"; msg.textContent = d.detail || "Failed."; }
  }

  checkAuth();
  const h = new URLSearchParams(location.search).get("handle");
  if (h) { document.getElementById("lookup-handle").value = h; doLookup(); }
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

    def _escrow_for_handle(handle: str):
        """Return (user_id, escrow_dict) or raise HTTPException."""
        handle = handle.lower()
        row = con.execute(
            "SELECT user_id, encrypted_identity_key FROM handles WHERE username = ?", (handle,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Handle not found")
        if not row[0]:
            raise HTTPException(404, "No permanent identity registered for this handle")
        if not row[1]:
            raise HTTPException(404, "No recovery escrow stored for this handle")
        return row[0], json.loads(row[1])

    def _decrypt_escrow(escrow: dict, passphrase: str) -> bytes:
        """Decrypt escrow blob with passphrase; raises ValueError on wrong passphrase."""
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _S
        # Use argon2 params stored in escrow
        salt = bytes.fromhex(escrow["argon2_salt"])
        tc = escrow.get("argon2_time_cost", 3)
        mc = escrow.get("argon2_memory_cost", 65536)
        pa = escrow.get("argon2_parallelism", 4)
        from argon2.low_level import hash_secret_raw, Type
        key = hash_secret_raw(passphrase.encode(), salt, time_cost=tc,
                               memory_cost=mc, parallelism=pa,
                               hash_len=32, type=Type.ID)
        ciphertext = base64.b64decode(escrow["encrypted_identity_key"])
        nonce, ct = ciphertext[:12], ciphertext[12:]
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            return AESGCM(key).decrypt(nonce, ct, None)
        except Exception:
            raise ValueError("Wrong recovery passphrase")

    class RecoverBody(BaseModel):
        handle: str
        recovery_passphrase: str

    @app.post("/identity/recover")
    def recover_identity(body: RecoverBody, request: Request):
        """Decrypt and return the identity private key for a handle.
        Requires registry session (Google auth) + recovery passphrase."""
        if not _get_session(request):
            raise HTTPException(401, "Sign in first")
        _, escrow = _escrow_for_handle(body.handle)
        try:
            id_priv = _decrypt_escrow(escrow, body.recovery_passphrase)
        except ValueError as e:
            raise HTTPException(403, str(e))
        return {"identity_private_key": id_priv.hex()}

    class ChangePassphraseBody(BaseModel):
        handle: str
        old_recovery_passphrase: str
        new_recovery_passphrase: str

    @app.post("/identity/change-passphrase", status_code=204)
    def change_identity_passphrase(body: ChangePassphraseBody, request: Request):
        """Re-encrypt the identity key escrow under a new passphrase.
        Requires registry session (Google auth) + recovery passphrase."""
        if not _get_session(request):
            raise HTTPException(401, "Sign in first")
        user_id, escrow = _escrow_for_handle(body.handle)
        try:
            id_priv = _decrypt_escrow(escrow, body.old_recovery_passphrase)
        except ValueError as e:
            raise HTTPException(403, str(e))
        # Re-encrypt under new passphrase
        new_salt = os.urandom(16)
        from argon2.low_level import hash_secret_raw, Type
        tc = escrow.get("argon2_time_cost", 3)
        mc = escrow.get("argon2_memory_cost", 65536)
        pa = escrow.get("argon2_parallelism", 4)
        new_key = hash_secret_raw(body.new_recovery_passphrase.encode(), new_salt,
                                   time_cost=tc, memory_cost=mc, parallelism=pa,
                                   hash_len=32, type=Type.ID)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        new_ct = AESGCM(new_key).encrypt(nonce, id_priv, None)
        new_escrow = {**escrow,
                      "encrypted_identity_key": base64.b64encode(nonce + new_ct).decode(),
                      "argon2_salt": new_salt.hex()}
        con.execute("UPDATE handles SET encrypted_identity_key = ? WHERE user_id = ?",
                    (json.dumps(new_escrow), user_id))
        con.commit()

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

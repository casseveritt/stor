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
        owner_id = cert.get("owner_id") or cert["user_id"]
        canonical = (f"contacc:delegate:{owner_id}:"
                     f"{cert['node_public_key']}:{cert['expires_at']}")
        id_pub.verify(base64.b64decode(cert["signature"] + "=="), canonical.encode())
        return True
    except Exception:
        return False


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    # Schema v3: node_id is PK (node deployment); owner_id is person identifier (stable, groups 1:n nodes).
    con.execute("""
        CREATE TABLE IF NOT EXISTS handles (
            node_id       TEXT PRIMARY KEY,
            owner_id      TEXT NOT NULL,
            username      TEXT NOT NULL DEFAULT '',
            server_url    TEXT NOT NULL,
            public_key    TEXT NOT NULL,
            ttl           INTEGER NOT NULL DEFAULT 14400,
            registered_at INTEGER NOT NULL,
            updated_at    INTEGER NOT NULL,
            display_name  TEXT,
            web_url       TEXT,
            identity_public_key TEXT,
            delegation_sig TEXT,
            encrypted_identity_key TEXT,
            google_identity TEXT,
            is_primary    INTEGER DEFAULT 0,
            superseded_at INTEGER
        )
    """)
    # Migrate from v2 schema (user_id PK) to v3 (node_id PK, owner_id separate)
    try:
        con.execute("SELECT owner_id FROM handles LIMIT 1")
    except Exception:
        con.execute("ALTER TABLE handles RENAME TO _handles_v2")
        con.execute("""
            CREATE TABLE handles (
                node_id       TEXT PRIMARY KEY,
                owner_id      TEXT NOT NULL,
                username      TEXT NOT NULL DEFAULT '',
                server_url    TEXT NOT NULL,
                public_key    TEXT NOT NULL,
                ttl           INTEGER NOT NULL DEFAULT 14400,
                registered_at INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL,
                display_name  TEXT,
                web_url       TEXT,
                identity_public_key TEXT,
                delegation_sig TEXT,
                encrypted_identity_key TEXT,
                google_identity TEXT,
                is_primary    INTEGER DEFAULT 0,
                superseded_at INTEGER
            )
        """)
        con.execute("""
            INSERT INTO handles
              (node_id, owner_id, username, server_url, public_key, ttl, registered_at,
               updated_at, display_name, web_url, identity_public_key, delegation_sig,
               encrypted_identity_key, google_identity, is_primary)
            SELECT
              COALESCE(node_id, user_id),
              user_id,
              username, server_url, public_key, ttl, registered_at, updated_at,
              display_name, web_url, identity_public_key, delegation_sig,
              encrypted_identity_key, google_identity, COALESCE(is_primary, 0)
            FROM _handles_v2
        """)
        con.execute("DROP TABLE _handles_v2")
        con.commit()
    con.execute("CREATE INDEX IF NOT EXISTS handles_owner_id ON handles (owner_id)")
    con.execute("CREATE INDEX IF NOT EXISTS handles_username ON handles (username)")

    con.execute("""
        CREATE TABLE IF NOT EXISTS registry_keys (
            id          INTEGER PRIMARY KEY DEFAULT 1,
            private_key TEXT NOT NULL,
            public_key  TEXT NOT NULL
        )
    """)
    _reg_key_row = con.execute("SELECT private_key, public_key FROM registry_keys WHERE id = 1").fetchone()
    if not _reg_key_row:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EPK
        from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF, PrivateFormat as _PRF, NoEncryption as _NE
        _rk = _EPK.generate()
        _rk_priv_hex = _rk.private_bytes(_E.Raw, _PRF.Raw, _NE()).hex()
        _rk_pub_b64 = base64.b64encode(_rk.public_key().public_bytes(_E.Raw, _PF.Raw)).decode()
        con.execute("INSERT INTO registry_keys (id, private_key, public_key) VALUES (1, ?, ?)", (_rk_priv_hex, _rk_pub_b64))
        con.commit()
        _registry_signing_key = _rk
        _registry_pub_b64 = _rk_pub_b64
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EPK
        _registry_signing_key = _EPK.from_private_bytes(bytes.fromhex(_reg_key_row[0]))
        _registry_pub_b64 = _reg_key_row[1]

    def _sign_record(record: dict) -> dict:
        """Return a signed node record stripped of owner_id — querying nodes don't need it."""
        queried_at = int(time.time())
        node_id = record.get('node_id', '')
        server_url = record.get('server_url', '')
        handle = record.get('handle', '') or ''
        display_name = record.get('display_name', '') or ''
        canonical = (f"contacc:node-record:{queried_at}:{node_id}:"
                     f"{server_url}:{handle}:{display_name}")
        sig = base64.b64encode(_registry_signing_key.sign(canonical.encode())).decode()
        return {
            "node_id": node_id,
            "server_url": server_url,
            "web_url": record.get("web_url"),
            "handle": handle,
            "display_name": display_name or None,
            "queried_at": queried_at,
            "registry_signature": sig,
            "registry_public_key": _registry_pub_b64,
        }

    con.execute("""
        CREATE TABLE IF NOT EXISTS tang_keys (
            node_id    TEXT PRIMARY KEY,
            t_priv     BLOB NOT NULL,
            t_pub      TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)

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

    app = FastAPI(title="contacc registry", docs_url=None, redoc_url=None)

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

    @app.get("/auth/nodes")
    def auth_nodes(request: Request):
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Not authenticated")
        rows = con.execute(
            "SELECT username, display_name, server_url, web_url, node_id, owner_id, "
            "public_key, delegation_sig, identity_public_key, is_primary "
            "FROM handles WHERE google_identity = ? ORDER BY is_primary DESC, updated_at DESC",
            (identity,)
        ).fetchall()
        nodes = []
        for r in rows:
            node = {"handle": r[0], "display_name": r[1], "server_url": r[2],
                    "web_url": r[3], "node_id": r[4], "owner_id": r[5],
                    "user_id": r[5],  # legacy alias
                    "public_key": r[6], "identity_public_key": r[8], "is_primary": bool(r[9])}
            if r[7]:
                try:
                    node["delegation_cert"] = json.loads(r[7])
                except Exception:
                    pass
            nodes.append(node)
        return {"nodes": nodes}

    # ── Tang network-bound unlock ─────────────────────────────────────────────

    class TangRegisterBody(BaseModel):
        node_id: str
        identity_public_key: str   # base64 (identity key OR node key)
        timestamp: int
        signature: str             # signs "contacc:tang:register:{node_id}:{timestamp}"

    @app.post("/tang/register")
    def tang_register(body: TangRegisterBody):
        """Generate a per-node Tang X25519 key pair. Authenticated by identity key or node key."""
        _check_timestamp(body.timestamp)
        msg = f"contacc:tang:register:{body.node_id}:{body.timestamp}"
        pub_bytes = base64.b64decode(body.identity_public_key + "==")
        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
                base64.b64decode(body.signature + "=="), msg.encode())
        except Exception:
            # Fall back to checking against the registered node key
            row = con.execute("SELECT public_key FROM handles WHERE node_id = ?", (body.node_id,)).fetchone()
            if not row:
                raise HTTPException(401, "Node not found")
            try:
                node_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(row[0] + "=="))
                node_pub.verify(base64.b64decode(body.signature + "=="), msg.encode())
            except Exception:
                raise HTTPException(401, "Invalid signature")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
        t_priv = X25519PrivateKey.generate()
        t_pub_bytes = t_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        t_priv_bytes = t_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        t_pub_b64 = base64.b64encode(t_pub_bytes).decode()
        con.execute("INSERT OR REPLACE INTO tang_keys (node_id, t_priv, t_pub, created_at) VALUES (?, ?, ?, ?)",
                    (body.node_id, t_priv_bytes, t_pub_b64, time.time_ns()))
        con.commit()
        return {"T_pub": t_pub_b64}

    class TangExchangeBody(BaseModel):
        node_id: str
        C: str           # base64 client ephemeral X25519 public key
        nonce: str       # one-time nonce generated by the node
        callback_url: str

    @app.post("/tang/exchange", status_code=202)
    def tang_exchange(body: TangExchangeBody):
        """Compute S = X25519(t_priv_node, C) and deliver it to the node's callback URL."""
        row = con.execute("SELECT t_priv FROM tang_keys WHERE node_id = ?", (body.node_id,)).fetchone()
        if not row:
            raise HTTPException(404, "No Tang key registered for this node")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        t_priv = X25519PrivateKey.from_private_bytes(row[0])
        try:
            C_bytes = base64.b64decode(body.C + "==")
            C_pub = X25519PublicKey.from_public_bytes(C_bytes)
        except Exception:
            raise HTTPException(400, "Invalid C (client public key)")
        S_bytes = t_priv.exchange(C_pub)
        S_b64 = base64.b64encode(S_bytes).decode()
        # Deliver S to the node's registered URL (the "check" — only the real node receives it)
        try:
            r = httpx.post(body.callback_url, json={"S": S_b64, "nonce": body.nonce}, timeout=10, verify=True)
            if not r.is_success:
                raise HTTPException(502, f"Tang delivery failed: {r.status_code}")
        except httpx.RequestError as e:
            raise HTTPException(502, f"Could not reach node for Tang delivery: {e}")
        return {"status": "delivered"}

    class TangExchangeDirectBody(BaseModel):
        node_id: str
        C: str
        node_public_key: str   # base64 — must match registry's stored public_key
        timestamp: int
        signature: str         # node_key signs "contacc:tang:direct:{node_id}:{C}:{timestamp}"

    @app.post("/tang/exchange-direct")
    def tang_exchange_direct(body: TangExchangeDirectBody):
        """Return S directly (no callback) for authenticated node operations like passphrase change."""
        _check_timestamp(body.timestamp)
        # Verify node key signature
        msg = f"contacc:tang:direct:{body.node_id}:{body.C}:{body.timestamp}"
        if not _verify_sig(body.node_public_key, msg, body.signature):
            raise HTTPException(401, "Invalid node key signature")
        # Verify the node_public_key matches what's registered
        row = con.execute("SELECT public_key FROM handles WHERE node_id = ?", (body.node_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Node not registered")
        if row[0] != body.node_public_key:
            raise HTTPException(403, "Node key mismatch")
        # Compute S
        tang_row = con.execute("SELECT t_priv FROM tang_keys WHERE node_id = ?", (body.node_id,)).fetchone()
        if not tang_row:
            raise HTTPException(404, "No Tang key for this node")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        t_priv = X25519PrivateKey.from_private_bytes(tang_row[0])
        C_pub = X25519PublicKey.from_public_bytes(base64.b64decode(body.C + "=="))
        S_bytes = t_priv.exchange(C_pub)
        return {"S": base64.b64encode(S_bytes).decode()}

    def _require_node_ownership(request, node_id: str) -> str:
        """Verify session owns this node; return google_identity."""
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Not authenticated")
        row = con.execute(
            "SELECT google_identity FROM handles WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Node not found")
        if row[0] != identity:
            raise HTTPException(403, "Not your node")
        return identity

    class UpdateNodeBody(BaseModel):
        handle: str | None = None
        display_name: str | None = None

    @app.get("/meta")
    def registry_meta():
        return {"public_key": _registry_pub_b64, "version": 1}

    @app.get("/nodes/{node_id}")
    def get_node(node_id: str):
        row = con.execute(
            "SELECT server_url, web_url, username, display_name, owner_id FROM handles WHERE node_id = ?",
            (node_id,)
        ).fetchone()
        if not row:
            # Try owner_id lookup — return primary node for this owner
            row2 = con.execute(
                "SELECT server_url, web_url, username, display_name, owner_id, node_id "
                "FROM handles WHERE owner_id = ? ORDER BY is_primary DESC, updated_at DESC LIMIT 1",
                (node_id,)
            ).fetchone()
            if not row2:
                raise HTTPException(404, "Node not found")
            rec = {"node_id": row2[5], "owner_id": row2[4], "user_id": row2[4],
                   "server_url": row2[0], "web_url": row2[1], "handle": row2[2], "display_name": row2[3]}
            return _sign_record(rec)
        rec = {"node_id": node_id, "owner_id": row[4], "user_id": row[4],
               "server_url": row[0], "web_url": row[1], "handle": row[2], "display_name": row[3]}
        return _sign_record(rec)

    @app.patch("/nodes/{node_id}", status_code=204)
    def update_node(node_id: str, body: UpdateNodeBody, request: Request):
        _require_node_ownership(request, node_id)
        updates, params = [], []
        if body.handle is not None:
            updates.append("username = ?"); params.append(body.handle.lower())
        if body.display_name is not None:
            updates.append("display_name = ?"); params.append(body.display_name)
        if not updates:
            raise HTTPException(422, "Nothing to update")
        params.extend([time.time_ns(), node_id])
        con.execute(f"UPDATE handles SET {', '.join(updates)}, updated_at = ? WHERE node_id = ?", params)
        con.commit()

    @app.delete("/nodes/{node_id}", status_code=204)
    def remove_node(node_id: str, request: Request):
        _require_node_ownership(request, node_id)
        con.execute("DELETE FROM handles WHERE node_id = ?", (node_id,))
        con.commit()

    class RedelegateBody(BaseModel):
        identity_private_key: str  # hex

    @app.post("/nodes/{node_id}/redelegate", status_code=204)
    def redelegate_node(node_id: str, body: RedelegateBody, request: Request):
        _require_node_ownership(request, node_id)
        row = con.execute(
            "SELECT public_key, identity_public_key, owner_id FROM handles WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Node not found")
        node_pub_b64, stored_id_pub, owner_id = row
        # Verify identity key matches
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EPK
        from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
        try:
            id_key = _EPK.from_private_bytes(bytes.fromhex(body.identity_private_key))
            provided_pub = base64.b64encode(id_key.public_key().public_bytes(_E.Raw, _PF.Raw)).decode()
            if provided_pub != stored_id_pub:
                raise HTTPException(403, "Identity key does not match this node's identity")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, "Invalid identity private key")
        # Sign new delegation cert (owner_id is the person identifier, node_id is deployment-specific)
        from server.identity import make_delegation_cert as _mkdel
        cert = _mkdel(id_key, owner_id, node_pub_b64, node_id=node_id)
        con.execute("UPDATE handles SET delegation_sig = ?, updated_at = ? WHERE node_id = ?",
                    (json.dumps(cert), time.time_ns(), node_id))
        con.commit()

    @app.post("/nodes/{node_id}/supersede", status_code=204)
    def supersede_node(node_id: str, request: Request):
        """Mark a node as superseded (replaced by a new deployment). Requires registry session."""
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Sign in first")
        row = con.execute(
            "SELECT google_identity, superseded_at FROM handles WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Node not found")
        if row[0] != identity:
            raise HTTPException(403, "Not your node")
        if row[1]:
            raise HTTPException(409, "Node already superseded")
        con.execute("UPDATE handles SET superseded_at = ? WHERE node_id = ?", (time.time_ns(), node_id))
        con.commit()

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
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='114.1085 98.626948 11.98291 9.7358322'%3E%3Cpath style='fill:%234285f4' d='m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z'/%3E%3Cpath style='fill:%234285f4' d='m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z'/%3E%3C/svg%3E" type="image/svg+xml">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #111; color: #e0e0e0;
           min-height: 100vh; padding: 2rem 1rem; }
    .page { max-width: 540px; margin: 0 auto; display: flex; flex-direction: column; gap: 2rem; }
    .logo { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; }
    .logo span { font-size: 1.8rem; font-weight: 300; letter-spacing: 0.1em; color: #fff; }
    .logo small { font-size: 0.8rem; color: #555; margin-left: 0.25rem; align-self: flex-end; margin-bottom: 0.2rem; }
    .auth-gate-box { display: flex; flex-direction: column; align-items: center; gap: 2rem; text-align: center; padding: 3rem 1rem; }
    [hidden] { display: none !important; }
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
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="114.1085 98.626948 11.98291 9.7358322" style="height:2.2rem;width:auto"><path style="fill:#4285f4;stroke-width:0.199817" d="m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z"/><path style="fill:#4285f4;stroke-width:0.199817" d="m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z"/></svg>
    <span>contacc</span><small>registry</small>
  </div>
  <div style="display:flex;gap:1rem;font-size:0.82rem">
    <a href="/docs" style="color:#4285f4;text-decoration:none">Overview</a>
    <a href="/docs/api" style="color:#4285f4;text-decoration:none">Getting started</a>
    <a href="/docs/roadmap" style="color:#4285f4;text-decoration:none">Roadmap</a>
  </div>

  <!-- Auth gate — shown when not signed in -->
  <div id="auth-gate" class="auth-gate-box" hidden>
    <p style="color:#888;font-size:1rem">Please sign in to continue.</p>
    <button class="btn btn-primary" onclick="signIn()">Sign in with Google</button>
  </div>

  <!-- Recover identity key — shown when signed in -->
  <!-- Nodes — shown when signed in -->
  <div id="nodes-card" class="card" style="display:none">
    <h2 id="nodes-heading">Node</h2>
    <div id="nodes-list"></div>
  </div>

  <div id="recover-card" class="card" style="display:none">
    <h2>Recover identity key</h2>
    <p style="font-size:0.82rem;color:#666;margin-bottom:0.75rem">
      If you've lost access to your node, enter your handle and owner passphrase
      to retrieve your identity private key.
    </p>
    <div class="field">
      <input id="rec-pass" type="password" placeholder="Owner passphrase">
    </div>
    <button class="btn btn-primary" onclick="doRecover()">Retrieve key</button>
    <div id="rec-msg" class="msg"></div>
    <div id="rec-key" class="key-box"></div>
    <div id="rec-warn" style="display:none">
      <p class="warn">⚠ Save this key immediately.</p>
      <p style="font-size:0.8rem;color:#888;margin-top:0.4rem">
        For security, close this entire tab once you have saved the key.
        The browser cannot reliably erase key material from memory — closing the tab is the only safe way to discard it.
      </p>
    </div>
    <button id="rec-clear" class="btn btn-muted" style="display:none" onclick="window.close()">Close tab</button>
  </div>

  <!-- Change owner passphrase — shown when signed in -->
  <div id="chgpass-card" class="card" style="display:none">
    <h2>Change owner passphrase</h2>
    <div class="field">
      <input id="chg-old" type="password" placeholder="Current owner passphrase">
    </div>
    <div class="field">
      <input id="chg-new" type="password" placeholder="New owner passphrase">
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
    try {
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
    } catch(e) {
      console.error("checkAuth failed:", e);
      showAuth(false);
    }
  }

  function showAuth(authed, identity) {
    _authed = authed;
    document.getElementById("auth-gate").hidden = authed;
    document.getElementById("nodes-card").style.display = authed ? "" : "none";
    document.getElementById("recover-card").style.display = authed ? "" : "none";
    document.getElementById("chgpass-card").style.display = authed ? "" : "none";
    document.getElementById("auth-footer").style.display = authed ? "" : "none";
    if (authed && identity) document.getElementById("auth-identity").textContent = identity;
    if (authed) loadNodes();
  }

  function esc(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  let _nodes = [];

  async function loadNodes() {
    const r = await fetch("/auth/nodes");
    if (!r.ok) return;
    const { nodes } = await r.json();
    _nodes = nodes;
    document.getElementById("nodes-heading").textContent = nodes.length === 1 ? "Node" : "Nodes";
    document.getElementById("nodes-list").innerHTML = nodes.map((n, i) => {
      const name = n.display_name || n.handle;
      const link = n.web_url || n.server_url;
      const cert = n.delegation_cert || {};
      const expiry = cert.expires_at ? new Date(cert.expires_at / 1_000_000).toLocaleDateString() : "unknown";
      const pubShort = n.public_key ? n.public_key.slice(0,16)+"…" : "—";
      return `<div style="border-bottom:1px solid #2a2a2a;padding:0.5rem 0">
        <div style="display:flex;align-items:center;justify-content:space-between">
          <div>
            <div style="font-size:0.92rem;color:#e0e0e0">${esc(name)}</div>
            <div style="font-size:0.75rem;color:#555">@${esc(n.handle)} &nbsp;·&nbsp; ${esc(n.server_url)}</div>
          </div>
          <div style="display:flex;gap:0.4rem;align-items:center">
            ${(n.is_primary || nodes.length === 1) ? '<span style="font-size:0.75rem;color:#6cbe6c;padding:0.3rem 0.5rem">★ primary</span>' : `<button class="btn btn-muted" style="font-size:0.8rem;padding:0.3rem 0.7rem" onclick="setPrimary('${esc(n.node_id)}')">Set primary</button>`}
            ${link ? `<a href="${esc(link)}" target="_blank" class="btn btn-muted" style="font-size:0.8rem;padding:0.3rem 0.7rem;text-decoration:none">Open ↗</a>` : ''}
            <button class="btn btn-muted" style="font-size:0.8rem;padding:0.3rem 0.7rem" onclick="toggleNode(${i})">Info ▾</button>
          </div>
        </div>
        <div id="node-info-${i}" style="display:none;margin-top:0.75rem;display:none">
          <div style="font-size:0.78rem;color:#555;margin-bottom:0.6rem">
            <strong style="color:#888">Owner ID:</strong> ${esc(n.owner_id)}<br>
            <strong style="color:#888">Node ID:</strong> ${esc(n.node_id)}<br>
            <strong style="color:#888">Node key:</strong> ${esc(pubShort)}<br>
            <strong style="color:#888">Delegation expires:</strong> ${esc(expiry)}
          </div>
          <div style="display:flex;flex-direction:column;gap:0.5rem">
            <details style="background:#111;border-radius:4px;padding:0.5rem">
              <summary style="cursor:pointer;font-size:0.85rem;color:#aaa">Update handle / display name</summary>
              <div style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.4rem">
                <input type="text" id="node-handle-${i}" placeholder="Handle" value="${esc(n.handle)}" style="font-size:0.85rem">
                <input type="text" id="node-name-${i}" placeholder="Display name" value="${esc(n.display_name||'')}" style="font-size:0.85rem">
                <button class="btn btn-primary" style="font-size:0.82rem" onclick="updateNode(${i})">Save</button>
                <div id="node-update-msg-${i}" class="msg"></div>
              </div>
            </details>
            <details style="background:#111;border-radius:4px;padding:0.5rem">
              <summary style="cursor:pointer;font-size:0.85rem;color:#aaa">Re-delegate (renew cert)</summary>
              <div style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.4rem">
                <input type="password" id="node-idkey-${i}" placeholder="Identity private key (hex)" style="font-size:0.82rem;font-family:monospace">
                <button class="btn btn-primary" style="font-size:0.82rem" onclick="redelegateNode(${i})">Sign new delegation</button>
                <div id="node-redeleg-msg-${i}" class="msg"></div>
              </div>
            </details>
            <details style="background:#111;border-radius:4px;padding:0.5rem">
              <summary style="cursor:pointer;font-size:0.85rem;color:#c8a84a">Supersede (replaced by new node)</summary>
              <div style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.4rem">
                <p style="font-size:0.82rem;color:#888">Mark this node as superseded after restoring a backup onto a new node. Superseded nodes cannot update their registry entry.</p>
                <button class="btn" style="background:#2a2a1a;color:#c8a84a;font-size:0.82rem" onclick="supersedeNode(${i})">Mark superseded</button>
                <div id="node-supersede-msg-${i}" class="msg"></div>
              </div>
            </details>
            <details style="background:#111;border-radius:4px;padding:0.5rem">
              <summary style="cursor:pointer;font-size:0.85rem;color:#e06c6c">Remove from registry</summary>
              <div style="margin-top:0.5rem;display:flex;flex-direction:column;gap:0.4rem">
                <p style="font-size:0.82rem;color:#888">This only removes the registry entry — the node continues running.</p>
                <button class="btn" style="background:#3a1a1a;color:#e06c6c;font-size:0.82rem" onclick="removeNode(${i})">Remove</button>
                <div id="node-remove-msg-${i}" class="msg"></div>
              </div>
            </details>
          </div>
        </div>
      </div>`;
    }).join('') || '<div style="color:#555;font-size:0.85rem">No nodes found for your account.</div>';
  }

  function toggleNode(i) {
    const el = document.getElementById("node-info-"+i);
    el.style.display = el.style.display === "none" ? "block" : "none";
  }

  async function updateNode(i) {
    const n = _nodes[i];
    const handle = document.getElementById("node-handle-"+i).value.trim().toLowerCase();
    const displayName = document.getElementById("node-name-"+i).value.trim();
    const msg = document.getElementById("node-update-msg-"+i);
    msg.textContent = "Saving…"; msg.className = "msg";
    const r = await fetch("/nodes/"+n.node_id, {
      method: "PATCH", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({handle, display_name: displayName}),
    });
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ Updated."; await loadNodes(); }
    else { const d = await r.json().catch(()=>{}); msg.className = "msg err"; msg.textContent = d?.detail||"Failed."; }
  }

  async function redelegateNode(i) {
    const n = _nodes[i];
    const key = document.getElementById("node-idkey-"+i).value.trim();
    const msg = document.getElementById("node-redeleg-msg-"+i);
    if (!key) { msg.className="msg err"; msg.textContent="Identity private key required."; return; }
    msg.textContent = "Signing…"; msg.className = "msg";
    const r = await fetch("/nodes/"+n.node_id+"/redelegate", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({identity_private_key: key}),
    });
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ New delegation cert signed."; await loadNodes(); }
    else { const d = await r.json().catch(()=>{}); msg.className = "msg err"; msg.textContent = d?.detail||"Failed."; }
  }

  async function supersedeNode(i) {
    const n = _nodes[i];
    const msg = document.getElementById("node-supersede-msg-"+i);
    if (!confirm("Mark @"+n.handle+" as superseded? This cannot be undone.")) return;
    const r = await fetch("/nodes/"+n.node_id+"/supersede", {method: "POST"});
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ Marked superseded."; await loadNodes(); }
    else { const d = await r.json().catch(()=>{}); msg.className = "msg err"; msg.textContent = d?.detail||"Failed."; }
  }

  async function removeNode(i) {
    const n = _nodes[i];
    const msg = document.getElementById("node-remove-msg-"+i);
    if (!confirm("Remove @"+n.handle+" from the registry?")) return;
    const r = await fetch("/nodes/"+n.node_id, {method: "DELETE"});
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ Removed."; await loadNodes(); }
    else { const d = await r.json().catch(()=>{}); msg.className = "msg err"; msg.textContent = d?.detail||"Failed."; }
  }

  async function setPrimary(nodeId) {
    const r = await fetch("/nodes/"+nodeId+"/set-primary", {method: "POST"});
    if (r.ok) await loadNodes();
  }

  function signIn() {
    window.location.href = "/auth/start?return_to=" + encodeURIComponent(location.origin + "/");
  }

  async function signOut() {
    await fetch("/auth/logout", {method: "POST"});
    showAuth(false);
  }

  async function doRecover() {
    const pass = document.getElementById("rec-pass").value;
    const msg = document.getElementById("rec-msg");
    const keyBox = document.getElementById("rec-key");
    const warn = document.getElementById("rec-warn");
    msg.textContent = ""; keyBox.style.display = "none"; warn.style.display = "none";
    if (!pass) { msg.className = "msg err"; msg.textContent = "Owner passphrase required."; return; }
    msg.className = "msg"; msg.textContent = "Decrypting…";
    const r = await fetch("/identity/recover", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({owner_passphrase: pass}),
    });
    const d = await r.json();
    if (!r.ok) { msg.className = "msg err"; msg.textContent = d.detail || "Failed."; return; }
    msg.textContent = "";
    keyBox.innerHTML =
      '<div style="color:#666;font-size:0.7rem;margin-bottom:0.2rem">Owner ID</div>' +
      '<div style="margin-bottom:0.6rem">' + (d.owner_id || d.user_id) + '</div>' +
      '<div style="color:#666;font-size:0.7rem;margin-bottom:0.2rem">Identity Public Key</div>' +
      '<div style="margin-bottom:0.6rem;word-break:break-all">' + d.identity_public_key + '</div>' +
      '<div style="color:#666;font-size:0.7rem;margin-bottom:0.2rem">Identity Private Key</div>' +
      '<div style="word-break:break-all">' + d.identity_private_key + '</div>';
    keyBox.style.display = "block";
    warn.style.display = "block";
    document.getElementById("rec-clear").style.display = "";
  }


  async function doChangePass() {
    const oldPass = document.getElementById("chg-old").value;
    const newPass = document.getElementById("chg-new").value;
    const msg = document.getElementById("chg-msg");
    msg.textContent = "";
    if (!oldPass || !newPass) { msg.className = "msg err"; msg.textContent = "Both passphrases required."; return; }
    msg.className = "msg"; msg.textContent = "Updating…";
    const r = await fetch("/identity/change-passphrase", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({old_owner_passphrase: oldPass, new_owner_passphrase: newPass}),
    });
    if (r.ok) { msg.className = "msg ok"; msg.textContent = "✓ Passphrase updated."; }
    else { const d = await r.json(); msg.className = "msg err"; msg.textContent = d.detail || "Failed."; }
  }

  checkAuth();
  const h = new URLSearchParams(location.search).get("handle");
</script>
</body>
</html>"""

    _DOC_STYLE = """
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #111; color: #e0e0e0;
           min-height: 100vh; padding: 2rem 1rem; font-size: 16px; }
    .page { max-width: 720px; margin: 0 auto; display: flex; flex-direction: column; gap: 2rem; }
    .logo { display: flex; align-items: center; gap: 0.6rem; }
    .logo span { font-size: 1.8rem; font-weight: 300; letter-spacing: 0.1em; color: #fff; }
    .logo small { font-size: 0.8rem; color: #555; margin-left: 0.25rem; align-self: flex-end; margin-bottom: 0.2rem; }
    nav { display: flex; gap: 1rem; font-size: 0.82rem; }
    nav a { color: #4285f4; text-decoration: none; }
    nav a:hover { text-decoration: underline; }
    h1 { font-size: 1.4rem; font-weight: 500; color: #fff; margin-bottom: 0.25rem; }
    h2 { font-size: 1.05rem; font-weight: 500; color: #ccc; margin: 1.75rem 0 0.5rem; border-bottom: 1px solid #222; padding-bottom: 0.3rem; }
    h3 { font-size: 0.92rem; font-weight: 600; color: #aaa; margin: 1.25rem 0 0.35rem; }
    p { font-size: 1rem; color: #bbb; line-height: 1.7; margin-bottom: 0.6rem; }
    ul, ol { padding-left: 1.4rem; margin-bottom: 0.6rem; }
    li { font-size: 1rem; color: #bbb; line-height: 1.7; margin-bottom: 0.2rem; }
    code { font-family: monospace; background: #1e1e1e; border: 1px solid #2a2a2a;
           border-radius: 3px; padding: 0.1em 0.35em; font-size: 0.82rem; color: #a8d8a8; }
    pre { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px;
          padding: 0.85rem 1rem; overflow-x: auto; margin-bottom: 0.75rem; }
    pre code { background: none; border: none; padding: 0; font-size: 0.82rem; color: #a8d8a8; }
    table { width: 100%; border-collapse: collapse; font-size: 0.84rem; margin-bottom: 0.75rem; }
    th { text-align: left; color: #888; font-weight: 500; padding: 0.35rem 0.6rem;
         border-bottom: 1px solid #2a2a2a; }
    td { padding: 0.3rem 0.6rem; color: #bbb; border-bottom: 1px solid #1e1e1e; vertical-align: top; }
    .badge { display: inline-block; background: #1e3a1e; color: #6cbe6c; border-radius: 3px;
             padding: 0.1em 0.4em; font-size: 0.75rem; font-weight: 600; margin-right: 0.3rem; }
    .badge-pending { background: #2a2a1e; color: #c8b86c; }
    strong { color: #ddd; }
    a { color: #4285f4; }
    """

    _README_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>contacc — getting started</title>
<style>""" + _DOC_STYLE + """</style></head>
<body><div class="page">
<div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="114.1085 98.626948 11.98291 9.7358322" style="height:2.2rem;width:auto"><path style="fill:#4285f4" d="m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z"/><path style="fill:#4285f4" d="m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z"/></svg>
<span>contacc</span><small>docs</small></div>
<nav><a href="/">Registry</a><a href="/docs">Overview</a><a href="/docs/api">Getting started</a><a href="/docs/roadmap">Roadmap</a></nav>

<div>
<h1>Getting started</h1>
<p>contacc is a personal data store and social feed. You own your data; you choose who sees what.</p>
</div>

<div>
<h2>What you need</h2>
<ul>
  <li>A Raspberry Pi or any Linux server running 24/7</li>
  <li><strong>Docker</strong> — <code>curl -fsSL https://get.docker.com | sh</code></li>
  <li><strong>A domain name</strong> pointed at your server's public IP (<a href="https://www.duckdns.org" target="_blank">DuckDNS</a> is free and works well on a Pi)</li>
  <li><strong>Ports open</strong> in your router: <code>80</code> (TLS), <code>8443–8452</code> (node APIs), <code>6443–6452</code> (web UIs)</li>
  <li>A setup token and web URL from your registry operator</li>
</ul>
<p>No Google Cloud Console setup required — Google OAuth is handled by the registry.</p>
</div>

<div>
<h2>Setup</h2>
<pre><code>git clone https://github.com/casseveritt/stor
cd stor
cp .env.example .env    # set CONTACC_DOMAIN and CONTACC_DATA_DIR
docker compose up -d --build</code></pre>
<p>Open the web UI URL your registry operator gave you, enter your setup token, fill in your name, handle, and a passphrase, and click <strong>Create Identity</strong>.</p>
<p>That's it. Your node is registered, network-bound unlock (Tang) is configured, and your identity key is escrowed — all automatically. You only need to remember your passphrase.</p>
</div>

<div>
<h2>Security model</h2>
<h3>Identity key</h3>
<p>An Ed25519 key pair generated at setup. The private key is never stored on the node. It signs delegation certificates that bind your <strong>owner ID</strong> (who you are) to a <strong>node ID</strong> (a specific node deployment) to a <strong>node key</strong> (the current operational key for that node).</p>
<h3>Node key</h3>
<p>The day-to-day Ed25519 signing key, stored encrypted in <code>node_config.json</code> using Argon2id + AES-256-GCM with your passphrase.</p>
<h3>Registry escrow</h3>
<p>Your identity private key is encrypted with your passphrase and uploaded to the registry at setup. To recover it: visit the registry, sign in with Google, enter your passphrase.</p>
<h3>Tang network-bound unlock</h3>
<p>The registry holds a per-node X25519 key. On startup your node asks the registry to compute a shared secret and deliver it to your node's registered URL. The registry only delivers to the address on file — so your node can only unlock if it's actually running at its registered location. No passphrase entry needed on restart.</p>
</div>

<div>
<h2>Architecture</h2>
<table>
<tr><th>Container</th><th>Internal port</th><th>Role</th></tr>
<tr><td><code>node-N-me</code></td><td>28443+N</td><td>Owns identity, posts, assets. Encrypted SQLCipher DB + AES-256-GCM files.</td></tr>
<tr><td><code>node-N-them</code></td><td>18443+N</td><td>Aggregates contacts' feeds. Proxies API calls to <em>me</em>.</td></tr>
<tr><td><code>web-N</code></td><td>16443+N</td><td>Static UI + reverse proxy to <em>them</em>.</td></tr>
<tr><td><code>registry</code></td><td>9532</td><td>Shared user→node URL directory. Run by the host operator.</td></tr>
<tr><td><code>caddy</code></td><td>—</td><td>TLS termination. Routes 8443+N → <em>them</em>, 6443+N → <em>web</em>.</td></tr>
</table>
<p>All external traffic enters through <em>them</em>, which proxies to <em>me</em> via an internal token. Caddy has no path-based routing rules.</p>
</div>

<div>
<h2>Day-to-day operations</h2>
<pre><code>docker compose logs -f                  # tail all logs
docker compose up -d                    # start everything
docker compose down                     # stop everything</code></pre>
<p>Use the <strong>Backup</strong> button in the web UI to download your data. To restore, use the <strong>Restore Backup</strong> tab in the setup wizard on a fresh node.</p>
</div>

</div></body></html>"""

    _ROADMAP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>contacc — roadmap</title>
<style>""" + _DOC_STYLE + """</style></head>
<body><div class="page">
<div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="114.1085 98.626948 11.98291 9.7358322" style="height:2.2rem;width:auto"><path style="fill:#4285f4" d="m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z"/><path style="fill:#4285f4" d="m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z"/></svg>
<span>contacc</span><small>docs</small></div>
<nav><a href="/">Registry</a><a href="/docs">Overview</a><a href="/docs/api">Getting started</a><a href="/docs/roadmap">Roadmap</a></nav>

<div>
<h1>Roadmap</h1>
</div>

<div>
<h2>Pending</h2>

<h3><span class="badge">done</span> Separate node_id from owner_id (0a)</h3>
<p><code>owner_id</code> permanently identifies a person; <code>node_id</code> identifies a specific deployment. The registry schema (v3) uses <code>node_id</code> as the primary key with <code>owner_id</code> as a grouping column, enabling multiple nodes per owner.</p>

<h3><span class="badge">done</span> Multiple nodes per identity — registry (0b)</h3>
<p>Registry schema supports 1:n nodes per <code>owner_id</code>. The "link to existing identity" setup path (providing the identity private key to sign a delegation cert for a new node) is also implemented.</p>

<h3><span class="badge badge-pending">planned</span> Restore-from-backup supersession (0c)</h3>
<p>When restoring a backup onto a new node, the old node can be superseded via the registry landing page. Superseded nodes are blocked from updating their registration (HTTP 410). Shutdown of the old node and cert revocation remain manual steps.</p>

<h3><span class="badge badge-pending">planned</span> Upload identity escrow from settings</h3>
<p>Users who set up before the automatic escrow flow can upload their identity key escrow from the profile/settings UI (requires their identity private key).</p>

<h3><span class="badge badge-pending">planned</span> Profile photo preview on hover</h3>
<p>Show a larger version of a contact's photo when hovering over their avatar.</p>

<h3><span class="badge badge-pending">planned</span> Reaction emoji</h3>
<p>React to posts and comments with emoji. Stored server-side, attributed to the reactor, displayed as grouped counts.</p>

<h3><span class="badge badge-pending">planned</span> @mention notifications</h3>
<p>When a post contains <code>@handle</code>, push a lightweight ping to the tagged contact's server. Surface an unread-mentions badge and mentions feed.</p>

<h3><span class="badge badge-pending">planned</span> Chat / direct messages</h3>
<p>1:1 and small-group messaging. End-to-end encrypted, stored on sender's node, pushed or polled by recipient.</p>
</div>

<div>
<h2>Completed</h2>

<h3><span class="badge">done</span> Permanent identity (UUID + identity key)</h3>
<p>UUID + Ed25519 identity key generated at setup. Identity key never stored on node. Delegation cert links identity key → node key.</p>

<h3><span class="badge">done</span> Registry escrow</h3>
<p>Identity private key encrypted with owner passphrase, uploaded to registry at setup. Recoverable via Google auth + passphrase at the registry landing page.</p>

<h3><span class="badge">done</span> Tang network-bound unlock</h3>
<p>Registry holds a per-node X25519 key. On startup the node sends its ephemeral public key to the registry; registry computes a shared secret and delivers it to the node's registered URL — the node can only unlock if it's actually at its registered address. Auto-registers when a node changes its passphrase for the first time. Retries at 2s, 7s, 22s after startup.</p>

<h3><span class="badge">done</span> Automatic setup flow</h3>
<p>Registration, Tang, and escrow all happen server-side during setup. No extra screens. User only needs to remember their passphrase.</p>

<h3><span class="badge">done</span> Full name at setup</h3>
<p>Stored in the profile table at setup, sent to the registry via heartbeat, searchable when adding contacts.</p>

<h3><span class="badge">done</span> Default passphrase banner</h3>
<p>Red banner prompts users still on the default passphrase to set a real one. Also updates registry escrow if escrow passphrase is also the default.</p>

<h3><span class="badge">done</span> Aggregate feed + contacts</h3>
<p>Client fetches all contacts in parallel and merges by timestamp. Add/remove contacts by handle via registry lookup. Contact URL auto-refreshed on failure.</p>

<h3><span class="badge">done</span> Visibility system</h3>
<p><code>private</code> | <code>contacts</code> | <code>authenticated</code> | <code>public</code> for both post visibility and comment access. Both must pass independently.</p>

<h3><span class="badge">done</span> Multi-slot deployment</h3>
<p>Up to 10 node slots per host (ports 8443–8452 / 6443–6452). Independent web layer per slot. All external traffic routes through <em>them</em>; path-based routing decisions live in code, not Caddy.</p>

<h3><span class="badge">done</span> Registry landing page</h3>
<p>Google auth, node list, passphrase recovery, change owner passphrase.</p>
</div>

</div></body></html>"""

    @app.get("/", response_class=HTMLResponse)
    def index():
        return _INDEX_HTML

    _OVERVIEW_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>contacc — overview</title>
<style>""" + _DOC_STYLE + """
blockquote { border-left: 3px solid #2a2a2a; margin: 0.75rem 0; padding: 0.5rem 1rem; }
blockquote p { color: #888; font-style: italic; }
.diagram { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px;
           padding: 1rem 1.25rem; font-family: monospace; font-size: 0.8rem;
           color: #888; line-height: 1.7; overflow-x: auto; white-space: pre; }
.diagram em { color: #4285f4; font-style: normal; }
</style></head>
<body><div class="page">
<div class="logo"><svg xmlns="http://www.w3.org/2000/svg" viewBox="114.1085 98.626948 11.98291 9.7358322" style="height:2.2rem;width:auto"><path style="fill:#4285f4" d="m 125.34474,104.96592 0.74667,1.9637 -0.10218,0.12403 c -0.0734,-0.11943 -0.13361,-0.17915 -0.18077,-0.17915 -0.0472,0 -0.17946,0.11024 -0.39691,0.33073 -0.45062,0.45475 -0.8305,0.76252 -1.13965,0.92329 -0.30652,0.15617 -0.67199,0.23426 -1.09641,0.23426 -0.84623,0 -1.54049,-0.3514 -2.08281,-1.0542 -0.31962,-0.40881 -0.50719,-0.82671 -0.69058,-1.43305 -0.19942,-1.14201 -0.14909,-1.18922 -0.15208,-2.72041 -0.003,-1.67715 -0.007,-1.74466 0.33965,-2.63337 0.44703,-1.145722 1.43438,-1.894801 2.58975,-1.894801 0.42442,0 0.78858,0.07809 1.09248,0.234267 0.30391,0.156177 0.68379,0.463939 1.13965,0.923285 0.21745,0.215889 0.34975,0.323839 0.39691,0.323839 0.0472,0 0.10742,-0.0597 0.18077,-0.179145 l 0.10218,0.124025 -0.74667,1.9637 -0.1061,-0.12402 c 0.005,-0.0735 0.008,-0.13551 0.008,-0.18604 0,-0.13321 -0.0327,-0.25723 -0.0983,-0.37207 -0.0655,-0.11943 -0.18208,-0.26182 -0.34975,-0.42719 -0.46372,-0.45935 -0.95495,-0.68902 -1.47368,-0.68902 -0.61305,0 -1.10166,0.26872 -1.46582,0.80615 -0.42966,0.62931 -0.64449,1.45154 -0.64449,2.46669 0,1.01515 0.21483,1.83738 0.64449,2.46669 0.36416,0.53743 0.85277,0.80615 1.46582,0.80615 0.51873,0 1.00996,-0.22967 1.47368,-0.68902 0.16767,-0.16537 0.28426,-0.30547 0.34975,-0.4203 0.0655,-0.11943 0.0983,-0.24575 0.0983,-0.37896 0,-0.0505 -0.003,-0.11025 -0.008,-0.17915 z"/><path style="fill:#4285f4" d="m 114.85517,104.96592 -0.74667,1.9637 0.10218,0.12403 c 0.0734,-0.11943 0.13361,-0.17915 0.18077,-0.17915 0.0472,0 0.17946,0.11024 0.39691,0.33073 0.45062,0.45475 0.8305,0.76252 1.13965,0.92329 0.30652,0.15617 0.67199,0.23426 1.09641,0.23426 0.84623,0 1.54049,-0.3514 2.08281,-1.0542 0.31962,-0.40881 0.50719,-0.82671 0.69058,-1.43305 0.19942,-1.14201 0.14909,-1.18922 0.15208,-2.72041 0.003,-1.67715 0.007,-1.74466 -0.33965,-2.63337 -0.44703,-1.145723 -1.43438,-1.894802 -2.58975,-1.894802 -0.42442,0 -0.78858,0.07809 -1.09248,0.234267 -0.30391,0.156177 -0.68379,0.463939 -1.13965,0.923285 -0.21745,0.21589 -0.34975,0.32384 -0.39691,0.32384 -0.0472,0 -0.10742,-0.0597 -0.18077,-0.179146 l -0.10218,0.124026 0.74667,1.9637 0.1061,-0.12402 c -0.005,-0.0735 -0.008,-0.13551 -0.008,-0.18604 0,-0.13321 0.0327,-0.25723 0.0982,-0.37207 0.0655,-0.11943 0.18208,-0.26182 0.34975,-0.42719 0.46372,-0.45935 0.95495,-0.68902 1.47368,-0.68902 0.61305,0 1.10166,0.26872 1.46582,0.80615 0.42966,0.62931 0.64449,1.45154 0.64449,2.46669 0,1.01515 -0.21483,1.83738 -0.64449,2.46669 -0.36416,0.53743 -0.85277,0.80615 -1.46582,0.80615 -0.51873,0 -1.00996,-0.22967 -1.47368,-0.68902 -0.16767,-0.16537 -0.28426,-0.30547 -0.34975,-0.4203 -0.0655,-0.11943 -0.0982,-0.24575 -0.0982,-0.37896 0,-0.0505 0.003,-0.11025 0.008,-0.17915 z"/></svg>
<span>contacc</span><small>docs</small></div>
<nav><a href="/">Registry</a><a href="/docs">Overview</a><a href="/docs/api">Getting started</a><a href="/docs/roadmap">Roadmap</a></nav>

<div>
<h1>Overview</h1>
<blockquote><p>Most of what we share online is shaped by the question "who will see this?" — and that invisible pressure changes what we say, how we say it, and what we leave out entirely. contacc starts from a different premise: your data should belong to you, live on hardware you control, and be shared only when and how you decide.</p></blockquote>
</div>

<div>
<h2>The basic idea</h2>
<p>contacc is a personal server for your photos, videos, and writing — typically running on a Raspberry Pi or small VPS. You share things directly with specific people, who read them from your server. No intermediary, no algorithm, no copy of your content sitting on someone else's infrastructure.</p>
<p>It works in both directions. Your client connects to the servers of people you follow and pulls their feeds directly from their hardware. What you see is exactly what they chose to share with you — nothing more, nothing less.</p>
</div>

<div>
<h2>Nodes</h2>
<p>Every person runs a <strong>node</strong> — a server that stores their data and serves it to authorized contacts. A node is the authoritative source for everything its owner posts. Content is never copied to a central server; it lives on your hardware.</p>
<p>Each node has two sides that work together:</p>
<ul>
  <li><strong>me</strong> — the private side. Owns your identity, stores your posts and assets, enforces your access rules. Only you can write to it. Other people's nodes read from it.</li>
  <li><strong>them</strong> — the outward-facing side. Aggregates feeds from your contacts' nodes and presents them to your browser. Proxies your requests to <em>me</em>.</li>
</ul>
<p>A third container, <strong>web</strong>, serves the browser UI and routes requests to <em>them</em>. These three containers run together as a unit for each person on the host.</p>
<div class="diagram">  Browser
     │
     ▼
  <em>web</em>  ─────────── static files (HTML/CSS/JS)
     │
     ▼ (everything else)
  <em>them</em> ─────────── your contacts' nodes (reads their feeds)
     │
     ▼ (your own data)
  <em>me</em>   ─────────── your posts, assets, identity</div>
</div>

<div>
<h2>Identity</h2>
<p>Your identity is built from two layers:</p>
<ul>
  <li><strong>Identity key</strong> — an Ed25519 key pair generated once at setup. The private key is never stored on your node. It signs <em>delegation certificates</em> that say "this node key speaks for me." Think of it as your master key, kept offline.</li>
  <li><strong>Node key</strong> — the day-to-day signing key, stored encrypted on your node. Used for heartbeats, federation, and request signing. Can be rotated by presenting a new delegation signed by the identity key.</li>
</ul>
<p>Your permanent identifier is an <strong>owner ID</strong> — a UUID generated at setup that lives in the registry and identifies you as a person across all your nodes. Your <strong>handle</strong> is human-readable and changeable — just a name, not your identity. Two people can have the same handle; the owner ID is what distinguishes them. Each node you run has its own <strong>node ID</strong> identifying that specific deployment.</p>
<p>All your data is encrypted at rest. Your passphrase is never stored — it's used to derive the encryption keys when the node starts up.</p>
</div>

<div>
<h2>The registry</h2>
<p>The <strong>registry</strong> is a shared directory that maps users to node URLs. It's how contacts find each other: search by name, get a URL, add them. The registry also brokers Google sign-in so individual node operators don't need to set up OAuth credentials.</p>
<p>The registry doesn't store your content — it only knows your user ID, handle, full name, node URL, and identity public key. It's a phonebook, not a platform.</p>
<div class="diagram">  Registry
  ├── cass  →  https://strk.xyzw.us:8443
  ├── cindy →  https://strk.xyzw.us:8445
  └── lucas →  https://strk.xyzw.us:8446</div>
<p>Nodes send a signed heartbeat to the registry every hour to keep their entry current. If you move your node to a new address, the registry updates automatically on the next heartbeat.</p>
</div>

<div>
<h2>Automatic unlock (Tang)</h2>
<p>Your node encrypts everything with your passphrase. Normally you'd need to enter it every time the server restarts — inconvenient for a device that reboots occasionally.</p>
<p>contacc uses a protocol called <strong>Tang</strong> (named after the astronaut drink, because it's network-bound) to unlock automatically. Here's how it works:</p>
<ol>
  <li>The registry holds a secret key specific to your node.</li>
  <li>When your node starts, it sends a request to the registry to compute a shared secret.</li>
  <li>The registry computes the secret and delivers it <em>to your node's registered URL</em> — not back to whoever asked.</li>
  <li>Your node uses the secret to derive its passphrase and unlock.</li>
</ol>
<p>The security property: the registry only delivers the secret to the address it has on file for your node. If someone steals your disk and tries to unlock it elsewhere, the registry delivers to your real node — not theirs. The stolen disk stays locked. And even without the network secret, the data is encrypted with a key derived via Argon2id, making brute-force password attacks impractical.</p>
</div>

<div>
<h2>Recovery</h2>
<p>At setup, your identity private key is encrypted with your passphrase and stored in the registry. If you ever lose access to your node, you can recover it:</p>
<ol>
  <li>Visit the registry and sign in with Google.</li>
  <li>Enter your passphrase.</li>
  <li>The registry returns your encrypted identity key; your browser decrypts it locally.</li>
  <li>Use the key to set up a new node and prove it belongs to your identity.</li>
</ol>
<p>The registry never sees your identity private key in plaintext — it's encrypted before upload and decrypted in your browser.</p>
</div>

<div>
<h2>Sharing and visibility</h2>
<p>Every post has two independent controls:</p>
<ul>
  <li><strong>Visibility</strong> — who can see the post at all: just you, your contacts, any authenticated node, the public, or an arbitrary filter based on user-defined contact categories.</li>
  <li><strong>Comment access</strong> — who can comment on it, with the same options.</li>
</ul>
<p>Both must pass independently. A post visible to contacts can still restrict comments to just you.</p>
<p>Contacts are node endpoints — you add a specific node, not a person. If someone runs two nodes (personal and professional), you choose which to follow. What you see is what they explicitly shared with you, nothing else.</p>
</div>

<div>
<h2>How it all connects</h2>
<div class="diagram">  <em>Registry</em> ──────────────────────────────────────┐
  │  users → node URLs     identity escrow        │
  │  Tang keys             Google OAuth           │
  └───────────────────────────────────────────────┘
        ▲ heartbeat                ▲ Tang unlock
        │                         │
  <em>Your node</em> ◄──────────────── <em>Contact's node</em>
  (me + them + web)    federation    (me + them + web)
        │
        ▼
     Browser</div>
<p>Your node tells the registry where it lives. The registry helps your contacts find you, unlocks your node on restart, and holds your recovery key. Your node and your contacts' nodes talk directly to each other for content — the registry is not in that path.</p>
</div>

</div></body></html>"""

    @app.get("/docs", response_class=HTMLResponse)
    def docs_overview():
        return _OVERVIEW_HTML

    @app.get("/docs/api", response_class=HTMLResponse)
    def docs_readme():
        return _README_HTML

    @app.get("/docs/roadmap", response_class=HTMLResponse)
    def docs_roadmap():
        return _ROADMAP_HTML

    @app.get("/go")
    def go_me(request: Request, proxy_token: str = None):
        """Redirect to the signed-in user's primary node."""
        identity = _get_session(request)
        response = None
        if not identity and proxy_token:
            # Exchange proxy_token for a session and set cookie
            row = con.execute(
                "SELECT identity, created_at FROM proxy_tokens WHERE token = ?", (proxy_token,)
            ).fetchone()
            if row and time.time_ns() - row[1] <= 300 * NS:
                identity = row[0]
                con.execute("DELETE FROM proxy_tokens WHERE token = ?", (proxy_token,))
                con.commit()
                session_token = secrets.token_urlsafe(32)
                _reg_sessions[session_token] = (identity, time.time() + REG_SESSION_TTL)
                # We'll set the cookie on the response below
                response = "set_cookie"
        if not identity:
            return RedirectResponse("/auth/start?return_to=/go", status_code=302)
        rows = con.execute(
            "SELECT server_url, web_url, is_primary FROM handles "
            "WHERE google_identity = ? ORDER BY is_primary DESC, updated_at DESC",
            (identity,)
        ).fetchall()
        dest = (rows[0][1] or rows[0][0]) if rows else "/"
        r = RedirectResponse(dest, status_code=302)
        if response == "set_cookie":
            r.set_cookie("reg_session", session_token, httponly=True,
                         samesite="lax", max_age=REG_SESSION_TTL)
        return r

    @app.post("/nodes/{node_id}/set-primary", status_code=204)
    def set_primary(node_id: str, request: Request):
        """Mark a node as the primary for its owner. Requires registry session."""
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Sign in first")
        row = con.execute(
            "SELECT google_identity, owner_id FROM handles WHERE node_id = ?", (node_id,)
        ).fetchone()
        if not row or row[0] != identity:
            raise HTTPException(403, "Not your node")
        # Clear existing primary for this owner, set new one
        con.execute("UPDATE handles SET is_primary = 0 WHERE owner_id = ?", (row[1],))
        con.execute("UPDATE handles SET is_primary = 1 WHERE node_id = ?", (node_id,))
        con.commit()

    @app.get("/go/{username}")
    def go(username: str):
        username = username.lower()
        row = con.execute(
            "SELECT server_url, web_url FROM handles WHERE username = ? AND superseded_at IS NULL "
            "ORDER BY is_primary DESC, updated_at DESC LIMIT 1", (username,)
        ).fetchone()
        if not row:
            return RedirectResponse(f"/?handle={username}", status_code=302)
        return RedirectResponse(row[1] or row[0], status_code=302)

    @app.get("/health")
    def health():
        return {"status": "ok", "proxy": proxy_enabled}

    @app.get("/meta")
    def registry_meta():
        return {
            "api_version": 1,
            "extensions": ["tang", "identity_escrow"] + (["google_oauth_proxy"] if proxy_enabled else []),
            "name": "contacc registry",
        }

    # ── handle directory ──────────────────────────────────────────────────────

    @app.get("/search")
    def search(q: str, limit: int = 20):
        q = q.strip()
        if not q:
            return {"results": []}
        pattern = "%" + q.lower() + "%"
        rows = con.execute(
            """SELECT username, server_url, display_name, public_key, node_id, owner_id, identity_public_key
               FROM handles
               WHERE (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?)
                 AND superseded_at IS NULL
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
                entry["node_id"] = r[4]
                entry["user_id"] = r[5] or r[4]   # legacy alias = owner_id
            if r[5]:
                entry["owner_id"] = r[5]
            if r[6]:
                entry["identity_public_key"] = r[6]
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
            "SELECT server_url, web_url, public_key, ttl, updated_at, display_name, "
            "node_id, owner_id, identity_public_key "
            "FROM handles WHERE username = ? AND superseded_at IS NULL "
            "ORDER BY is_primary DESC, updated_at DESC LIMIT 1", (username,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Username not found")
        server_url, web_url, public_key, ttl, updated_at, display_name, node_id, owner_id, identity_public_key = row
        result = {
            "username": username,
            "server_url": server_url,
            "web_url": web_url,
            "public_key": public_key,
            "ttl": ttl,
            "updated_at": updated_at,
            "display_name": display_name,
            "photo_url": server_url.rstrip("/") + "/profile/photo",
        }
        if node_id:
            result["node_id"] = node_id
            result["user_id"] = owner_id or node_id  # legacy alias
        if owner_id:
            result["owner_id"] = owner_id
        if identity_public_key:
            result["identity_public_key"] = identity_public_key
        return result

    @app.get("/id/{owner_id}")
    def go_by_id(owner_id: str):
        # Try exact node_id first, then primary node for owner
        row = con.execute(
            "SELECT server_url, web_url FROM handles WHERE node_id = ? AND superseded_at IS NULL",
            (owner_id,)
        ).fetchone()
        if not row:
            row = con.execute(
                "SELECT server_url, web_url FROM handles WHERE owner_id = ? AND superseded_at IS NULL "
                "ORDER BY is_primary DESC, updated_at DESC LIMIT 1", (owner_id,)
            ).fetchone()
        if not row:
            raise HTTPException(404, "ID not found")
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
        google_identity: str | None = None

    def _claim_url(server_url: str, claiming_node_id: str, claiming_pub_key: str) -> None:
        """Verify the claiming node is live at server_url and evict any stale entry.

        Always fetches /node at the URL:
        - Key matches claiming node → node is live there; evict any conflicting entry.
        - Different key live at URL → reject 409 (URL genuinely in use by someone else).
        - Unreachable → allow only if no active conflict exists (old node presumed dead).
        """
        conflict = con.execute(
            "SELECT node_id FROM handles WHERE server_url = ? AND node_id != ? AND superseded_at IS NULL",
            (server_url, claiming_node_id)
        ).fetchone()
        old_node_id = conflict[0] if conflict else None
        try:
            r = httpx.get(server_url.rstrip("/") + "/node", timeout=5)
            if not r.is_success:
                raise HTTPException(409, "Node is unreachable at the claimed URL — must be live to register")
            live_key = r.json().get("public_key", "")
            if live_key == claiming_pub_key:
                # Claiming node is live at this URL — evict any stale entry
                if old_node_id:
                    con.execute("UPDATE handles SET superseded_at = ? WHERE node_id = ?",
                                (time.time_ns(), old_node_id))
                    con.commit()
            elif live_key:
                raise HTTPException(409, "URL is currently in use by a different active node")
            # live_key empty: can't verify but no conflict, allow
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(409, "Node is unreachable at the claimed URL — must be live to register")

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
        reg_identity_public_key = reg_delegation_json = None
        if body.delegation_cert:
            cert = body.delegation_cert
            if not _verify_delegation_cert(cert, body.public_key):
                raise HTTPException(400, "Invalid or expired delegation cert")
            reg_owner_id = cert.get("owner_id") or cert.get("user_id")
            reg_node_id = cert.get("node_id")
            if not reg_node_id:
                raise HTTPException(400, "Delegation cert must include a node_id distinct from owner_id")
            if reg_node_id == reg_owner_id:
                raise HTTPException(400, "node_id must be distinct from owner_id")
            reg_identity_public_key = cert.get("identity_public_key")
            reg_delegation_json = json.dumps(cert)
        else:
            raise HTTPException(400, "A delegation cert is required to register")
        if con.execute("SELECT 1 FROM handles WHERE node_id = ?", (reg_node_id,)).fetchone():
            raise HTTPException(status_code=409, detail="Already registered — use update instead")
        _claim_url(body.server_url, reg_node_id, body.public_key)
        now = time.time_ns()
        con.execute(
            "INSERT INTO handles "
            "(node_id, owner_id, username, server_url, public_key, ttl, registered_at, updated_at, "
            "display_name, web_url, identity_public_key, delegation_sig, google_identity) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (reg_node_id, reg_owner_id, username, body.server_url, body.public_key, ttl, now, now,
             body.display_name, body.web_url, reg_identity_public_key, reg_delegation_json, body.google_identity),
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
        google_identity: str | None = None

    @app.put("/update/{username}")
    def update(username: str, body: UpdateBody):
        username = username.lower()
        _check_timestamp(body.timestamp)
        # Locate the node: cert node_id > cert owner_id > username fallback
        cert_node_id = body.delegation_cert.get("node_id") if body.delegation_cert else None
        cert_owner_id = (body.delegation_cert.get("owner_id") or body.delegation_cert.get("user_id")) if body.delegation_cert else None
        row = None
        if cert_node_id:
            row = con.execute(
                "SELECT public_key, node_id, superseded_at FROM handles WHERE node_id = ?", (cert_node_id,)
            ).fetchone()
        if not row and cert_owner_id:
            row = con.execute(
                "SELECT public_key, node_id, superseded_at FROM handles WHERE owner_id = ? "
                "ORDER BY is_primary DESC, updated_at DESC LIMIT 1", (cert_owner_id,)
            ).fetchone()
        if not row:
            row = con.execute(
                "SELECT public_key, node_id, superseded_at FROM handles WHERE username = ? "
                "ORDER BY updated_at DESC LIMIT 1", (username,)
            ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Handle not found")
        pub_key, update_node_id, superseded_at = row
        if superseded_at:
            raise HTTPException(status_code=410, detail="This node has been superseded and cannot update its registration")
        ttl = _clamp_ttl(body.ttl)
        msg = f"contacc:update:{username}:{body.server_url}:{body.timestamp}"
        if not _verify_sig(pub_key, msg, body.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        upd_identity_public_key = upd_delegation_json = None
        if body.delegation_cert:
            cert = body.delegation_cert
            if not _verify_delegation_cert(cert, pub_key):
                raise HTTPException(400, "Invalid or expired delegation cert")
            upd_identity_public_key = cert.get("identity_public_key")
            upd_delegation_json = json.dumps(cert)
        _claim_url(body.server_url, update_node_id, pub_key)
        con.execute(
            "UPDATE handles SET username=?, server_url=?, ttl=?, updated_at=?, display_name=?, web_url=?, "
            "identity_public_key=?, delegation_sig=?, google_identity=COALESCE(?, google_identity) "
            "WHERE node_id=?",
            (username, body.server_url, ttl, time.time_ns(), body.display_name, body.web_url,
             upd_identity_public_key, upd_delegation_json, body.google_identity, update_node_id),
        )
        con.commit()
        return {"username": username, "ttl": ttl}

    # ── identity escrow ───────────────────────────────────────────────────────

    class EscrowBody(BaseModel):
        encrypted_identity_key: str  # base64: AES-GCM ciphertext
        argon2_salt: str             # hex, used with owner passphrase
        argon2_time_cost: int = 3
        argon2_memory_cost: int = 65536
        argon2_parallelism: int = 4
        signature: str               # identity_key signs f"contacc:escrow:{user_id}:{timestamp}"
        timestamp: int

    @app.put("/identity-key/{owner_id}", status_code=204)
    def store_escrow(owner_id: str, body: EscrowBody):
        row = con.execute(
            "SELECT identity_public_key FROM handles WHERE owner_id = ? LIMIT 1", (owner_id,)
        ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "Owner ID not registered or has no identity key")
        if abs(time.time() - body.timestamp) > TIMESTAMP_TOLERANCE:
            raise HTTPException(401, "Timestamp too skewed")
        try:
            id_pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(row[0] + "=="))
            msg = f"contacc:escrow:{owner_id}:{body.timestamp}"
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
        # Store escrow on the primary node for this owner (or any node if no primary)
        con.execute(
            "UPDATE handles SET encrypted_identity_key = ? WHERE owner_id = ?",
            (escrow_data, owner_id),
        )
        con.commit()

    @app.get("/identity-key/{owner_id}")
    def get_escrow(owner_id: str):
        """Return the encrypted escrow blob for an owner_id. Decryption requires the owner passphrase."""
        row = con.execute(
            "SELECT encrypted_identity_key FROM handles WHERE owner_id = ? "
            "AND encrypted_identity_key IS NOT NULL ORDER BY is_primary DESC, updated_at DESC LIMIT 1",
            (owner_id,)
        ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "No escrow stored for this owner ID")
        return json.loads(row[0])

    @app.post("/identity-key/{owner_id}/recover")
    def recover_escrow(owner_id: str):
        row = con.execute(
            "SELECT encrypted_identity_key FROM handles WHERE owner_id = ? "
            "AND encrypted_identity_key IS NOT NULL ORDER BY is_primary DESC, updated_at DESC LIMIT 1",
            (owner_id,)
        ).fetchone()
        if not row or not row[0]:
            raise HTTPException(404, "No escrow stored for this owner ID")
        return json.loads(row[0])

    def _escrow_for_handle(handle: str):
        """Return (owner_id, escrow_dict) or raise HTTPException."""
        handle = handle.lower()
        row = con.execute(
            "SELECT owner_id, encrypted_identity_key FROM handles WHERE username = ? "
            "AND encrypted_identity_key IS NOT NULL ORDER BY is_primary DESC, updated_at DESC LIMIT 1",
            (handle,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Handle not found or no escrow stored")
        if not row[0]:
            raise HTTPException(404, "No permanent identity registered for this handle")
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
            raise ValueError("Wrong owner passphrase")

    class RecoverBody(BaseModel):
        owner_passphrase: str

    def _escrow_for_session(request) -> tuple[str, dict]:
        """Find the escrow for the currently signed-in user; return (owner_id, escrow_dict)."""
        identity = _get_session(request)
        if not identity:
            raise HTTPException(401, "Sign in first")
        row = con.execute(
            "SELECT owner_id, encrypted_identity_key FROM handles WHERE google_identity = ? "
            "AND encrypted_identity_key IS NOT NULL ORDER BY is_primary DESC, updated_at DESC LIMIT 1",
            (identity,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "No registered identity or escrow found for your account")
        return row[0], json.loads(row[1])

    @app.post("/identity/recover")
    def recover_identity(body: RecoverBody, request: Request):
        """Decrypt and return the identity private key for the signed-in user.
        Requires registry session (Google auth) + owner passphrase."""
        owner_id, escrow = _escrow_for_session(request)
        try:
            id_priv = _decrypt_escrow(escrow, body.owner_passphrase)
        except ValueError as e:
            raise HTTPException(403, str(e))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EPK
        from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
        _key = _EPK.from_private_bytes(id_priv)
        id_pub_hex = _key.public_key().public_bytes(_E.Raw, _PF.Raw).hex()
        return {"owner_id": owner_id, "user_id": owner_id,
                "identity_public_key": id_pub_hex, "identity_private_key": id_priv.hex()}

    class ChangePassphraseBody(BaseModel):
        old_owner_passphrase: str
        new_owner_passphrase: str

    @app.post("/identity/change-passphrase", status_code=204)
    def change_identity_passphrase(body: ChangePassphraseBody, request: Request):
        """Re-encrypt the identity key escrow under a new passphrase.
        Requires registry session (Google auth) + owner passphrase."""
        owner_id, escrow = _escrow_for_session(request)
        try:
            id_priv = _decrypt_escrow(escrow, body.old_owner_passphrase)
        except ValueError as e:
            raise HTTPException(403, str(e))
        # Re-encrypt under new passphrase
        new_salt = os.urandom(16)
        from argon2.low_level import hash_secret_raw, Type
        tc = escrow.get("argon2_time_cost", 3)
        mc = escrow.get("argon2_memory_cost", 65536)
        pa = escrow.get("argon2_parallelism", 4)
        new_key = hash_secret_raw(body.new_owner_passphrase.encode(), new_salt,
                                   time_cost=tc, memory_cost=mc, parallelism=pa,
                                   hash_len=32, type=Type.ID)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        new_ct = AESGCM(new_key).encrypt(nonce, id_priv, None)
        new_escrow = {**escrow,
                      "encrypted_identity_key": base64.b64encode(nonce + new_ct).decode(),
                      "argon2_salt": new_salt.hex()}
        con.execute("UPDATE handles SET encrypted_identity_key = ? WHERE owner_id = ?",
                    (json.dumps(new_escrow), owner_id))
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

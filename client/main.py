"""contacc client process — API-first personal aggregator.

Exposes /api/... routes that any frontend (web UI, mobile app) can consume.
The client manages authentication to server nodes internally; frontends
never handle server credentials directly.

Auth flow:
  1. POST /client/session {token?} → {token}
       Verifies that the stored (or provided) own-server token belongs to the
       owner identity. Issues a short-lived client session token.
  2. Include session token as Authorization: Bearer <token> on all /api/ calls
       (or ?client_token= for browser-initiated requests like <img src>)

Server OAuth flow:
  1. GET /api/auth/login-url  → {auth_url}  (Google OAuth via own_server)
  2. Browser completes OAuth; server redirects to /auth/callback#token=<token>
  3. callback.html POSTs server token to /client/session, stores client token
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.config import ClientConfig, NodeKey, load_tokens, save_tokens
from client.db import (open_client_db, open_client_db_memory, get_all_tags, get_tag,
                       set_tag as db_set_tag, get_contact_poll, set_contact_poll,
                       node_list_id, store_node_list, get_node_list, get_all_node_lists)
from client.registry import registry

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contacc")


def _load_private_key(node_key: NodeKey, passphrase: str):
    """Decrypt and return the Ed25519 private key, or None on failure."""
    try:
        from server.crypto import derive_master_key, decrypt_bytes
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        salt = bytes.fromhex(node_key.argon2_salt)
        master_key = derive_master_key(
            passphrase, salt,
            node_key.argon2_time_cost,
            node_key.argon2_memory_cost,
            node_key.argon2_parallelism,
        )
        privkey_bytes = decrypt_bytes(base64.b64decode(node_key.encrypted_private_key), master_key)
        return Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    except Exception as e:
        log.warning("Could not load node private key: %s", e)
        return None




def create_app(config_path: str | Path) -> FastAPI:
    config_path = Path(config_path).resolve()
    raw_config_data = json.loads(config_path.read_text()) if config_path.exists() else {}
    config = ClientConfig.load(config_path)
    tokens: dict[str, str] = load_tokens(config_path)

    # Load private key now so we can derive the client DB encryption key.
    _private_key = None

    # Derive client DB key from private key (same HKDF pattern as the post-cache key).
    # Falls back to an in-memory DB during the pre-setup phase when no node key exists yet.
    if _private_key:
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        _priv_bytes = _private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        _client_db_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"contacc-client-db").derive(_priv_bytes)
        _client_db = open_client_db(Path("/data"), _client_db_key)
        log.info("Node private key loaded.")
    else:
        _client_db = open_client_db_memory()

    # One-time migration: move any tags from config JSON into client DB (keyed by node_id)
    _url_to_node_id = {c.url: c.node_id for c in config.contacts if c.url and c.node_id}
    for raw_contact in raw_config_data.get("contacts", []):
        tag = raw_contact.get("tag")
        url = raw_contact.get("url")
        node_id = _url_to_node_id.get(url or "")
        if tag and node_id and not get_tag(_client_db, node_id):
            db_set_tag(_client_db, node_id, tag)

    app = FastAPI(title="contacc client")
    app.state.config = config
    app.state.config_path = config_path
    app.state.private_key = _private_key

    @app.get("/registry-cache/{node_id}")
    async def peer_registry_cache(node_id: str):
        """Expose locally-cached signed registry records to peer nodes."""
        entry = registry._cache.get(node_id)
        if not entry:
            raise HTTPException(status_code=404, detail="Not in cache")
        record, cached_at = entry
        if time.time() - cached_at > registry.MAX_AGE:
            raise HTTPException(status_code=404, detail="Cache entry too stale")
        return record

    @app.on_event("startup")
    async def _warm_caches():
        if not config.own_node_id:
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(_server + "/node", timeout=5)
                if r.is_success:
                    nid = r.json().get("node_id")
                    if nid:
                        config.own_node_id = nid
                        config.save(config_path)
                        log.info("Migrated own_node_id=%s into client config", nid)
            except Exception:
                pass
        asyncio.create_task(_fetch_cache_key())
        asyncio.create_task(_refresh_contact_photos())
        asyncio.create_task(_startup_consistency_check())
        asyncio.create_task(_dm_sse_subscriber())
        asyncio.create_task(_background_poller())
        # Warm the post cache immediately so the "all" feed has data on first load.
        own_poll_id = config.own_node_id or hashlib.sha256(config.own_server.encode()).hexdigest()[:16]
        asyncio.create_task(_background_fetch_one(own_poll_id))
        for c in config.contacts:
            if c.node_id:
                asyncio.create_task(_background_fetch_one(c.node_id))

    async def _startup_consistency_check():
        """Run all startup consistency checks. Add new checks here as needed."""
        import asyncio as _asyncio
        await _asyncio.sleep(5)  # let the server finish starting up
        dirty = False

        # ── migrate: copy server_url-keyed tags from legacy users table to contact_tags ──
        for c in config.contacts:
            if c.node_id:
                old_row = _client_db.execute("SELECT tag FROM users WHERE server_url = ?", (c.url,)).fetchone()
                if old_row and old_row["tag"]:
                    _client_db.execute(
                        "INSERT OR IGNORE INTO contact_tags (node_id, tag, updated_at) VALUES (?, ?, ?)",
                        (c.node_id, old_row["tag"], time.time_ns())
                    )
        _client_db.commit()

        # ── check: contacts missing node_id ──────────────────────────────────
        contacts_need_node_id = [c for c in config.contacts if not c.node_id]
        if contacts_need_node_id:
            seen_node_ids = {c.node_id for c in config.contacts if c.node_id}
            async with httpx.AsyncClient() as hc:
                for c in contacts_need_node_id:
                    try:
                        r = await hc.get(c.url.rstrip("/") + "/node", timeout=4)
                        if r.is_success:
                            nd = r.json()
                            nid = nd.get("node_id") or nd.get("user_id")
                            if nid and nid not in seen_node_ids:
                                c.node_id = nid
                                seen_node_ids.add(nid)
                                if nd.get("public_key") and not c.public_key:
                                    c.public_key = nd["public_key"]
                                dirty = True
                                try:
                                    tok = _token(config.own_server)
                                    if tok:
                                        async with httpx.AsyncClient() as _hc2:
                                            await _hc2.post(
                                                _server + "/users",
                                                json={"server_url": c.url, "name": c.name,
                                                      "handle": c.handle, "node_id": nid,
                                                      "public_key": c.public_key},
                                                headers=_headers(config.own_server),
                                                timeout=5,
                                            )
                                except Exception:
                                    pass
                    except Exception:
                        pass

        # ── check: duplicate contacts by node_id ─────────────────────────────
        seen: dict[str, object] = {}
        to_remove = []
        for c in config.contacts:
            if c.node_id:
                if c.node_id in seen:
                    to_remove.append(c)
                else:
                    seen[c.node_id] = c
        if to_remove:
            for c in to_remove:
                config.contacts.remove(c)
            dirty = True

        if dirty:
            config.save(config_path)
        asyncio.create_task(_backfill_contact_pubkeys())

    async def _dm_sse_subscriber():
        """Subscribe to server's /dm/events SSE and forward updates to browser SSE."""
        backoff = 1.0
        while True:
            connected = False
            try:
                timeout = httpx.Timeout(connect=5.0, read=None, write=5.0, pool=5.0)
                async with httpx.AsyncClient() as hc:
                    async with hc.stream("GET", _server + "/dm/events",
                                         headers=_internal_headers(),
                                         timeout=timeout) as r:
                        if r.status_code == 200:
                            connected = True
                            backoff = 1.0
                            buf = ""
                            async for chunk in r.aiter_text():
                                buf += chunk
                                while "\n\n" in buf:
                                    block, buf = buf.split("\n\n", 1)
                                    for line in block.splitlines():
                                        if line.startswith("data:"):
                                            try:
                                                event = json.loads(line[5:].strip())
                                                _push_to_sse(event)
                                            except Exception:
                                                pass
            except Exception:
                pass
            if connected:
                await asyncio.sleep(0.5)
            else:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)

    async def _backfill_contact_pubkeys():
        """Fetch public key from /node for any contact that's missing one, then sync to server."""
        changed = False
        for contact in config.contacts:
            if contact.public_key:
                continue
            if not contact.node_id:
                continue
            url = await _contact_server_url(contact.node_id)
            if not url:
                continue
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(url.rstrip("/") + "/node", timeout=5)
                if r.is_success:
                    pub_key = r.json().get("public_key")
                    if pub_key:
                        contact.public_key = pub_key
                        changed = True
                        log.info("Backfilled public key for contact %s", contact.node_id)
                        t = _token(config.own_server)
                        if t:
                            async with httpx.AsyncClient() as hc2:
                                await hc2.post(
                                    _server + "/users",
                                    json={"server_url": url, "name": contact.name,
                                          "handle": contact.handle, "public_key": pub_key,
                                          "node_id": contact.node_id},
                                    headers=_headers(config.own_server),
                                    timeout=5,
                                )
            except Exception:
                pass
        if changed:
            config.save(config_path)

    async def _refresh_contact_photos():
        cache_dir = Path("/data/photo_cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        for contact in config.contacts:
            if not contact.node_id:
                continue
            url = await _contact_server_url(contact.node_id)
            if not url:
                continue
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(url + "/profile/photo", timeout=5)
                if r.is_success:
                    (cache_dir / contact.node_id).write_bytes(r.content)
                    log.info("Cached photo for %s", contact.node_id)
            except Exception:
                pass

    # Internal server URL — use CONTACC_SERVER_URL if set (avoids external loop
    # when Caddy routes everything to the client).  Falls back to own_server so
    # local dev without Docker still works.
    _server = os.environ.get("CONTACC_SERVER_URL", "").rstrip("/") or config.own_server

    # ── client-level session auth ─────────────────────────────────────────

    _sessions: dict[str, int] = {}  # token -> expiry (nanoseconds)
    SESSION_TTL = 86400 * 30

    class SessionBody(BaseModel):
        token: str = ""  # server token to verify+store; omit to reuse stored token

    @app.post("/client/session")
    async def client_session(body: Optional[SessionBody] = None):
        server_token = (body.token if body else "") or tokens.get(config.own_server)
        if not server_token:
            raise HTTPException(status_code=401, detail="No server token — sign in first")
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/auth/me",
                             headers={"Authorization": f"Bearer {server_token}", **_internal_headers()})
        if not r.is_success:
            raise HTTPException(status_code=401, detail="Server token invalid or expired")
        if r.json().get("role") != "owner":
            raise HTTPException(status_code=403, detail="Owner access required")
        if body and body.token:
            tokens[config.own_server] = body.token
            save_tokens(config_path, tokens)
        session_token = secrets.token_urlsafe(32)
        _sessions[session_token] = time.time_ns() + SESSION_TTL * 1_000_000_000
        return {"token": session_token}

    @app.get("/client/login-url")
    async def client_login_url(request: Request, return_to: str = ""):
        if not return_to:
            return_to = config.own_server.rstrip("/") + "/auth/callback"
        server_login = (_server + "/auth/login?provider=google&return_to="
                        + return_to)
        async with httpx.AsyncClient() as hc:
            r = await hc.get(server_login, headers=_internal_headers())
        if not r.is_success:
            raise HTTPException(status_code=502, detail="Server login unavailable")
        return {"auth_url": r.json()["auth_url"]}

    def _require_client_auth(request: Request):
        auth = request.headers.get("Authorization", "")
        # fall back to query param so <img src> and <video src> requests work
        t = auth[7:] if auth.startswith("Bearer ") else request.query_params.get("client_token", "")
        if not t:
            raise HTTPException(status_code=401, detail="Client authentication required")
        expiry = _sessions.get(t)
        if not expiry or time.time_ns() > expiry:
            raise HTTPException(status_code=401, detail="Invalid or expired client session")

    # api router — all /api/ routes require client auth
    api = APIRouter(prefix="/api", dependencies=[Depends(_require_client_auth)])

    def _token(server_url: str) -> Optional[str]:
        return tokens.get(server_url)

    def _internal_headers() -> dict:
        return {"x-contacc-internal": config.internal_token} if config.internal_token else {}

    def _call_url(server_url: str) -> str:
        """Map own_server to the internal Docker URL for actual httpx calls."""
        return _server if server_url == config.own_server else server_url

    def _headers(server_url: str) -> dict:
        if server_url == config.own_server:
            h = _internal_headers()
        else:
            h = {"X-Origin-Server": config.own_server}
        t = _token(server_url)
        if t:
            h["Authorization"] = f"Bearer {t}"
        return h

    async def _sign_federated(method: str, path: str, body: bytes) -> dict:
        """Return X-Timestamp and X-Signature headers by asking the server to sign."""
        import hashlib, time as _time
        ts = str(int(_time.time()))
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{method}\n{path}\n{ts}\n{body_hash}"
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.post(
                    _server + "/auth/sign-federated",
                    json={"canonical": canonical},
                    headers=_internal_headers(),
                    timeout=5,
                )
            if r.is_success:
                data = r.json()
                headers = {"X-Timestamp": ts, "X-Signature": data["signature"]}
                if data.get("public_key"):
                    headers["X-Public-Key"] = data["public_key"]
                return headers
        except Exception:
            pass
        return {}

    def _registry_url() -> str:
        # Prefer explicit registry/proxy URL from environment, then fall back
        # to deriving from own_server hostname (same host, port 8421).
        url = (os.environ.get("CONTACC_REGISTRY_URL")
               or os.environ.get("CONTACC_IDENTITY_PROXY_URL"))
        if url:
            return url.rstrip("/")
        from urllib.parse import urlparse
        parsed = urlparse(config.own_server)
        return f"https://{parsed.hostname}:8421"

    registry.init(
        get_registry_url=_registry_url,
        get_contacts=lambda: config.contacts,
        get_db=lambda: getattr(app.state, "db", None),
    )

    async def _contact_server_url(node_id: str) -> str | None:
        """Return the current server URL for a node via the registry module."""
        try:
            record = await registry.lookup(node_id)
            return record.get("server_url")
        except Exception:
            return None

    def _server_name(url: str) -> str:
        return "me" if url == config.own_server else url

    def _contact_name(node_id: str) -> str:
        c = next((c for c in config.contacts if c.node_id == node_id), None)
        return c.name if c else node_id

    def _all_contact_node_ids() -> list[str]:
        return [c.node_id for c in config.contacts if c.node_id]

    # ── background poll state ─────────────────────────────────────────────
    _fetch_in_flight: set[str] = set()   # node_ids currently being fetched
    _contact_status: dict[str, str] = {} # node_id -> "online" | "offline"

    def _poll_interval_s(last_update_ns: int) -> float:
        """Adaptive interval: half the age of the newest seen post, clamped 5min–1day.
        Returns 0 when the node has never been checked so it fires immediately."""
        if last_update_ns == 0:
            return 0.0
        age_s = (time.time_ns() - last_update_ns) / 1e9
        return max(300.0, min(86400.0, age_s / 2.0))

    async def _background_fetch_one(node_id: str) -> None:
        if not _cache_key_event.is_set():
            try:
                await asyncio.wait_for(_cache_key_event.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
        if node_id in _fetch_in_flight:
            return
        _fetch_in_flight.add(node_id)
        is_own = (node_id == config.own_node_id)
        try:
            set_contact_poll(_client_db, node_id, last_check=time.time_ns())
            if is_own:
                url = config.own_server
            else:
                url = await _contact_server_url(node_id)
                if not url:
                    _contact_status[node_id] = "offline"
                    return
            fetch_target = _call_url(url)
            hdrs = {**_headers(url), **await _sign_federated("GET", "/posts", b"")}
            async with httpx.AsyncClient() as hc:
                r = await hc.get(fetch_target + "/posts", headers=hdrs, timeout=10.0)
            if r.is_success:
                _contact_status[node_id] = "online"
                posts = r.json().get("posts", [])
                name = _contact_name(node_id) if not is_own else "me"
                for post in posts:
                    post["_server_url"] = url
                    post["_server_name"] = name
                    post["_server_node_id"] = node_id
                _cache_posts(node_id, posts)
                if posts:
                    newest = max(p.get("created_at", 0) for p in posts)
                    set_contact_poll(_client_db, node_id, last_update=newest)
            else:
                _contact_status[node_id] = "offline"
        except Exception:
            _contact_status[node_id] = "offline"
        finally:
            _fetch_in_flight.discard(node_id)

    async def _background_poller() -> None:
        await asyncio.sleep(5)
        while True:
            now_ns = time.time_ns()
            # Use a URL-derived fallback key if own_node_id is not yet known (e.g.,
            # startup /node fetch failed because the server started after the client).
            own_poll_id = config.own_node_id or hashlib.sha256(config.own_server.encode()).hexdigest()[:16]
            last_update, last_check = get_contact_poll(_client_db, own_poll_id)
            elapsed_s = (now_ns - last_check) / 1e9
            if elapsed_s >= _poll_interval_s(last_update):
                asyncio.create_task(_background_fetch_one(own_poll_id))
            for c in config.contacts:
                if not c.node_id:
                    continue
                last_update, last_check = get_contact_poll(_client_db, c.node_id)
                elapsed_s = (now_ns - last_check) / 1e9
                if elapsed_s >= _poll_interval_s(last_update):
                    asyncio.create_task(_background_fetch_one(c.node_id))
            await asyncio.sleep(60)

    # ── local post/asset cache ────────────────────────────────────────────
    _POST_CACHE_DIR = Path("/data/post_cache")
    _ASSET_CACHE_DIR = Path("/data/asset_cache")
    _CACHE_TTL = 3 * 86400  # 3 days
    _CACHE_MAX_ASSET_BYTES = 50 * 1024 * 1024  # 50 MB

    _cache_key_bytes: list[bytes | None] = [None]
    _cache_key_event = asyncio.Event()

    def _cache_aes_key() -> bytes | None:
        return _cache_key_bytes[0]

    async def _fetch_cache_key() -> None:
        """Fetch the AES cache key from the co-located me-node. Retries until available."""
        import asyncio as _aio
        while True:
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(_server + "/internal/client-cache-key",
                                     headers=_internal_headers(), timeout=5)
                if r.is_success:
                    raw = base64.b64decode(r.json()["key"])
                    if len(raw) == 32:
                        _cache_key_bytes[0] = raw
                        _cache_key_event.set()
                        log.info("Client cache key loaded from me-node.")
                        return
            except Exception:
                pass
            await _aio.sleep(5)

    def _cache_write(path: Path, data: bytes) -> None:
        key = _cache_aes_key()
        if key is None:
            return
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = os.urandom(12)
            ct = AESGCM(key).encrypt(nonce, data, None)
            expiry = struct.pack(">Q", int(time.time()) + _CACHE_TTL)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expiry + nonce + ct)
        except Exception:
            pass

    def _cache_read(path: Path, allow_expired: bool = False) -> bytes | None:
        if not path.exists():
            return None
        try:
            raw = path.read_bytes()
            if len(raw) < 20:
                return None
            expiry = struct.unpack(">Q", raw[:8])[0]
            if not allow_expired and time.time() > expiry:
                return None
            key = _cache_aes_key()
            if key is None:
                return None
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(key).decrypt(raw[8:20], raw[20:], None)
        except Exception:
            return None

    def _post_cache_path(contact_key: str, post_id: str) -> Path:
        bucket = hashlib.sha256(contact_key.encode()).hexdigest()[:16]
        return _POST_CACHE_DIR / bucket / f"{post_id}.enc"

    def _asset_cache_path(asset_id: str, thumb: bool) -> Path:
        suffix = ".thumb.enc" if thumb else ".enc"
        return _ASSET_CACHE_DIR / asset_id[:2] / f"{asset_id}{suffix}"

    def _cache_posts(contact_key: str, posts: list[dict]) -> None:
        # Remove cache files not in the new fetch so deleted/filtered posts don't linger
        bucket = hashlib.sha256(contact_key.encode()).hexdigest()[:16]
        d = _POST_CACHE_DIR / bucket
        if d.exists():
            new_ids = {post["id"] for post in posts}
            for f in d.glob("*.enc"):
                if f.stem not in new_ids:
                    f.unlink(missing_ok=True)
        for post in posts:
            _cache_write(_post_cache_path(contact_key, post["id"]), json.dumps(post).encode())

    def _read_cached_posts(contact_key: str, allow_expired: bool = False) -> list[dict]:
        bucket = hashlib.sha256(contact_key.encode()).hexdigest()[:16]
        d = _POST_CACHE_DIR / bucket
        if not d.exists():
            return []
        posts = []
        for f in d.glob("*.enc"):
            data = _cache_read(f, allow_expired=allow_expired)
            if data is None:
                if not allow_expired:
                    f.unlink(missing_ok=True)
                continue
            try:
                posts.append(json.loads(data))
            except Exception:
                pass
        return posts

    def _cache_asset(asset_id: str, content_type: str, data: bytes, thumb: bool) -> None:
        if len(data) > _CACHE_MAX_ASSET_BYTES:
            return
        content_hash = hashlib.sha256(data).digest()  # 32 bytes, stored for integrity check
        payload = struct.pack(">I", len(content_type)) + content_type.encode() + content_hash + data
        _cache_write(_asset_cache_path(asset_id, thumb), payload)

    def _read_cached_asset(asset_id: str, thumb: bool, expected_hash: str | None = None) -> tuple[str, bytes] | None:
        path = _asset_cache_path(asset_id, thumb)
        for allow_expired in (False, True):
            data = _cache_read(path, allow_expired=allow_expired)
            if data is None:
                continue
            if len(data) < 4:
                continue
            ct_len = struct.unpack(">I", data[:4])[0]
            if len(data) < 4 + ct_len + 32:
                continue
            content_type = data[4:4 + ct_len].decode()
            stored_hash = data[4 + ct_len:4 + ct_len + 32]
            asset_bytes = data[4 + ct_len + 32:]
            if hashlib.sha256(asset_bytes).digest() != stored_hash:
                path.unlink(missing_ok=True)
                return None
            if expected_hash and hashlib.sha256(asset_bytes).hexdigest() != expected_hash:
                return None  # asset superseded
            return content_type, asset_bytes
        return None

    @app.on_event("startup")
    async def _cleanup_post_cache():
        """Remove expired cache files at startup (expiry stored plaintext so no key needed)."""
        import asyncio
        async def _do_cleanup():
            for d in [_POST_CACHE_DIR, _ASSET_CACHE_DIR]:
                if not d.exists():
                    continue
                for f in d.rglob("*.enc"):
                    try:
                        raw = f.read_bytes()
                        if len(raw) >= 8 and time.time() > struct.unpack(">Q", raw[:8])[0]:
                            f.unlink(missing_ok=True)
                    except Exception:
                        pass
        asyncio.create_task(_do_cleanup())

    # ── config / status ───────────────────────────────────────────────────

    @api.get("/config")
    async def api_config():
        cache_dir = Path("/data/photo_cache")
        def _has_cached_photo(node_id: str) -> bool:
            return (cache_dir / node_id).exists()
        own_display_name = None
        own_handle = None
        own_identity = None
        try:
            async with httpx.AsyncClient() as hc:
                profile_task = hc.get(_server + "/profile", headers=_internal_headers(), timeout=2)
                me_task = hc.get(_server + "/auth/me", headers=_internal_headers(), timeout=2)
                rp, rm = await asyncio.gather(profile_task, me_task, return_exceptions=True)
                if not isinstance(rp, Exception) and rp.is_success:
                    p = rp.json()
                    own_display_name = p.get("display_name")
                    own_handle = p.get("handle")
                if not isinstance(rm, Exception) and rm.is_success:
                    own_identity = rm.json().get("identity")
        except Exception:
            pass
        tags = get_all_tags(_client_db)

        # Resolve current server URL for each contact from the registry.
        # registry.lookup has its own memory+DB cache so repeated calls are fast.
        async def _resolved_url(c) -> str:
            if c.node_id:
                url = await _contact_server_url(c.node_id)
                if url:
                    c.url = url  # populate transient field for this request's lifetime
                    return url
            return c.url or ""

        # Build contacts with fresh URLs
        contact_urls = {}
        for c in config.contacts:
            contact_urls[c.node_id] = await _resolved_url(c)

        servers_list = [{"name": "me", "url": config.own_server, "authenticated": bool(_token(config.own_server))}]
        for c in config.contacts:
            url = contact_urls.get(c.node_id, "")
            entry: dict = {"name": c.name, "url": url, "authenticated": bool(_token(url))}
            entry["tag"] = tags.get(c.node_id) if c.node_id else None
            entry["handle"] = c.handle
            entry["description"] = c.description
            entry["poll_weight"] = _contact_weight(c)
            for f in _CAT_FIELDS:
                entry[f] = getattr(c, f, 0.0)
            servers_list.append(entry)

        def _contact_dict(c):
            url = contact_urls.get(c.node_id, c.url or "")
            d = {"name": c.name, "url": url, "handle": c.handle, "public_key": c.public_key,
                 "node_id": c.node_id,
                 "tag": tags.get(c.node_id) if c.node_id else None,
                 "description": c.description,
                 "poll_weight": _contact_weight(c)}
            for f in _CAT_FIELDS:
                d[f] = getattr(c, f, 0.0)
            return d

        return {
            "own_server": config.own_server,
            "own_node_id": config.own_node_id,
            "own_display_name": own_display_name,
            "own_handle": own_handle,
            "own_identity": own_identity,
            "identity_proxy_url": os.environ.get("CONTACC_IDENTITY_PROXY_URL", ""),
            "provider_url": os.environ.get("CONTACC_PROVIDER_URL", "").rstrip("/") or None,
            "servers": servers_list,
            "contacts": [_contact_dict(c) for c in config.contacts],
            "cached_photos": [c.node_id for c in config.contacts if c.node_id and _has_cached_photo(c.node_id)],
        }

    # ── auth ──────────────────────────────────────────────────────────────

    class TokenBody(BaseModel):
        token: str
        server: str = ""

    @api.post("/auth/token")
    def api_store_token(body: TokenBody):
        server = body.server or config.own_server
        tokens[server] = body.token
        save_tokens(config_path, tokens)
        return {"ok": True, "server": server}

    @api.delete("/auth/token")
    def api_clear_token(server: str = ""):
        url = server or config.own_server
        tokens.pop(url, None)
        save_tokens(config_path, tokens)
        return {"ok": True}

    @api.get("/auth/me")
    async def api_me(server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_call_url(src) + "/auth/me", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── feed ──────────────────────────────────────────────────────────────

    @api.get("/feed")
    async def api_feed(
        server: str = "",
        cursor: str = "",
        q: str = "",
        tags: list[str] = Query(default=[]),
        limit: int = 20,
        node_ids: str = "",
    ):
        if server:
            # single-server fetch
            src = server
            is_own = src == config.own_server
            if is_own and not _token(src):
                raise HTTPException(status_code=401, detail="Not authenticated for this server")
            params: list[tuple[str, str]] = [("limit", str(limit))]
            if cursor: params.append(("cursor", cursor))
            if q: params.append(("q", q))
            for t in tags: params.append(("tags", t))
            fetch_headers = {**_headers(src), "X-Origin-Server": config.own_server,
                             **await _sign_federated("GET", "/posts", b"")}
            fetch_url = _server if is_own else src
            async with httpx.AsyncClient() as hc:
                r = await hc.get(fetch_url + "/posts", params=params, headers=fetch_headers, timeout=10.0)
            if not r.is_success:
                raise HTTPException(status_code=r.status_code)
            data = r.json()
            name = _server_name(src)
            for post in data.get("posts", []):
                post["_server_url"] = src
                post["_server_name"] = name
            return data

        # aggregate all servers — serve from cache, fire background refreshes for visible nodes
        own_poll_id = config.own_node_id or hashlib.sha256(config.own_server.encode()).hexdigest()[:16]
        node_ids = [own_poll_id] + _all_contact_node_ids()

        all_posts: list[dict] = []
        for nid in node_ids:
            cached = _read_cached_posts(nid) or _read_cached_posts(nid, allow_expired=True)
            all_posts.extend(cached)

        # If own server has no cached posts, do a synchronous live fetch so the
        # feed isn't empty on first load or after posting (before the bg poller runs).
        if not any(p.get("_server_url") == config.own_server for p in all_posts):
            try:
                own_key = hashlib.sha256(config.own_server.encode()).hexdigest()
                fetch_hdrs = {**_headers(config.own_server), **await _sign_federated("GET", "/posts", b"")}
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(_call_url(config.own_server) + "/posts",
                                     params=[("limit", str(limit))], headers=fetch_hdrs, timeout=5.0)
                if r.is_success:
                    own_posts = r.json().get("posts", [])
                    name = _server_name(config.own_server)
                    for p in own_posts:
                        p["_server_url"] = config.own_server
                        p["_server_name"] = name
                    _cache_posts(own_key, own_posts)
                    all_posts.extend(own_posts)
            except Exception:
                pass

        if cursor:
            try:
                cursor_ts = int(cursor)
                all_posts = [p for p in all_posts if p.get("created_at", 0) < cursor_ts]
            except (ValueError, TypeError):
                pass
        if q:
            q_lower = q.lower()
            all_posts = [p for p in all_posts if q_lower in (p.get("body") or "").lower()]
        if tags:
            tag_set = set(tags)
            all_posts = [p for p in all_posts if tag_set.intersection(p.get("tags") or [])]
        if node_ids:
            _nid_set = set(node_ids.split(","))
            _url_set = {c.url for c in config.contacts if c.node_id in _nid_set}
            _url_set.add(config.own_server)  # always include own posts
            all_posts = [p for p in all_posts if p.get("_server_url") in _url_set]

        seen_ids: set[str] = set()
        deduped: list[dict] = []
        for p in all_posts:
            pid = p.get("id", "")
            if pid not in seen_ids:
                seen_ids.add(pid)
                deduped.append(p)
        merged = sorted(deduped, key=lambda p: p.get("created_at", 0), reverse=True)[:limit]

        visible_node_ids = {p.get("_server_node_id") for p in merged if p.get("_server_node_id")}
        # Always refresh all nodes when nothing is visible (empty cache); otherwise
        # only refresh nodes whose posts are currently shown.
        for nid in (visible_node_ids or node_ids):
            if nid:
                asyncio.create_task(_background_fetch_one(nid))

        server_status = {nid: _contact_status.get(nid, "unknown") for nid in node_ids}
        next_cursor = str(merged[-1]["created_at"]) if len(merged) == limit else None
        return {"posts": merged, "server_status": server_status, "next_cursor": next_cursor}

    # ── posts ─────────────────────────────────────────────────────────────

    async def _send_reply_notification(parent_post_id: str, parent_node_id: str, reply_post_id: str, parent_server_url: str = ""):
        if not parent_node_id and not parent_server_url:
            return
        if parent_node_id == config.own_node_id and not parent_server_url:
            return  # local reply, no notification needed
        try:
            parent_server = parent_server_url
            if not parent_server and parent_node_id:
                record = await registry.lookup(parent_node_id)
                parent_server = record.get("server_url") or record.get("web_url")
            if not parent_server:
                return
            body_bytes = json.dumps({
                "reply_post_id": reply_post_id,
                "reply_node_id": config.own_node_id or "",
            }).encode()
            path = f"/posts/{parent_post_id}/notify-reply"
            sign_hdrs = await _sign_federated("POST", path, body_bytes)
            async with httpx.AsyncClient() as hc:
                await hc.post(
                    parent_server.rstrip("/") + path,
                    content=body_bytes,
                    headers={"Content-Type": "application/json",
                             "X-Origin-Server": config.own_server,
                             **sign_hdrs},
                    timeout=10.0,
                )
        except Exception:
            pass

    @api.post("/posts")
    async def api_create_post(request: Request, notify_parent: bool = False):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        form = await request.form()
        fields: dict[str, str] = {}
        file_tuples: list = []
        for key, value in form.multi_items():
            if hasattr(value, "read"):
                content = await value.read()
                file_tuples.append((key, (value.filename or key, content, value.content_type or "application/octet-stream")))
            else:
                fields[key] = value
        # inject visibility_list_id for contacts-visibility top-level posts
        if fields.get("visibility", "contacts") == "contacts" and not fields.get("parent_id"):
            node_ids = [c.node_id for c in config.contacts if c.node_id]
            if node_ids:
                fields["visibility_list_id"] = store_node_list(_client_db, node_ids)
        async with httpx.AsyncClient() as hc:
            r = await hc.post(
                _server + "/posts",
                data=fields,
                files=file_tuples or None,
                headers=_headers(config.own_server),
                timeout=60.0,
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        post = r.json()
        post["_server_url"] = config.own_server
        post["_server_name"] = "me"
        own_poll_id = config.own_node_id or hashlib.sha256(config.own_server.encode()).hexdigest()[:16]
        asyncio.create_task(_background_fetch_one(own_poll_id))
        # Use form values for notification — the server auto-fills parent_node_id with own node_id
        # when it's missing from the form, so the response value is unreliable for remote parents.
        req_parent_id = fields.get("parent_id", "")
        req_parent_node_id = fields.get("parent_node_id", "")
        req_parent_server_url = fields.get("parent_server_url", "")
        if notify_parent and req_parent_id and (req_parent_node_id or req_parent_server_url):
            asyncio.create_task(
                _send_reply_notification(req_parent_id, req_parent_node_id, post["id"], req_parent_server_url)
            )
        return post

    @api.get("/posts/{post_id}")
    async def api_get_post(post_id: str, server: str = ""):
        src = server or config.own_server
        is_own = src == config.own_server
        fetch_url = _call_url(src) if is_own else src
        hdrs = {**_headers(src), **await _sign_federated("GET", f"/posts/{post_id}", b"")}
        async with httpx.AsyncClient() as hc:
            r = await hc.get(fetch_url + f"/posts/{post_id}", headers=hdrs, timeout=10.0)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        post = r.json()
        post["_server_url"] = src
        post["_server_name"] = _server_name(src)
        return post

    @api.patch("/posts/{post_id}")
    async def api_update_post(post_id: str, request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.patch(
                _server + f"/posts/{post_id}",
                json=payload,
                headers=_headers(config.own_server),
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        post = r.json()
        post["_server_url"] = config.own_server
        post["_server_name"] = "me"
        return post

    @api.delete("/posts/{post_id}", status_code=204)
    async def api_delete_post(post_id: str):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        async with httpx.AsyncClient() as hc:
            r = await hc.delete(
                _server + f"/posts/{post_id}",
                headers=_headers(config.own_server),
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    @api.post("/posts/{post_id}/react")
    async def api_react(post_id: str, request: Request, server: str = ""):
        src = server or config.own_server
        path = f"/posts/{post_id}/react"
        body = json.dumps(await request.json()).encode()
        h = {**_headers(src), "X-Origin-Server": config.own_server,
             "Content-Type": "application/json", **await _sign_federated("POST", path, body)}
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_call_url(src) + path, content=body, headers=h)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.get("/posts/{post_id}/replies")
    async def api_get_replies(post_id: str, server: str = ""):
        src = server or config.own_server
        path = f"/posts/{post_id}/replies"
        hdrs = {**_headers(src), **await _sign_federated("GET", path, b"")}
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_call_url(src) + path, headers=hdrs, timeout=10.0)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    # ── assets ────────────────────────────────────────────────────────────

    @api.post("/assets")
    async def api_upload_asset(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        body = await request.body()
        content_type = request.headers.get("content-type", "")
        async with httpx.AsyncClient() as hc:
            r = await hc.post(
                _server + "/assets",
                content=body,
                headers={**_headers(config.own_server), "content-type": content_type},
                timeout=120.0,
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.get("/assets/{asset_id}/thumb")
    async def api_asset_thumb(asset_id: str, server: str = "", hash: str = ""):
        src = server or config.own_server
        is_remote = src != config.own_server
        path = f"/assets/{asset_id}/thumb"
        try:
            sign_hdrs = await _sign_federated("GET", path, b"") if is_remote else {}
            async with httpx.AsyncClient() as hc:
                r = await hc.get(_call_url(src) + path, headers={**_headers(src), **sign_hdrs})
            if r.is_success:
                if is_remote:
                    _cache_asset(asset_id, r.headers.get("content-type", "image/jpeg"), r.content, thumb=True)
                return StreamingResponse(iter([r.content]),
                                         media_type=r.headers.get("content-type", "image/jpeg"))
        except Exception:
            pass
        if is_remote:
            cached = _read_cached_asset(asset_id, thumb=True, expected_hash=hash or None)
            if cached:
                return Response(content=cached[1], media_type=cached[0])
        raise HTTPException(status_code=502)

    @api.get("/assets/{asset_id}")
    async def api_asset(asset_id: str, server: str = "", hash: str = ""):
        src = server or config.own_server
        is_remote = src != config.own_server
        path = f"/assets/{asset_id}"
        try:
            sign_hdrs = await _sign_federated("GET", path, b"") if is_remote else {}
            async with httpx.AsyncClient() as hc:
                r = await hc.get(_call_url(src) + path, headers={**_headers(src), **sign_hdrs})
            if r.is_success:
                if is_remote:
                    _cache_asset(asset_id, r.headers.get("content-type", "application/octet-stream"), r.content, thumb=False)
                return StreamingResponse(
                    iter([r.content]),
                    media_type=r.headers.get("content-type", "application/octet-stream"),
                    headers={"content-disposition": r.headers.get("content-disposition", "")},
                )
        except Exception:
            pass
        if is_remote:
            cached = _read_cached_asset(asset_id, thumb=False, expected_hash=hash or None)
            if cached:
                return Response(content=cached[1], media_type=cached[0])
        raise HTTPException(status_code=502)

    # ── tags ──────────────────────────────────────────────────────────────

    @api.get("/tags")
    async def api_tags(server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_call_url(src) + "/tags", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── contacts ──────────────────────────────────────────────────────────
    _CAT_FIELDS = ["family", "close_friends", "friends", "colleagues", "acquaintances"]

    def _contact_weight(c) -> float:
        return max(getattr(c, f, 0.0) or 0.0 for f in _CAT_FIELDS)

    @api.get("/profile")
    async def api_profile():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/profile", headers=_internal_headers(), timeout=10)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.post("/profile/private-key")
    async def api_download_private_key(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/profile/private-key", json=payload,
                              headers=_headers(config.own_server), timeout=30)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return Response(
            content=r.content,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": "attachment; filename=contacc-private-key.pem"},
        )

    # ── SSE event bus ─────────────────────────────────────────────────────────
    _pending_post_updates: list[dict] = []   # fallback queue (no SSE connected)
    _pending_dm_updates: list[dict] = []     # fallback queue for DM events
    _active_subs: dict[str, float] = {}
    _sse_queues: list[asyncio.Queue] = []    # one per open SSE connection

    def _push_to_sse(event: dict) -> None:
        """Push event to all open SSE connections.

        When no browser is connected, DM events are buffered so a reconnecting
        browser can catch up on missed notifications (e.g. after tab was hidden).
        """
        if not _sse_queues:
            if event.get("type") == "dm":
                _pending_dm_updates.append(event)
                if len(_pending_dm_updates) > 50:
                    del _pending_dm_updates[:25]
            return
        for q in list(_sse_queues):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass

    @app.post("/notifications/post-update", status_code=204)
    async def receive_post_update(request: Request):
        try:
            body = await request.json()
            if body.get("post_id") and body.get("event"):
                if _sse_queues:
                    _push_to_sse(body)
                else:
                    _pending_post_updates.append(body)
                    if len(_pending_post_updates) > 200:
                        del _pending_post_updates[:100]
        except Exception:
            pass

    @app.post("/notifications/dm-update", status_code=204)
    async def receive_dm_update(request: Request):
        try:
            body = await request.json()
            event = {"type": "dm", "thread_id": body.get("thread_id", "")}
            if _sse_queues:
                _push_to_sse(event)
            else:
                _pending_dm_updates.append(event)
                if len(_pending_dm_updates) > 50:
                    del _pending_dm_updates[:25]
        except Exception:
            pass

    @api.get("/events")
    async def sse_events(request: Request):
        """SSE stream — browser holds this open to receive push events."""
        import asyncio as _aio
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        # Drain buffered DM events into this new connection so the browser catches
        # up on notifications missed while the SSE was closed (e.g. tab was hidden).
        pending = list(_pending_dm_updates)
        _pending_dm_updates.clear()
        for ev in pending:
            try:
                queue.put_nowait(ev)
            except asyncio.QueueFull:
                break
        _sse_queues.append(queue)

        async def _generate():
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=20.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            except asyncio.CancelledError:
                pass  # client disconnected — task cancelled
            finally:
                try:
                    _sse_queues.remove(queue)
                except ValueError:
                    pass

        return StreamingResponse(
            _generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @api.get("/subscribed-updates")
    async def get_subscribed_updates():
        updates = list(_pending_post_updates) + list(_pending_dm_updates)
        _pending_post_updates.clear()
        _pending_dm_updates.clear()
        # Also pull any inbound DM updates from server (legacy path, no SSE)
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.get(_server + "/dm/updates", headers=_internal_headers(), timeout=3)
            if r.is_success:
                updates.extend(r.json().get("updates", []))
        except Exception:
            pass
        return {"updates": updates}

    @api.post("/posts/{post_id}/subscribe")
    async def api_subscribe_post(post_id: str, request: Request, server: str = ""):
        src = server or config.own_server
        own_node = os.environ.get("CONTACC_NODE_ADDRESS", config.own_server).rstrip("/")
        callback_url = own_node + "/notifications/post-update"
        sub_key = f"{post_id}|{src}"
        now_t = time.time()
        if _active_subs.get(sub_key, 0) > now_t + 60:
            return {"status": "active"}
        ttl = 300
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.post(
                    _call_url(src) + f"/posts/{post_id}/subscribe",
                    json={"callback_url": callback_url, "ttl": ttl},
                    headers=_headers(src), timeout=5,
                )
            if r.is_success or r.status_code == 204:
                _active_subs[sub_key] = now_t + ttl
                return {"status": "subscribed", "ttl": ttl}
        except Exception:
            pass
        return {"status": "failed"}

    @api.get("/notifications/mentions")
    async def api_get_mentions():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/api/notifications/mentions",
                             headers=_internal_headers(), timeout=10)
        return r.json() if r.is_success else {"notifications": []}

    @api.post("/notifications/mentions/mark-seen", status_code=204)
    async def api_mark_mentions_seen():
        async with httpx.AsyncClient() as hc:
            await hc.post(_server + "/api/notifications/mentions/mark-seen",
                          headers=_internal_headers(), timeout=10)

    @api.get("/setup/passphrase-is-default")
    async def api_passphrase_is_default():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/setup/passphrase-is-default",
                             headers=_internal_headers(), timeout=30)
        return r.json() if r.is_success else {"is_default": False}

    @api.post("/setup/change-owner-passphrase")
    async def api_change_owner_passphrase(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/change-owner-passphrase", json=payload,
                              headers=_internal_headers(), timeout=30)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
        return r.json()

    @api.get("/setup/has-escrow")
    async def api_has_escrow():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/setup/has-escrow", headers=_internal_headers(), timeout=10)
        return r.json() if r.is_success else {"has_escrow": False}

    @api.post("/setup/create-identity-escrow")
    async def api_create_identity_escrow(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/create-identity-escrow", json=payload,
                              headers=_internal_headers(), timeout=30)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
        return r.json()

    @api.post("/setup/refresh-delegation")
    async def api_refresh_delegation(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/refresh-delegation", json=payload,
                              headers=_internal_headers(), timeout=30)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
        return r.json()

    @api.post("/settings/change-passphrase")
    async def api_change_passphrase(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/change-passphrase", json=payload,
                              headers=_internal_headers(), timeout=120)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
        data = r.json()
        # Keep client node_key in sync — it holds the same private key, re-encrypted.
        if "node_key" in data:
            nk = data["node_key"]
            config.node_key = NodeKey(
                argon2_salt=nk["argon2_salt"],
                encrypted_private_key=nk["encrypted_private_key"],
                argon2_time_cost=nk["argon2_time_cost"],
                argon2_memory_cost=nk["argon2_memory_cost"],
                argon2_parallelism=nk["argon2_parallelism"],
            )
            config.save(config_path)
        return data

    @api.post("/setup/release", status_code=204)
    async def api_release_node(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/release", json=payload,
                              headers=_internal_headers(), timeout=30)
        if not r.is_success:
            detail = r.json().get("detail", r.text) if r.content else "Release failed"
            raise HTTPException(status_code=r.status_code, detail=detail)
        # Server is now uninitialized — clear stored credentials
        own = config.own_server
        config.node_key = None
        config.internal_token = None
        config.own_node_id = None
        config.contacts = []
        config.save(config_path)
        # Drop stale server token and all client sessions so the next page load
        # goes through the proper login flow rather than appearing authenticated
        tokens.pop(own, None)
        save_tokens(config_path, tokens)
        _sessions.clear()
        return Response(status_code=204)

    @api.put("/profile")
    async def api_update_profile(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.put(
                _server + "/profile",
                json=payload,
                headers=_headers(config.own_server),
                timeout=10,
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.put("/profile/photo")
    async def api_update_photo(file: UploadFile = File(...)):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        content = await file.read()
        async with httpx.AsyncClient() as hc:
            r = await hc.put(
                _server + "/profile/photo",
                files={"file": (file.filename, content, file.content_type or "image/jpeg")},
                headers=_headers(config.own_server),
                timeout=30,
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.get("/contacts/lookup")
    async def api_lookup_handle(handle: str = Query(...)):
        from registry.client import lookup as registry_lookup
        record = await registry_lookup(handle, registry_url=_registry_url())
        if record is None:
            raise HTTPException(status_code=404, detail=f"Handle '{handle}' not found")
        return {
            "handle": handle,
            "name": record.get("display_name") or handle,
            "server_url": record["server_url"],
            "display_name": record.get("display_name"),
            "photo_url": record.get("photo_url"),
            "public_key": record.get("public_key"),
        }

    @api.get("/registry/node/{node_id}")
    async def api_registry_node(node_id: str):
        """Proxy GET /nodes/{node_id}: check local cache → peers → registry."""
        try:
            return await registry.lookup(node_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Node not found")

    @api.get("/contacts/search")
    async def api_search_contacts(q: str = Query(...)):
        q = q.strip()
        if not q:
            return {"results": []}
        reg = _registry_url()
        # Public key: route to lookup-by-key
        if len(q) >= 40 and not q.startswith("http") and "/" not in q and " " not in q:
            async with httpx.AsyncClient() as hc:
                r = await hc.get(reg + "/lookup-by-key", params={"public_key": q}, timeout=5)
            if r.is_success:
                d = r.json()
                return {"results": [{"username": d.get("username"), "server_url": d["server_url"],
                                     "display_name": d.get("display_name"), "photo_url": d.get("photo_url"),
                                     "public_key": q}]}
            return {"results": []}
        async with httpx.AsyncClient() as hc:
            r = await hc.get(reg + "/search", params={"q": q}, timeout=5)
        if not r.is_success:
            raise HTTPException(status_code=502, detail="Registry search failed")
        return r.json()

    @api.post("/contacts/refresh-node-ids", status_code=200)
    async def api_refresh_contact_node_ids():
        """Back-fill and correct node_id for contacts.

        Fetches /node for every contact (resolving URL via registry or legacy c.url)
        and updates node_id when:
        - it is missing entirely, or
        - the stored value is an old user_id/owner_id that differs from the
          server's current node_id (handles migrated identities).
        """
        updated = 0
        async with httpx.AsyncClient() as hc:
            for c in config.contacts:
                try:
                    url = None
                    if c.node_id:
                        url = await _contact_server_url(c.node_id)
                    if not url:
                        url = c.url  # fallback for contacts without node_id yet
                    if not url:
                        continue
                    r = await hc.get(url.rstrip("/") + "/node", timeout=4)
                    if not r.is_success:
                        continue
                    nd = r.json()
                    live_nid = nd.get("node_id")
                    pub = nd.get("public_key")
                    if not live_nid:
                        continue
                    # Update if missing or stale (node migrated to a new node_id).
                    if c.node_id != live_nid and not any(
                        x.node_id == live_nid for x in config.contacts if x is not c
                    ):
                        c.node_id = live_nid
                        if pub and not c.public_key:
                            c.public_key = pub
                        updated += 1
                except Exception:
                    pass
        if updated:
            config.save(config_path)
        return {"updated": updated}

    class ContactBody(BaseModel):
        name: str
        url: str
        handle: str | None = None
        public_key: str | None = None
        node_id: str | None = None  # node deployment identifier

    @api.post("/contacts", status_code=201)
    async def api_add_contact(body: ContactBody):
        from client.config import ContactEntry
        if body.url == config.own_server:
            raise HTTPException(status_code=400, detail="Cannot add yourself as a contact")

        # Fetch /node to get node_id and public_key — node_id is the stable identity
        node_id = body.node_id
        pub_key = body.public_key
        try:
            async with httpx.AsyncClient() as hc:
                nr = await hc.get(body.url.rstrip("/") + "/node", timeout=5)
            if nr.is_success:
                nd = nr.json()
                node_id = node_id or nd.get("node_id") or nd.get("user_id")
                pub_key = pub_key or nd.get("public_key") or None
        except Exception:
            pass
        if not node_id:
            raise HTTPException(status_code=502, detail="Could not reach contact's node to get node ID")

        # Deduplicate by node_id (primary key)
        if any(c.node_id == node_id for c in config.contacts):
            raise HTTPException(status_code=409, detail="Contact with this node ID already exists")

        # url is transient: populate in-memory for this request but don't persist
        config.contacts.append(ContactEntry(
            name=body.name, url=body.url, handle=body.handle,
            public_key=pub_key, node_id=node_id,
        ))
        config.save(config_path)
        if _token(config.own_server):
            async with httpx.AsyncClient() as hc:
                await hc.post(
                    _server + "/users",
                    json={"server_url": body.url, "name": body.name, "handle": body.handle, "public_key": pub_key, "node_id": node_id},
                    headers=_headers(config.own_server),
                    timeout=10.0,
                )
        return {"name": body.name, "url": body.url, "handle": body.handle, "node_id": node_id}

    class ContactPatchBody(BaseModel):
        url: str = ""
        node_id: str | None = None
        tag: str | None = None
        description: str | None = None
        family: float | None = None
        close_friends: float | None = None
        friends: float | None = None
        colleagues: float | None = None
        acquaintances: float | None = None

    @api.patch("/contacts")
    async def api_patch_contact(body: ContactPatchBody):
        contact = None
        if body.node_id:
            contact = next((c for c in config.contacts if c.node_id == body.node_id), None)
        if not contact and body.url:
            contact = next((c for c in config.contacts if c.url == body.url), None)
        if not contact:
            raise HTTPException(status_code=404, detail="Contact not found")
        dirty = False
        if body.tag is not None:
            db_set_tag(_client_db, contact.node_id or body.url, body.tag or None)
        if body.node_id is not None and not contact.node_id:
            contact.node_id = body.node_id
            dirty = True
        if body.description is not None:
            contact.description = body.description or None
            dirty = True
        for f in _CAT_FIELDS:
            v = getattr(body, f)
            if v is not None:
                setattr(contact, f, max(0.0, min(1.0, v)))
                dirty = True
        if dirty:
            config.save(config_path)
            # Sync weight to server so it can make nuanced data-sharing decisions
            weight = _contact_weight(contact)
            if weight > 0 and _token(config.own_server):
                try:
                    async with httpx.AsyncClient() as hc:
                        await hc.patch(
                            _server + "/users",
                            params={"server_url": body.url},
                            json={"server_url": body.url, "weight": weight},
                            headers=_headers(config.own_server),
                            timeout=5.0,
                        )
                except Exception:
                    pass  # non-fatal; weight will sync on next contact add
        return {"ok": True, "poll_weight": _contact_weight(contact)}

    # ── dev / debug ───────────────────────────────────────────────────────

    @api.get("/dev/asset-state/{asset_id}")
    async def api_dev_asset_state(asset_id: str):
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + f"/debug/asset-state/{asset_id}",
                             headers=_internal_headers(), timeout=10)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.get("/backup")
    async def api_backup():
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        import io, zipfile
        from fastapi.responses import Response as _Resp
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/backup", headers=_headers(config.own_server), timeout=120.0)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail="Backup failed")
        # Append client data so restore is complete
        buf = io.BytesIO(r.content)
        with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("client_config.json", config_path.read_text())
        cd = r.headers.get("content-disposition", "attachment; filename=contacc-backup.zip")
        return _Resp(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": cd},
        )

    @api.delete("/contacts")
    async def api_remove_contact(node_id: str = Query(None), url: str = Query(None)):
        before = len(config.contacts)
        if node_id:
            removed = [c for c in config.contacts if c.node_id == node_id]
            config.contacts = [c for c in config.contacts if c.node_id != node_id]
        elif url:
            removed = [c for c in config.contacts if c.url == url]
            config.contacts = [c for c in config.contacts if c.url != url]
        else:
            raise HTTPException(status_code=400, detail="node_id or url required")
        if len(config.contacts) == before:
            raise HTTPException(status_code=404, detail="Contact not found")
        config.save(config_path)
        # Sync removal to server
        if _token(config.own_server) and removed:
            c = removed[0]
            server_url = c.url or (await _contact_server_url(c.node_id) if c.node_id else None)
            if server_url:
                async with httpx.AsyncClient() as hc:
                    await hc.delete(
                        _server + "/users",
                        params={"server_url": server_url},
                        headers=_headers(config.own_server),
                        timeout=10.0,
                    )
        return {"ok": True}

    # ── node lists ────────────────────────────────────────────────────────────

    @api.get("/node-lists")
    async def api_get_node_lists():
        return {"node_lists": get_all_node_lists(_client_db)}

    @api.get("/node-lists/{list_id}")
    async def api_get_node_list(list_id: str):
        members = get_node_list(_client_db, list_id)
        if members is None:
            raise HTTPException(status_code=404, detail="Node list not found")
        return {"list_id": list_id, "node_ids": members}

    @api.post("/node-lists/from-contacts", status_code=201)
    async def api_node_list_from_contacts():
        node_ids = [c.node_id for c in config.contacts if c.node_id]
        if not node_ids:
            raise HTTPException(status_code=422, detail="No contacts with resolved node_ids")
        lid = store_node_list(_client_db, node_ids)
        return {"list_id": lid}

    # ── DM proxy endpoints ─────────────────────────────────────────────────────

    @api.get("/dm/threads")
    async def api_dm_threads():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/dm/threads", headers=_headers(config.own_server), timeout=10)
        data = r.json() if r.is_success else {"threads": []}
        threads = data.get("threads", [])
        # Auto-dedup: merge 1:1 threads sharing the same peer_node_id. Group
        # threads legitimately reuse their creator's peer_node_id (it names
        # "the relay hub", not "the conversation") and must never trigger this.
        seen_nodes: set[str] = set()
        has_dupes = False
        for t in threads:
            if t.get("group_id"):
                continue
            nid = t.get("peer_node_id") or ""
            if nid and nid in seen_nodes:
                has_dupes = True
                break
            if nid:
                seen_nodes.add(nid)
        if has_dupes:
            async with httpx.AsyncClient() as hc:
                await hc.post(_server + "/dm/threads/dedup", headers=_headers(config.own_server), timeout=15)
            async with httpx.AsyncClient() as hc:
                r2 = await hc.get(_server + "/dm/threads", headers=_headers(config.own_server), timeout=10)
            data = r2.json() if r2.is_success else data
            threads = data.get("threads", [])
        contact_by_node_id = {c.node_id: c for c in config.contacts if c.node_id}
        tags = get_all_tags(_client_db)

        def _name_for(node_id: str) -> str | None:
            contact = contact_by_node_id.get(node_id)
            if not contact:
                return None
            return (tags.get(contact.node_id) if contact.node_id else None) or contact.name

        for t in threads:
            contact = contact_by_node_id.get(t.get("peer_node_id", ""))
            t["is_contact"] = contact is not None
            if contact and not t.get("peer_name"):
                t["peer_name"] = _name_for(contact.node_id) if contact.node_id else contact.name
            # member_names are resolved server-side from registry_cache;
            # pass them through without overriding.
        return data

    class DmSendBody(BaseModel):
        peer_node_id: str | None = None
        peer_url: str | None = None
        group_id: str | None = None
        body: str

    @api.post("/dm/send", status_code=201)
    async def api_dm_send(payload: DmSendBody):
        json_body = {"body": payload.body}
        if payload.group_id:
            json_body["group_id"] = payload.group_id
        else:
            json_body["peer_node_id"] = payload.peer_node_id
            json_body["peer_url"] = payload.peer_url
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/dm/send", json=json_body,
                              headers=_headers(config.own_server), timeout=15)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    class CreateGroupBody(BaseModel):
        name: str
        member_node_ids: list[str]

    @api.post("/dm/groups", status_code=201)
    async def api_dm_create_group(payload: CreateGroupBody):
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/dm/groups",
                              json={"name": payload.name, "member_node_ids": payload.member_node_ids},
                              headers=_headers(config.own_server), timeout=20)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    class GroupMemberBody(BaseModel):
        node_id: str

    @api.post("/dm/groups/{group_id}/members", status_code=204)
    async def api_dm_add_group_member(group_id: str, payload: GroupMemberBody):
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + f"/dm/groups/{group_id}/members",
                              json={"node_id": payload.node_id},
                              headers=_headers(config.own_server), timeout=15)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    @api.post("/dm/groups/{group_id}/leave", status_code=204)
    async def api_dm_leave_group(group_id: str):
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + f"/dm/groups/{group_id}/leave",
                              headers=_headers(config.own_server), timeout=15)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    class RenameGroupBody(BaseModel):
        name: str

    @api.post("/dm/groups/{group_id}/rename", status_code=204)
    async def api_dm_rename_group(group_id: str, payload: RenameGroupBody):
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + f"/dm/groups/{group_id}/rename",
                              json={"name": payload.name},
                              headers=_headers(config.own_server), timeout=15)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    @api.get("/dm/messages/{thread_id}")
    async def api_dm_messages(thread_id: str, since: int = 0, limit: int = 50):
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + f"/dm/messages/{thread_id}",
                             params={"since": since, "limit": limit},
                             headers=_headers(config.own_server), timeout=10)
        return r.json() if r.is_success else {"messages": []}

    @api.post("/dm/threads/{thread_id}/seen", status_code=204)
    async def api_dm_seen(thread_id: str):
        async with httpx.AsyncClient() as hc:
            await hc.post(_server + f"/dm/threads/{thread_id}/seen",
                          headers=_headers(config.own_server), timeout=5)

    @api.post("/dm/threads/{keep_id}/merge/{drop_id}")
    async def api_dm_merge(keep_id: str, drop_id: str):
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + f"/dm/threads/{keep_id}/merge/{drop_id}",
                              headers=_headers(config.own_server), timeout=15)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    app.include_router(api)

    # ── contact photo cache (public — no client auth, contact node_id only) ──────

    @app.get("/api/contacts/photo")
    async def api_contact_photo(node_id: str):
        contact = next((c for c in config.contacts if c.node_id == node_id), None)
        if not contact:
            raise HTTPException(status_code=403, detail="Not a known contact")
        cache_dir = Path("/data/photo_cache")
        cache_file = cache_dir / node_id
        url = await _contact_server_url(node_id)
        if url:
            try:
                sign_hdrs = await _sign_federated("GET", "/profile/photo", b"")
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(url + "/profile/photo",
                                     headers={"X-Origin-Server": config.own_server, **sign_hdrs},
                                     timeout=5)
                if r.is_success:
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    cache_file.write_bytes(r.content)
                    return Response(content=r.content, media_type="image/jpeg",
                                    headers={"Cache-Control": "public, max-age=3600"})
            except Exception:
                pass
        if cache_file.exists():
            return Response(content=cache_file.read_bytes(), media_type="image/jpeg",
                            headers={"Cache-Control": "public, max-age=3600"})
        raise HTTPException(status_code=404, detail="Photo not available")

    # ── setup intercepts: capture key material returned by server ─────────────

    @app.post("/setup/new")
    async def proxy_setup_new(request: Request):
        payload = await request.json()
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.post(_server + "/setup/new", json=payload, timeout=30)
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Could not reach server: {exc}")
        data = r.json()
        if r.is_success and "node_key" in data:
            config.node_key = NodeKey(**data["node_key"])
            config.internal_token = data.get("internal_token")
            config.own_node_id = data.get("node_id")
            config.save(config_path)
            tokens.pop(config.own_server, None)
            if owner_token := data.get("owner_token"):
                tokens[config.own_server] = owner_token
            save_tokens(config_path, tokens)
            _sessions.clear()
            session_token = secrets.token_urlsafe(32)
            _sessions[session_token] = time.time_ns() + SESSION_TTL * 1_000_000_000
            return JSONResponse({"status": data.get("status"), "node_address": data.get("node_address"),
                                 "client_session": session_token}, status_code=r.status_code)
        return JSONResponse(content=data, status_code=r.status_code)

    @app.post("/setup/new-for-owner")
    async def proxy_setup_new_for_owner(request: Request):
        payload = await request.json()
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.post(_server + "/setup/new-for-owner", json=payload, timeout=30)
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Could not reach server: {exc}")
        data = r.json()
        if r.is_success and "node_key" in data:
            config.node_key = NodeKey(**data["node_key"])
            config.internal_token = data.get("internal_token")
            config.own_node_id = data.get("node_id")
            config.save(config_path)
            tokens.pop(config.own_server, None)
            if owner_token := data.get("owner_token"):
                tokens[config.own_server] = owner_token
            save_tokens(config_path, tokens)
            _sessions.clear()
            session_token = secrets.token_urlsafe(32)
            _sessions[session_token] = time.time_ns() + SESSION_TTL * 1_000_000_000
            return JSONResponse({"status": data.get("status"), "client_session": session_token},
                                status_code=r.status_code)
        return JSONResponse(content=data, status_code=r.status_code)

    # ── setup restore proxy (client extracts client_config.json from bundle) ──

    @app.post("/setup/restore")
    async def proxy_setup_restore(bundle: UploadFile = File(...), passphrase: str = Form(...), setup_token: str = Form(...)):
        import io, json as _json, zipfile
        from client.config import ContactEntry
        data = await bundle.read()
        # Restore client data from bundle before forwarding server data
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            if "client_config.json" in zf.namelist():
                client_data = _json.loads(zf.read("client_config.json"))
                # Restore contacts and own_node_id; keep own_server from current bootstrap
                config.contacts = [ContactEntry(**c) for c in client_data.get("contacts", [])]
                if client_data.get("own_node_id"):
                    config.own_node_id = client_data["own_node_id"]
                config.save(config_path)
        except Exception:
            pass
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.post(
                    _server + "/setup/restore",
                    files={"bundle": (bundle.filename, data, bundle.content_type or "application/octet-stream")},
                    data={"passphrase": passphrase, "setup_token": setup_token},
                    timeout=60,
                )
            resp = r.json()
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Could not reach server: {exc}")
        if r.is_success and "node_key" in resp:
            config.node_key = NodeKey(**resp["node_key"])
            config.internal_token = resp.get("internal_token")
            config.save(config_path)
        return JSONResponse(content={"status": resp.get("status")}, status_code=r.status_code)

    # ── auth callback (no client auth required) ──────────────────────────

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        # SSO completion — proxy to server's internal /auth/callback
        # (no-params case is served as a static file by the web layer)
        async with httpx.AsyncClient() as hc:
            r = await hc.get(
                _server + "/auth/callback",
                params=dict(request.query_params),
                headers=_internal_headers(),
                follow_redirects=False,
            )
        if r.is_redirect:
            from fastapi.responses import RedirectResponse as _Redir
            return _Redir(url=r.headers["location"], status_code=r.status_code)
        return JSONResponse(content=r.json(), status_code=r.status_code)

    # ── catch-all: proxy everything else to the server ────────────────────
    _STRIP_INBOUND = {"host", "x-contacc-internal", "x-contacc-role", "x-contacc-identity"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy_to_server(path: str, request: Request):
        body = await request.body()
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _STRIP_INBOUND}
        if config.internal_token:
            fwd_headers["x-contacc-internal"] = config.internal_token
        client = httpx.AsyncClient()
        try:
            server_req = client.build_request(
                method=request.method,
                url=_server + "/" + path,
                params=dict(request.query_params),
                content=body,
                headers=fwd_headers,
            )
            r = await client.send(server_req, stream=True, follow_redirects=False)
        except httpx.RequestError as exc:
            await client.aclose()
            raise HTTPException(status_code=502, detail=f"Server unreachable: {exc}")

        if r.is_redirect:
            location = r.headers.get("location", "/")
            await r.aclose()
            await client.aclose()
            from fastapi.responses import RedirectResponse as _Redir
            return _Redir(url=location, status_code=r.status_code)

        proxy_headers = {
            k: v for k, v in r.headers.items()
            if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
        }

        async def _stream():
            try:
                async for chunk in r.aiter_bytes():
                    yield chunk
            finally:
                await r.aclose()
                await client.aclose()

        return StreamingResponse(
            _stream(),
            status_code=r.status_code,
            headers=proxy_headers,
            media_type=r.headers.get("content-type"),
        )

    return app


def _dev_factory() -> FastAPI:
    """Factory for uvicorn --reload mode; reads config path from env."""
    return create_app(os.environ["CONTACC_CONFIG"])


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run the contacc client")
    parser.add_argument("config", help="Path to client_config.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9444)
    parser.add_argument("--reload", action="store_true", help="Reload on source changes (dev mode)")
    args = parser.parse_args()

    if args.reload:
        os.environ["CONTACC_CONFIG"] = args.config
        uvicorn.run("client.main:_dev_factory", factory=True, host=args.host, port=args.port,
                    reload=True, reload_dirs=["/app/client"], proxy_headers=True, forwarded_allow_ips="*",
                    timeout_graceful_shutdown=1)
        return

    app = create_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

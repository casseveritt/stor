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
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.config import ClientConfig, NodeKey, load_tokens, save_tokens

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
    config = ClientConfig.load(config_path)
    tokens: dict[str, str] = load_tokens(config_path)

    app = FastAPI(title="contacc client")
    app.state.config = config
    app.state.config_path = config_path

    @app.on_event("startup")
    async def _warm_caches():
        import asyncio
        asyncio.create_task(_refresh_contact_photos())
        asyncio.create_task(_backfill_contact_pubkeys())

    async def _backfill_contact_pubkeys():
        """Fetch public key from /node for any contact that's missing one, then sync to server."""
        changed = False
        for contact in config.contacts:
            if contact.public_key:
                continue
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(contact.url.rstrip("/") + "/node", timeout=5)
                if r.is_success:
                    pub_key = r.json().get("public_key")
                    if pub_key:
                        contact.public_key = pub_key
                        _contact_url_cache[pub_key] = contact.url
                        changed = True
                        log.info("Backfilled public key for contact %s", contact.url)
                        t = _token(config.own_server)
                        if t:
                            async with httpx.AsyncClient() as hc2:
                                await hc2.post(
                                    _server + "/users",
                                    json={"server_url": contact.url, "name": contact.name,
                                          "handle": contact.handle, "public_key": pub_key},
                                    headers=_headers(config.own_server),
                                    timeout=5,
                                )
            except Exception:
                pass
        if changed:
            config.save(config_path)

    async def _refresh_contact_photos():
        import hashlib
        cache_dir = Path("/data/photo_cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        for contact in config.contacts:
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(contact.url + "/profile/photo", timeout=5)
                if r.is_success:
                    key = hashlib.sha256(contact.url.encode()).hexdigest()
                    (cache_dir / key).write_bytes(r.content)
                    log.info("Cached photo for %s", contact.url)
            except Exception:
                pass

    # Decrypt private key at startup if we have key material and passphrase
    passphrase = os.environ.get("CONTACC_PASSPHRASE_UNSECURE", "")
    if config.node_key and passphrase:
        app.state.private_key = _load_private_key(config.node_key, passphrase)
        if app.state.private_key:
            log.info("Node private key loaded.")
    else:
        app.state.private_key = None

    # Internal server URL — use CONTACC_SERVER_URL if set (avoids external loop
    # when Caddy routes everything to the client).  Falls back to own_server so
    # local dev without Docker still works.
    _server = os.environ.get("CONTACC_SERVER_URL", "").rstrip("/") or config.own_server

    static_dir = Path(__file__).parent / "static"

    # ── client-level session auth ─────────────────────────────────────────

    _sessions: dict[str, float] = {}  # token -> expiry
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
        _sessions[session_token] = time.time() + SESSION_TTL
        return {"token": session_token}

    @app.get("/client/login-url")
    async def client_login_url(request: Request):
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
        if not expiry or time.time() > expiry:
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

    # ── contact URL indirection ───────────────────────────────────────────
    # pub_key → current URL; the only place contact URLs are cached.
    # Populated from config at startup; refreshed from registry on demand.
    _contact_url_cache: dict[str, str] = {
        c.public_key: c.url for c in config.contacts if c.public_key and c.url
    }

    def _url_for_pubkey(pub_key: str) -> str | None:
        return _contact_url_cache.get(pub_key)

    def _registry_url() -> str:
        from urllib.parse import urlparse
        parsed = urlparse(config.own_server)
        return f"https://{parsed.hostname}:8421"

    async def _refresh_url_for_pubkey(pub_key: str) -> str | None:
        """Query registry by public key, update cache + config, return fresh URL."""
        from registry.client import lookup_by_key as _lookup_by_key
        try:
            record = await _lookup_by_key(pub_key, registry_url=_registry_url())
            if record and record.get("server_url"):
                url = record["server_url"]
                _contact_url_cache[pub_key] = url
                contact = next((c for c in config.contacts if c.public_key == pub_key), None)
                if contact and contact.url != url:
                    log.info("Contact URL refreshed via registry: %s → %s", contact.url, url)
                    contact.url = url
                    config.save(config_path)
                return url
        except Exception:
            pass
        return None

    def _server_name(url: str) -> str:
        if url == config.own_server:
            return "me"
        return next((c.name for c in config.contacts if c.url == url), url)

    def _all_servers() -> list[str]:
        urls = [config.own_server]
        for c in config.contacts:
            url = (_url_for_pubkey(c.public_key) if c.public_key else None) or c.url
            if url:
                urls.append(url)
        return urls

    # ── local post/asset cache ────────────────────────────────────────────
    _POST_CACHE_DIR = Path("/data/post_cache")
    _ASSET_CACHE_DIR = Path("/data/asset_cache")
    _CACHE_TTL = 3 * 86400  # 3 days
    _CACHE_MAX_ASSET_BYTES = 50 * 1024 * 1024  # 50 MB

    def _cache_aes_key() -> bytes | None:
        private_key = getattr(app.state, "private_key", None)
        if not private_key:
            return None
        try:
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            from cryptography.hazmat.primitives.hashes import SHA256
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            return HKDF(algorithm=SHA256(), length=32, salt=None, info=b"contacc-local-cache").derive(priv_bytes)
        except Exception:
            return None

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
        import hashlib
        cache_dir = Path("/data/photo_cache")
        def _has_cached_photo(url: str) -> bool:
            key = hashlib.sha256(url.encode()).hexdigest()
            return (cache_dir / key).exists()
        own_display_name = None
        own_handle = None
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.get(_server + "/profile", headers=_internal_headers(), timeout=2)
                if r.is_success:
                    p = r.json()
                    own_display_name = p.get("display_name")
                    own_handle = p.get("handle")
        except Exception:
            pass
        return {
            "own_server": config.own_server,
            "own_display_name": own_display_name,
            "own_handle": own_handle,
            "dev": bool(os.environ.get("CONTACC_DEV")),
            "identity_proxy_url": os.environ.get("CONTACC_IDENTITY_PROXY_URL", ""),
            "servers": [
                {"name": _server_name(url), "url": url, "authenticated": bool(_token(url))}
                for url in _all_servers()
            ],
            "contacts": [{"name": c.name, "url": c.url, "handle": c.handle, "public_key": c.public_key} for c in config.contacts],
            "cached_photos": [c.url for c in config.contacts if _has_cached_photo(c.url)],
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

        # aggregate all servers
        servers = _all_servers()
        params_base: list[tuple[str, str]] = [("limit", str(limit))]
        if cursor: params_base.append(("cursor", cursor))
        if q: params_base.append(("q", q))
        for t in tags: params_base.append(("tags", t))

        async def _fetch_one(url: str) -> tuple[list, bool]:
            """Returns (posts, server_was_live)."""
            if not _token(url) and url == config.own_server:
                return [], True
            contact = next((c for c in config.contacts if c.url == url), None)
            contact_key = (contact.public_key if contact else None) or hashlib.sha256(url.encode()).hexdigest()
            is_contact_node = url != config.own_server

            async def _try_fetch(fetch_target: str) -> list | None:
                try:
                    actual_url = _server if fetch_target == config.own_server else fetch_target
                    hdrs = {**_headers(fetch_target), "X-Origin-Server": config.own_server,
                            **await _sign_federated("GET", "/posts", b"")}
                    async with httpx.AsyncClient() as hc:
                        r = await hc.get(actual_url + "/posts", params=params_base, headers=hdrs, timeout=10.0)
                    if r.is_success:
                        data = r.json()
                        name = _server_name(fetch_target)
                        posts = data.get("posts", [])
                        for post in posts:
                            post["_server_url"] = fetch_target
                            post["_server_name"] = name
                        if is_contact_node and not cursor and not q and not tags:
                            _cache_posts(contact_key, posts)
                        return posts
                except Exception:
                    pass
                return None

            result = await _try_fetch(url)
            if result is not None:
                return result, True
            # Fetch failed — try refreshing URL from registry
            if contact and contact.public_key:
                new_url = await _refresh_url_for_pubkey(contact.public_key)
                if new_url and new_url != url:
                    result = await _try_fetch(new_url)
                    if result is not None:
                        return result, True
            # Fall back to cached posts (serve expired as last resort)
            if is_contact_node:
                cached = _read_cached_posts(contact_key) or _read_cached_posts(contact_key, allow_expired=True)
                if cached:
                    log.info("Serving %d cached posts for %s", len(cached), url)
                    for p in cached:
                        p["_is_cached"] = True
                    return cached, False
            return [], not is_contact_node  # own server empty = live; contact empty = unknown, treat as offline

        import asyncio
        raw_results = await asyncio.gather(*[_fetch_one(url) for url in servers])
        server_status = {url: ("online" if live else "offline") for url, (_, live) in zip(servers, raw_results)}
        merged = sorted(
            [p for posts, _ in raw_results for p in posts],
            key=lambda p: p.get("created_at", 0),
            reverse=True,
        )[:limit]

        next_cursor = str(merged[-1]["created_at"]) if len(merged) == limit else None
        return {"posts": merged, "server_status": server_status, "next_cursor": next_cursor}

    # ── posts ─────────────────────────────────────────────────────────────

    @api.post("/posts")
    async def api_create_post(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        body = await request.body()
        content_type = request.headers.get("content-type", "")
        async with httpx.AsyncClient() as hc:
            r = await hc.post(
                _server + "/posts",
                content=body,
                headers={**_headers(config.own_server), "content-type": content_type},
                timeout=60.0,
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        post = r.json()
        post["_server_url"] = config.own_server
        post["_server_name"] = "me"
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

    @api.get("/posts/{post_id}/comments")
    async def api_get_comments(post_id: str, server: str = ""):
        src = server or config.own_server
        path = f"/posts/{post_id}/comments"
        h = {**_headers(src), "X-Origin-Server": config.own_server, **await _sign_federated("GET", path, b"")}
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_call_url(src) + path, headers=h)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.post("/posts/{post_id}/comments")
    async def api_post_comment(post_id: str, request: Request, server: str = ""):
        src = server or config.own_server
        path = f"/posts/{post_id}/comments"
        body = json.dumps(await request.json()).encode()
        h = {**_headers(src), "X-Origin-Server": config.own_server,
             "Content-Type": "application/json", **await _sign_federated("POST", path, body)}
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_call_url(src) + path, content=body, headers=h)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.patch("/posts/{post_id}/comments/{comment_id}")
    async def api_edit_comment(post_id: str, comment_id: str, request: Request):
        path = f"/posts/{post_id}/comments/{comment_id}"
        body = json.dumps(await request.json()).encode()
        h = {**_headers(config.own_server), "Content-Type": "application/json"}
        async with httpx.AsyncClient() as hc:
            r = await hc.patch(_call_url(config.own_server) + path, content=body, headers=h)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.delete("/posts/{post_id}/comments/{comment_id}", status_code=204)
    async def api_delete_comment(post_id: str, comment_id: str):
        path = f"/posts/{post_id}/comments/{comment_id}"
        async with httpx.AsyncClient() as hc:
            r = await hc.delete(_call_url(config.own_server) + path, headers=_headers(config.own_server))
        if not r.is_success and r.status_code != 204:
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

    # ── assets ────────────────────────────────────────────────────────────

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

    @api.post("/settings/change-passphrase")
    async def api_change_passphrase(request: Request):
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/setup/change-passphrase", json=payload,
                              headers=_internal_headers(), timeout=120)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.json().get("detail", r.text))
        return r.json()

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

    class ContactBody(BaseModel):
        name: str
        url: str
        handle: str | None = None
        public_key: str | None = None

    @api.post("/contacts", status_code=201)
    async def api_add_contact(body: ContactBody):
        from client.config import ContactEntry
        if body.url == config.own_server:
            raise HTTPException(status_code=400, detail="Cannot add yourself as a contact")
        if any(c.url == body.url for c in config.contacts):
            raise HTTPException(status_code=409, detail="Contact with this URL already exists")
        pub_key = body.public_key
        if not pub_key:
            try:
                async with httpx.AsyncClient() as hc:
                    nr = await hc.get(body.url.rstrip("/") + "/node", timeout=5)
                if nr.is_success:
                    pub_key = nr.json().get("public_key") or None
            except Exception:
                pass
        config.contacts.append(ContactEntry(name=body.name, url=body.url, handle=body.handle, public_key=pub_key))
        if pub_key:
            _contact_url_cache[pub_key] = body.url
        config.save(config_path)
        # Sync to server so it can authorize inbound comments from this contact
        if _token(config.own_server):
            async with httpx.AsyncClient() as hc:
                await hc.post(
                    _server + "/users",
                    json={"server_url": body.url, "name": body.name, "handle": body.handle, "public_key": pub_key},
                    headers=_headers(config.own_server),
                    timeout=10.0,
                )
        return {"name": body.name, "url": body.url, "handle": body.handle}

    # ── dev / debug ───────────────────────────────────────────────────────

    @api.get("/dev/asset-state/{asset_id}")
    async def api_dev_asset_state(asset_id: str):
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + f"/debug/asset-state/{asset_id}",
                             headers=_internal_headers(), timeout=10)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.get("/dev/db-check")
    async def api_dev_db_check():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(_server + "/debug/db-check",
                             headers=_internal_headers(), timeout=30)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        return r.json()

    @api.post("/dev/db-fix")
    async def api_dev_db_fix(request: Request):
        body = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(_server + "/debug/db-fix",
                              json=body, headers={**_internal_headers(), "Content-Type": "application/json"},
                              timeout=30)
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
        return _Resp(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=contacc-backup.zip"},
        )

    @api.delete("/contacts")
    async def api_remove_contact(url: str = Query(...)):
        before = len(config.contacts)
        removed = [c for c in config.contacts if c.url == url]
        config.contacts = [c for c in config.contacts if c.url != url]
        if len(config.contacts) == before:
            raise HTTPException(status_code=404, detail="Contact not found")
        for c in removed:
            if c.public_key:
                _contact_url_cache.pop(c.public_key, None)
        config.save(config_path)
        # Sync removal to server
        if _token(config.own_server):
            async with httpx.AsyncClient() as hc:
                await hc.delete(
                    _server + "/users",
                    params={"server_url": url},
                    headers=_headers(config.own_server),
                    timeout=10.0,
                )
        return {"ok": True}

    app.include_router(api)

    # ── contact photo cache (public — no client auth, contact URLs only) ──────

    @app.get("/api/contacts/photo")
    async def api_contact_photo(url: str):
        import hashlib
        if not any(c.url == url for c in config.contacts):
            raise HTTPException(status_code=403, detail="Not a known contact")
        cache_dir = Path("/data/photo_cache")
        cache_key = hashlib.sha256(url.encode()).hexdigest()
        cache_file = cache_dir / cache_key
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.get(url + "/profile/photo", timeout=5)
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
            config.save(config_path)
            passphrase = os.environ.get("CONTACC_PASSPHRASE_UNSECURE", "")
            if passphrase:
                app.state.private_key = _load_private_key(config.node_key, passphrase)
            return JSONResponse({"status": data.get("status"), "node_address": data.get("node_address")},
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
                # Restore contacts; keep own_server from current bootstrap
                config.contacts = [ContactEntry(**c) for c in client_data.get("contacts", [])]
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
            passphrase_env = os.environ.get("CONTACC_PASSPHRASE_UNSECURE", "")
            if passphrase_env:
                app.state.private_key = _load_private_key(config.node_key, passphrase_env)
        return JSONResponse(content={"status": resp.get("status")}, status_code=r.status_code)

    # ── auth callback and static (no client auth required) ────────────────

    _NC = {"Cache-Control": "no-cache"}

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        if request.query_params:
            # SSO completion — proxy to server's internal /auth/callback
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
        return FileResponse(static_dir / "callback.html", headers=_NC)

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html", headers=_NC)

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

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
                    reload=True, reload_dirs=["/app"], proxy_headers=True, forwarded_allow_ips="*")
        return

    app = create_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

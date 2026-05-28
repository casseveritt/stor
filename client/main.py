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
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

import httpx
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.config import ClientConfig, load_tokens, save_tokens


def create_app(config_path: str | Path) -> FastAPI:
    config_path = Path(config_path).resolve()
    config = ClientConfig.load(config_path)
    tokens: dict[str, str] = load_tokens(config_path)

    app = FastAPI(title="contacc client")
    app.state.config = config
    app.state.config_path = config_path

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
            r = await hc.get(config.own_server + "/auth/me",
                             headers={"Authorization": f"Bearer {server_token}"})
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
        # CONTACC_CLIENT_URL overrides request.base_url so the return_to link
        # uses the correct public https:// address even behind a reverse proxy.
        import os
        public_base = (os.environ.get("CONTACC_CLIENT_URL")
                       or str(request.base_url)).rstrip("/")
        return_to = public_base + "/auth/callback"
        server_login = (config.own_server + "/auth/login?provider=google&return_to="
                        + return_to)
        async with httpx.AsyncClient() as hc:
            r = await hc.get(server_login)
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

    def _headers(server_url: str) -> dict:
        t = _token(server_url)
        return {"Authorization": f"Bearer {t}"} if t else {}

    def _server_name(url: str) -> str:
        if url == config.own_server:
            return "me"
        return next((c.name for c in config.contacts if c.url == url), url)

    def _all_servers() -> list[str]:
        return [config.own_server] + [c.url for c in config.contacts]

    # ── config / status ───────────────────────────────────────────────────

    @api.get("/config")
    def api_config():
        return {
            "own_server": config.own_server,
            "servers": [
                {"name": _server_name(url), "url": url, "authenticated": bool(_token(url))}
                for url in _all_servers()
            ],
            "contacts": [{"name": c.name, "url": c.url} for c in config.contacts],
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
            r = await hc.get(src + "/auth/me", headers=_headers(src))
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
            if not _token(src):
                raise HTTPException(status_code=401, detail="Not authenticated for this server")
            params: list[tuple[str, str]] = [("limit", str(limit))]
            if cursor: params.append(("cursor", cursor))
            if q: params.append(("q", q))
            for t in tags: params.append(("tags", t))
            async with httpx.AsyncClient() as hc:
                r = await hc.get(src + "/posts", params=params, headers=_headers(src))
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

        async def _refresh_url(url: str) -> str | None:
            """Look up handle in registry; update and return new URL if changed."""
            contact = next((c for c in config.contacts if c.url == url), None)
            if not contact or not contact.handle:
                return None
            try:
                from registry.client import lookup as _lookup
                record = await _lookup(contact.handle)
                new_url = record.get("server_url") if record else None
                if new_url and new_url != url:
                    contact.url = new_url
                    config.save(config_path)
                    log.info("Contact %s URL updated: %s → %s", contact.handle, url, new_url)
                    return new_url
            except Exception:
                pass
            return None

        async def _fetch_one(url: str):
            if not _token(url) and url == config.own_server:
                return []
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(url + "/posts", params=params_base, headers=_headers(url), timeout=10.0)
                if r.is_success:
                    data = r.json()
                    name = _server_name(url)
                    for post in data.get("posts", []):
                        post["_server_url"] = url
                        post["_server_name"] = name
                    return data.get("posts", [])
            except Exception:
                pass
            # Fetch failed — try refreshing the URL from the registry
            new_url = await _refresh_url(url)
            if not new_url:
                return []
            try:
                async with httpx.AsyncClient() as hc:
                    r = await hc.get(new_url + "/posts", params=params_base, headers=_headers(new_url), timeout=10.0)
                if not r.is_success:
                    return []
                data = r.json()
                name = _server_name(new_url)
                for post in data.get("posts", []):
                    post["_server_url"] = new_url
                    post["_server_name"] = name
                return data.get("posts", [])
            except Exception:
                return []

        import asyncio
        results = await asyncio.gather(*[_fetch_one(url) for url in servers])
        merged = sorted(
            [p for batch in results for p in batch],
            key=lambda p: p.get("created_at", 0),
            reverse=True,
        )[:limit]

        next_cursor = str(merged[-1]["created_at"]) if len(merged) == limit else None
        return {"posts": merged, "next_cursor": next_cursor}

    # ── posts ─────────────────────────────────────────────────────────────

    @api.post("/posts")
    async def api_create_post(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        body = await request.body()
        content_type = request.headers.get("content-type", "")
        async with httpx.AsyncClient() as hc:
            r = await hc.post(
                config.own_server + "/posts",
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
                config.own_server + f"/posts/{post_id}",
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
                config.own_server + f"/posts/{post_id}",
                headers=_headers(config.own_server),
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code, detail=r.text)

    @api.get("/posts/{post_id}/comments")
    async def api_get_comments(post_id: str, server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + f"/posts/{post_id}/comments", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.post("/posts/{post_id}/comments")
    async def api_post_comment(post_id: str, request: Request, server: str = ""):
        src = server or config.own_server
        if not _token(src):
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.post(
                src + f"/posts/{post_id}/comments",
                json=payload,
                headers=_headers(src),
            )
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── assets ────────────────────────────────────────────────────────────

    @api.get("/assets/{asset_id}/thumb")
    async def api_asset_thumb(asset_id: str, server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + f"/assets/{asset_id}/thumb", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return StreamingResponse(iter([r.content]),
                                 media_type=r.headers.get("content-type", "image/jpeg"))

    @api.get("/assets/{asset_id}")
    async def api_asset(asset_id: str, server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + f"/assets/{asset_id}", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return StreamingResponse(
            iter([r.content]),
            media_type=r.headers.get("content-type", "application/octet-stream"),
            headers={"content-disposition": r.headers.get("content-disposition", "")},
        )

    # ── tags ──────────────────────────────────────────────────────────────

    @api.get("/tags")
    async def api_tags(server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + "/tags", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── contacts ──────────────────────────────────────────────────────────

    @api.get("/profile")
    async def api_profile():
        async with httpx.AsyncClient() as hc:
            r = await hc.get(config.own_server + "/profile", timeout=10)
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @api.put("/profile")
    async def api_update_profile(request: Request):
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = await request.json()
        async with httpx.AsyncClient() as hc:
            r = await hc.put(
                config.own_server + "/profile",
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
                config.own_server + "/profile/photo",
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
        record = await registry_lookup(handle)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Handle '{handle}' not found")
        return {
            "handle": handle,
            "name": record.get("display_name") or handle,
            "server_url": record["server_url"],
            "client_url": record.get("client_url", ""),
            "display_name": record.get("display_name"),
            "photo_url": record.get("photo_url"),
        }

    class ContactBody(BaseModel):
        name: str
        url: str
        handle: str | None = None

    @api.post("/contacts", status_code=201)
    def api_add_contact(body: ContactBody):
        from client.config import ContactEntry
        if any(c.url == body.url for c in config.contacts):
            raise HTTPException(status_code=409, detail="Contact with this URL already exists")
        config.contacts.append(ContactEntry(name=body.name, url=body.url, handle=body.handle))
        config.save(config_path)
        return {"name": body.name, "url": body.url, "handle": body.handle}

    @api.get("/backup")
    async def api_backup():
        if not _token(config.own_server):
            raise HTTPException(status_code=401, detail="Not authenticated")
        import io, zipfile
        from fastapi.responses import Response as _Resp
        async with httpx.AsyncClient() as hc:
            r = await hc.get(config.own_server + "/backup", headers=_headers(config.own_server), timeout=120.0)
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
    def api_remove_contact(url: str = Query(...)):
        before = len(config.contacts)
        config.contacts = [c for c in config.contacts if c.url != url]
        if len(config.contacts) == before:
            raise HTTPException(status_code=404, detail="Contact not found")
        config.save(config_path)
        return {"ok": True}

    app.include_router(api)

    # ── setup proxy (no client auth — server not initialized yet) ─────────

    async def _fwd(method: str, path: str, **kwargs) -> JSONResponse:
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.request(method, config.own_server + path, timeout=30, **kwargs)
            return JSONResponse(content=r.json(), status_code=r.status_code)
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Could not reach server: {exc}")

    @app.get("/node")
    async def proxy_node():
        return await _fwd("GET", "/node")

    @app.get("/setup/status")
    async def proxy_setup_status():
        return await _fwd("GET", "/setup/status")

    @app.get("/setup/check-handle")
    async def proxy_check_handle(handle: str):
        return await _fwd("GET", f"/setup/check-handle?handle={handle}")

    @app.post("/setup/new")
    async def proxy_setup_new(request: Request):
        return await _fwd("POST", "/setup/new", json=await request.json())

    @app.post("/setup/unlock")
    async def proxy_setup_unlock(request: Request):
        return await _fwd("POST", "/setup/unlock", json=await request.json())

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
                    config.own_server + "/setup/restore",
                    files={"bundle": (bundle.filename, data, bundle.content_type or "application/octet-stream")},
                    data={"passphrase": passphrase, "setup_token": setup_token},
                    timeout=60,
                )
            return JSONResponse(content=r.json(), status_code=r.status_code)
        except httpx.RequestError as exc:
            raise HTTPException(502, f"Could not reach server: {exc}")

    # ── auth callback and static (no client auth required) ────────────────

    _NC = {"Cache-Control": "no-cache"}

    @app.get("/auth/callback")
    def auth_callback():
        return FileResponse(static_dir / "callback.html", headers=_NC)

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html", headers=_NC)

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run the contacc client")
    parser.add_argument("config", help="Path to client_config.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9444)
    args = parser.parse_args()

    app = create_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

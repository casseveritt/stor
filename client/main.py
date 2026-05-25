"""contac client process — API-first personal aggregator.

Exposes /api/... routes that any frontend (web UI, mobile app) can consume.
The client manages authentication to server nodes internally; frontends
never handle server credentials directly.

Auth flow (web UI or mobile):
  1. GET /api/auth/login-url  → returns {auth_url}
  2. Open auth_url in browser → Google OAuth on own_server
  3. Server redirects to /auth/callback#token=<token>
  4. callback.html POSTs to /api/auth/token to persist it
  5. All subsequent /api/ calls use the stored token

NOTE: No auth on the client API itself in v1 (assumed localhost / trusted
network). Add client-level auth before exposing publicly.
"""
import sys
from pathlib import Path
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from client.config import ClientConfig, load_tokens, save_tokens


def create_app(config_path: str | Path) -> FastAPI:
    config_path = Path(config_path).resolve()
    config = ClientConfig.load(config_path)
    tokens: dict[str, str] = load_tokens(config_path)

    app = FastAPI(title="contac client")
    app.state.config = config
    app.state.config_path = config_path

    static_dir = Path(__file__).parent / "static"

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

    @app.get("/api/config")
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

    @app.get("/api/auth/login-url")
    async def api_login_url(request: Request):
        base = str(request.base_url).rstrip("/")
        return_to = base + "/auth/callback"
        server_login = (config.own_server + "/auth/login?provider=google&return_to="
                        + return_to)
        async with httpx.AsyncClient() as hc:
            r = await hc.get(server_login)
        if not r.is_success:
            raise HTTPException(status_code=502, detail="Server login unavailable")
        return {"auth_url": r.json()["auth_url"]}

    class TokenBody(BaseModel):
        token: str
        server: str = ""

    @app.post("/api/auth/token")
    def api_store_token(body: TokenBody):
        server = body.server or config.own_server
        tokens[server] = body.token
        save_tokens(config_path, tokens)
        return {"ok": True, "server": server}

    @app.delete("/api/auth/token")
    def api_clear_token(server: str = ""):
        url = server or config.own_server
        tokens.pop(url, None)
        save_tokens(config_path, tokens)
        return {"ok": True}

    @app.get("/api/auth/me")
    async def api_me(server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + "/auth/me", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── feed ──────────────────────────────────────────────────────────────

    @app.get("/api/feed")
    async def api_feed(
        server: str = "",
        cursor: str = "",
        q: str = "",
        tags: list[str] = Query(default=[]),
    ):
        src = server or config.own_server
        if not _token(src):
            raise HTTPException(status_code=401, detail="Not authenticated for this server")

        params: list[tuple[str, str]] = [("limit", "20")]
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

    # ── posts ─────────────────────────────────────────────────────────────

    @app.post("/api/posts")
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

    @app.get("/api/posts/{post_id}/comments")
    async def api_get_comments(post_id: str, server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + f"/posts/{post_id}/comments", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    @app.post("/api/posts/{post_id}/comments")
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

    @app.get("/api/assets/{asset_id}/thumb")
    async def api_asset_thumb(asset_id: str, server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + f"/assets/{asset_id}/thumb", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return StreamingResponse(iter([r.content]),
                                 media_type=r.headers.get("content-type", "image/jpeg"))

    @app.get("/api/assets/{asset_id}")
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

    @app.get("/api/tags")
    async def api_tags(server: str = ""):
        src = server or config.own_server
        async with httpx.AsyncClient() as hc:
            r = await hc.get(src + "/tags", headers=_headers(src))
        if not r.is_success:
            raise HTTPException(status_code=r.status_code)
        return r.json()

    # ── auth callback (receives token from server OAuth redirect) ─────────

    @app.get("/auth/callback")
    def auth_callback():
        return FileResponse(static_dir / "callback.html")

    # ── static / root ─────────────────────────────────────────────────────

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html")

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run the contac client")
    parser.add_argument("config", help="Path to client_config.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9865)
    args = parser.parse_args()

    app = create_app(args.config)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

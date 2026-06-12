"""contacc provider — node provisioning and invitation service."""
import os
import secrets
import sqlite3
import time
from urllib.parse import quote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

NS = 1_000_000_000
ADMIN_SESSION_TTL = 600  # 10 minutes


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.execute("""
        CREATE TABLE IF NOT EXISTS invitations (
            code            TEXT PRIMARY KEY,
            google_identity TEXT NOT NULL,
            node_url        TEXT NOT NULL,
            setup_token     TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            used_at         INTEGER
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token      TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        )
    """)
    con.commit()

    registry_url = os.environ.get("CONTACC_REGISTRY_URL", "https://strk.xyzw.us:8421").rstrip("/")
    provider_url = os.environ.get("CONTACC_PROVIDER_URL", "").rstrip("/")
    admin_identity = os.environ.get("CONTACC_ADMIN_IDENTITY", "")

    app = FastAPI(title="contacc provider", docs_url=None, redoc_url=None)

    def _verify_proxy_token(proxy_token: str) -> dict:
        """Call the registry to verify a proxy token. Returns {identity, display_name}."""
        try:
            r = httpx.get(f"{registry_url}/auth/verify", params={"token": proxy_token}, timeout=10)
        except httpx.RequestError:
            raise HTTPException(502, "Could not reach registry")
        if not r.is_success:
            raise HTTPException(403, "Token expired or invalid — please try again")
        return r.json()

    def _new_admin_session() -> str:
        now = time.time_ns()
        con.execute("DELETE FROM admin_sessions WHERE created_at < ?", (now - ADMIN_SESSION_TTL * NS,))
        token = secrets.token_urlsafe(24)
        con.execute("INSERT INTO admin_sessions VALUES (?, ?)", (token, now))
        con.commit()
        return token

    def _check_admin_session(token: str) -> bool:
        row = con.execute(
            "SELECT created_at FROM admin_sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row or time.time_ns() - row[0] > ADMIN_SESSION_TTL * NS:
            return False
        return True

    _CSS = """
      *{box-sizing:border-box}
      body{font-family:system-ui,sans-serif;background:#1a1a1a;color:#ddd;
           display:flex;align-items:center;justify-content:center;
           min-height:100vh;margin:0;padding:1rem}
      .card{background:#242424;border:1px solid #333;border-radius:8px;
            padding:2rem;width:100%;max-width:440px}
      h2{margin:0 0 1.25rem;font-size:1.1rem;color:#eee}
      label{display:block;font-size:.8rem;color:#888;margin-bottom:.25rem}
      input{width:100%;background:#1a1a1a;border:1px solid #444;border-radius:4px;
            color:#ddd;padding:.5rem .65rem;margin-bottom:.85rem;font-size:.9rem}
      button{width:100%;background:#4f8ef7;color:#fff;border:none;border-radius:4px;
             padding:.6rem;font-size:.95rem;cursor:pointer;margin-top:.25rem}
      button:hover{background:#3a7de0}
      .url-box{word-break:break-all;background:#1a1a1a;border:1px solid #444;
               border-radius:4px;padding:.65rem;font-size:.85rem;color:#7cf;
               margin-top:1rem;cursor:pointer}
      .meta{font-size:.78rem;color:#666;margin-top:.75rem}
      .err{color:#f87;font-size:.85rem;margin-top:.5rem}
      a{color:#4f8ef7;text-decoration:none}
    """

    # ── admin: create invitation ───────────────────────────────────────────────

    @app.get("/invite/new", response_class=HTMLResponse)
    def invite_new_start():
        if not admin_identity:
            raise HTTPException(503, "Provider admin not configured")
        return_to = provider_url + "/invite/new/form"
        return RedirectResponse(
            f"{registry_url}/auth/start?return_to={quote(return_to, safe='')}", 302
        )

    @app.get("/invite/new/form", response_class=HTMLResponse)
    def invite_new_form(proxy_token: str = ""):
        if not proxy_token:
            return RedirectResponse("/invite/new", 302)
        data = _verify_proxy_token(proxy_token)
        if data.get("identity") != admin_identity:
            return HTMLResponse(f"<style>{_CSS}</style>"
                                "<div class=card><p class=err>Admin access required.</p>"
                                "<p><a href='/invite/new'>Sign in as admin</a></p></div>", 403)
        session = _new_admin_session()
        return HTMLResponse(f"""<!doctype html><html><head><meta charset=utf-8>
<title>New Invitation — contacc</title><style>{_CSS}</style></head><body>
<div class=card>
  <h2>Create Invitation</h2>
  <form method=post action=/invite/new>
    <input type=hidden name=admin_session value="{session}">
    <label>Invitee Google email</label>
    <input name=google_identity placeholder="friend@example.com" required autocomplete=off>
    <label>Node URL</label>
    <input name=node_url placeholder="https://pc.xyzw.us:6448" required>
    <label>Setup token</label>
    <input name=setup_token placeholder="token from .setup_token file" required>
    <button type=submit>Create Invite Link</button>
  </form>
</div></body></html>""")

    @app.post("/invite/new", response_class=HTMLResponse)
    async def invite_new_create(request: Request):
        form = await request.form()
        admin_session = form.get("admin_session", "")
        if not _check_admin_session(admin_session):
            return RedirectResponse("/invite/new", 302)

        google_identity = form.get("google_identity", "").strip()
        node_url = form.get("node_url", "").strip().rstrip("/")
        setup_token = form.get("setup_token", "").strip()

        if not google_identity or not node_url or not setup_token:
            return HTMLResponse(f"<style>{_CSS}</style><div class=card>"
                                "<p class=err>All fields required.</p>"
                                "<p><a href='javascript:history.back()'>Go back</a></p></div>", 400)
        if not google_identity.startswith("google:"):
            google_identity = "google:" + google_identity

        code = secrets.token_urlsafe(16)
        con.execute(
            "INSERT INTO invitations VALUES (?, ?, ?, ?, ?, NULL)",
            (code, google_identity, node_url, setup_token, time.time_ns())
        )
        con.commit()

        invite_url = f"{provider_url}/invite/{code}"
        return HTMLResponse(f"""<!doctype html><html><head><meta charset=utf-8>
<title>Invitation Created — contacc</title><style>{_CSS}</style></head><body>
<div class=card>
  <h2>Invitation Created</h2>
  <p class=meta>For: {google_identity}</p>
  <div class=url-box onclick="navigator.clipboard.writeText(this.textContent)"
       title="Click to copy">{invite_url}</div>
  <p class=meta>Single-use link. Click the box to copy.</p>
  <p style="margin-top:1.25rem"><a href=/invite/new>Create another</a></p>
</div></body></html>""")

    # ── invitee: redeem invitation ─────────────────────────────────────────────

    @app.get("/invite/{code}")
    def invite_start(code: str):
        row = con.execute(
            "SELECT google_identity FROM invitations WHERE code = ? AND used_at IS NULL", (code,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Invitation not found or already used")
        return_to = f"{provider_url}/invite/{code}/verify"
        return RedirectResponse(
            f"{registry_url}/auth/start?return_to={quote(return_to, safe='')}", 302
        )

    @app.get("/invite/{code}/verify")
    def invite_verify(code: str, proxy_token: str = ""):
        if not proxy_token:
            raise HTTPException(400, "Missing proxy token")
        row = con.execute(
            "SELECT google_identity, node_url, setup_token FROM invitations"
            " WHERE code = ? AND used_at IS NULL",
            (code,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Invitation not found or already used")

        data = _verify_proxy_token(proxy_token)
        if data.get("identity") != row[0]:
            raise HTTPException(403, "This invitation is for a different Google account")

        con.execute("UPDATE invitations SET used_at = ? WHERE code = ?", (time.time_ns(), code))
        con.commit()

        node_url, setup_token = row[1], row[2]
        sep = "&" if "?" in node_url else "?"
        return RedirectResponse(f"{node_url}{sep}setup_token={setup_token}", 302)

    return app


def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Run the contacc provider")
    parser.add_argument("db", help="Path to provider SQLite database")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9520)
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    uvicorn.run(create_app(args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()

"""contacc provider — node provisioning and invitation service."""
import base64
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

NS = 1_000_000_000
ADMIN_SESSION_TTL = 1800   # 30 minutes
TIMESTAMP_TOLERANCE = 120  # seconds


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)

    # Migrate old invitations table (had code/node_url/setup_token columns) to new schema
    try:
        old_cols = {row[1] for row in con.execute("PRAGMA table_info(invitations)").fetchall()}
        if old_cols and "code" in old_cols:
            con.execute("DROP TABLE invitations")
    except Exception:
        pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS invitations (
            google_identity TEXT PRIMARY KEY,
            created_at      INTEGER NOT NULL,
            used_at         INTEGER
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS available_nodes (
            node_id     TEXT PRIMARY KEY,
            node_url    TEXT NOT NULL,
            setup_token TEXT NOT NULL,
            added_at    INTEGER NOT NULL
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

    # ── helpers ───────────────────────────────────────────────────────────────

    def _verify_proxy_token(proxy_token: str) -> dict:
        try:
            r = httpx.get(f"{registry_url}/auth/verify", params={"token": proxy_token}, timeout=10)
        except httpx.RequestError:
            raise HTTPException(502, "Could not reach registry")
        if not r.is_success:
            raise HTTPException(403, "Token expired or invalid — please try again")
        return r.json()

    def _verify_node_sig(public_key_b64: str, msg: str, signature_b64: str) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
            pub.verify(base64.b64decode(signature_b64), msg.encode())
            return True
        except (InvalidSignature, Exception):
            return False

    def _check_timestamp(ts: int) -> None:
        if abs(time.time() - ts) > TIMESTAMP_TOLERANCE:
            raise HTTPException(401, "Timestamp out of range")

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
        return bool(row and time.time_ns() - row[0] <= ADMIN_SESSION_TTL * NS)

    _CSS = """
      *{box-sizing:border-box}
      body{font-family:system-ui,sans-serif;background:#1a1a1a;color:#ddd;
           display:flex;align-items:center;justify-content:center;
           min-height:100vh;margin:0;padding:1rem}
      .card{background:#242424;border:1px solid #333;border-radius:8px;
            padding:2rem;width:100%;max-width:520px}
      h2{margin:0 0 1rem;font-size:1.05rem;color:#eee}
      label{display:block;font-size:.8rem;color:#888;margin-bottom:.25rem}
      input{width:100%;background:#1a1a1a;border:1px solid #444;border-radius:4px;
            color:#ddd;padding:.5rem .65rem;margin-bottom:.75rem;font-size:.9rem}
      .btn{background:#4f8ef7;color:#fff;border:none;border-radius:4px;
           padding:.5rem 1.1rem;font-size:.9rem;cursor:pointer}
      .btn:hover{background:#3a7de0}
      .inv-list{margin-top:.5rem;border-top:1px solid #333}
      .inv-row{display:flex;align-items:center;gap:.75rem;padding:.55rem 0;
               border-bottom:1px solid #2a2a2a}
      .inv-email{flex:1;font-size:.9rem;color:#ccc}
      .inv-date{font-size:.75rem;color:#666;white-space:nowrap}
      .del-btn{background:none;border:none;color:#f87;font-size:1rem;
               cursor:pointer;padding:.1rem .3rem;border-radius:3px;line-height:1}
      .del-btn:hover{background:#3a2020}
      .empty{color:#666;font-size:.85rem;padding:.5rem 0}
      .meta{font-size:.78rem;color:#666;margin:.5rem 0 0}
      .err{color:#f87;font-size:.85rem}
      a{color:#4f8ef7;text-decoration:none}
      .section{margin-top:1.75rem;padding-top:1.25rem;border-top:1px solid #333}
    """

    # ── node pool registration ─────────────────────────────────────────────────

    class NodeAvailableBody(BaseModel):
        node_id: str
        node_url: str
        setup_token: str
        public_key: str
        timestamp: int
        signature: str

    class NodeStartupBody(BaseModel):
        node_url: str
        setup_token: str

    class NodeRegisteredBody(BaseModel):
        node_id: str
        node_url: str
        public_key: str
        timestamp: int
        signature: str

    @app.post("/nodes/available", status_code=204)
    def node_available(body: NodeAvailableBody):
        _check_timestamp(body.timestamp)
        msg = f"contacc:provider-available:{body.node_id}:{body.timestamp}"
        if not _verify_node_sig(body.public_key, msg, body.signature):
            raise HTTPException(401, "Invalid signature")
        con.execute(
            "INSERT OR REPLACE INTO available_nodes VALUES (?, ?, ?, ?)",
            (body.node_id, body.node_url, body.setup_token, time.time_ns())
        )
        con.commit()

    @app.post("/nodes/startup", status_code=204)
    def node_startup(body: NodeStartupBody):
        """Uninitialized node announces availability; node_url used as synthetic node_id."""
        node_url = body.node_url.rstrip("/")
        con.execute(
            "INSERT OR REPLACE INTO available_nodes VALUES (?, ?, ?, ?)",
            (node_url, node_url, body.setup_token, time.time_ns())
        )
        con.commit()

    @app.post("/nodes/registered", status_code=204)
    def node_registered(body: NodeRegisteredBody):
        _check_timestamp(body.timestamp)
        msg = f"contacc:provider-registered:{body.node_id}:{body.timestamp}"
        if not _verify_node_sig(body.public_key, msg, body.signature):
            raise HTTPException(401, "Invalid signature")
        # Delete both the real node_id entry and any synthetic startup entry (node_id == node_url)
        con.execute("DELETE FROM available_nodes WHERE node_id = ? OR node_id = ?",
                    (body.node_id, body.node_url.rstrip("/")))
        con.commit()

    # ── admin UI ──────────────────────────────────────────────────────────────

    def _admin_page(s: str) -> str:
        rows = con.execute(
            "SELECT google_identity, created_at FROM invitations"
            " WHERE used_at IS NULL ORDER BY created_at DESC"
        ).fetchall()
        pool_count = con.execute("SELECT count(*) FROM available_nodes").fetchone()[0]

        inv_html = ""
        for identity, created_at in rows:
            email = identity.removeprefix("google:")
            ts = time.strftime("%Y-%m-%d", time.gmtime(created_at / NS))
            inv_html += f"""<div class=inv-row>
              <span class=inv-email>{email}</span>
              <span class=inv-date>{ts}</span>
              <form method=post action=/invite/delete style="margin:0">
                <input type=hidden name=s value="{s}">
                <input type=hidden name=google_identity value="{identity}">
                <button type=submit class=del-btn title="Delete invitation">🗑</button>
              </form>
            </div>"""
        if not inv_html:
            inv_html = "<p class=empty>No pending invitations.</p>"

        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>Invitations — contacc</title><style>{_CSS}</style></head><body>
<div class=card>
  <h2>Invite Someone</h2>
  <form method=post action="/invite/add?s={s}">
    <label>Google email</label>
    <input name=google_identity placeholder="friend@example.com" required autocomplete=off>
    <button type=submit class=btn>Add Invite</button>
  </form>
  <p class=meta>{pool_count} node{'s' if pool_count != 1 else ''} available in pool</p>
  <div class=section>
    <h2>Pending Invitations</h2>
    <div class=inv-list>{inv_html}</div>
  </div>
</div></body></html>"""

    @app.get("/", response_class=HTMLResponse)
    def root():
        return RedirectResponse("/invite/admin", 302)

    @app.get("/invite/admin", response_class=HTMLResponse)
    def invite_admin(s: str = ""):
        if not admin_identity:
            raise HTTPException(503, "Provider admin not configured")
        if not s or not _check_admin_session(s):
            return_to = provider_url + "/invite/admin/verify"
            return RedirectResponse(
                f"{registry_url}/auth/start?return_to={quote(return_to, safe='')}", 302
            )
        return HTMLResponse(_admin_page(s))

    @app.get("/invite/admin/verify")
    def invite_admin_verify(proxy_token: str = ""):
        if not proxy_token:
            return RedirectResponse("/invite/admin", 302)
        data = _verify_proxy_token(proxy_token)
        if data.get("identity") != admin_identity:
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<p class=err>Admin access required.</p>"
                "<p><a href='/invite/admin'>Sign in as admin</a></p></div>", 403
            )
        session = _new_admin_session()
        return RedirectResponse(f"/invite/admin?s={session}", 302)

    @app.post("/invite/add")
    async def invite_add(request: Request, s: str = ""):
        if not _check_admin_session(s):
            return RedirectResponse("/invite/admin", 302)
        form = await request.form()
        google_identity = form.get("google_identity", "").strip()
        if google_identity:
            if not google_identity.startswith("google:"):
                google_identity = "google:" + google_identity
            con.execute(
                "INSERT OR REPLACE INTO invitations VALUES (?, ?, NULL)",
                (google_identity, time.time_ns())
            )
            con.commit()
        return RedirectResponse(f"/invite/admin?s={s}", 302)

    @app.post("/invite/delete")
    async def invite_delete(request: Request):
        form = await request.form()
        s = form.get("s", "")
        if not _check_admin_session(s):
            return RedirectResponse("/invite/admin", 302)
        google_identity = form.get("google_identity", "")
        if google_identity:
            con.execute("DELETE FROM invitations WHERE google_identity = ?", (google_identity,))
            con.commit()
        return RedirectResponse(f"/invite/admin?s={s}", 302)

    # ── invitee: accept invitation ─────────────────────────────────────────────

    @app.get("/accept_invitation")
    def accept_invitation():
        return_to = provider_url + "/accept_invitation/verify"
        return RedirectResponse(
            f"{registry_url}/auth/start?return_to={quote(return_to, safe='')}", 302
        )

    @app.get("/accept_invitation/verify", response_class=HTMLResponse)
    def accept_invitation_verify(proxy_token: str = ""):
        if not proxy_token:
            return RedirectResponse("/accept_invitation", 302)
        data = _verify_proxy_token(proxy_token)
        identity = data.get("identity", "")

        inv = con.execute(
            "SELECT google_identity FROM invitations WHERE google_identity = ? AND used_at IS NULL",
            (identity,)
        ).fetchone()
        if not inv:
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>No invitation found</h2>"
                f"<p>No pending invitation for <b>{identity.removeprefix('google:')}</b>.</p>"
                "<p>Please ask the admin for an invite.</p></div>", 403
            )

        node_row = con.execute(
            "SELECT node_id, node_url, setup_token FROM available_nodes ORDER BY added_at LIMIT 1"
        ).fetchone()
        if not node_row:
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>No nodes available</h2>"
                "<p>All instances are currently claimed. Please try again later.</p></div>", 503
            )

        node_id, node_url, setup_token = node_row
        con.execute("UPDATE invitations SET used_at = ? WHERE google_identity = ?",
                    (time.time_ns(), identity))
        con.execute("DELETE FROM available_nodes WHERE node_id = ?", (node_id,))
        con.commit()

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

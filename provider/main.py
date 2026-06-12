"""contacc provider — node provisioning and invitation service."""
import base64
import logging
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
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

log = logging.getLogger("contacc.provider")

NS = 1_000_000_000
SESSION_TTL = 1800          # 30 minutes
TIMESTAMP_TOLERANCE = 120   # seconds
PENDING_TIMEOUT = 10 * 60   # 10 minutes before a stalled setup is recovered
USER_INVITE_LIMIT = 5       # max outstanding invites a node owner can have


def create_app(db_path: str) -> FastAPI:
    con = sqlite3.connect(db_path, check_same_thread=False)

    # ── schema ────────────────────────────────────────────────────────────────

    # Migrate invitations: add any missing columns (never drops)
    existing_inv = {row[1] for row in con.execute("PRAGMA table_info(invitations)").fetchall()}
    for col, typedef in [
        ("pending_at", "INTEGER"),
        ("pending_node_url", "TEXT"),
        ("pending_setup_token", "TEXT"),
        ("created_by", "TEXT"),   # google_identity of sponsor; NULL = admin
    ]:
        if col not in existing_inv:
            try:
                con.execute(f"ALTER TABLE invitations ADD COLUMN {col} {typedef}")
            except Exception:
                pass

    con.execute("""
        CREATE TABLE IF NOT EXISTS invitations (
            google_identity      TEXT PRIMARY KEY,
            created_at           INTEGER NOT NULL,
            pending_at           INTEGER,
            pending_node_url     TEXT,
            pending_setup_token  TEXT,
            used_at              INTEGER,
            created_by           TEXT
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
        CREATE TABLE IF NOT EXISTS claimed_nodes (
            node_url        TEXT PRIMARY KEY,
            google_identity TEXT NOT NULL,
            claimed_at      INTEGER NOT NULL
        )
    """)
    try:
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_claimed_identity"
                    " ON claimed_nodes(google_identity)")
    except Exception:
        pass
    con.execute("""
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token      TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            token      TEXT PRIMARY KEY,
            identity   TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    con.commit()

    registry_url = os.environ.get("CONTACC_REGISTRY_URL", "https://strk.xyzw.us:8421").rstrip("/")
    provider_url = os.environ.get("CONTACC_PROVIDER_URL", "").rstrip("/")
    admin_identity = os.environ.get("CONTACC_ADMIN_IDENTITY", "")

    app = FastAPI(title="contacc provider", docs_url=None, redoc_url=None)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=[],
    )

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
        con.execute("DELETE FROM admin_sessions WHERE created_at < ?", (now - SESSION_TTL * NS,))
        token = secrets.token_urlsafe(24)
        con.execute("INSERT INTO admin_sessions VALUES (?, ?)", (token, now))
        con.commit()
        return token

    def _check_admin_session(token: str) -> bool:
        row = con.execute(
            "SELECT created_at FROM admin_sessions WHERE token = ?", (token,)
        ).fetchone()
        return bool(row and time.time_ns() - row[0] <= SESSION_TTL * NS)

    def _new_user_session(identity: str) -> str:
        now = time.time_ns()
        con.execute("DELETE FROM user_sessions WHERE created_at < ?", (now - SESSION_TTL * NS,))
        token = secrets.token_urlsafe(24)
        con.execute("INSERT INTO user_sessions VALUES (?, ?, ?)", (token, identity, now))
        con.commit()
        return token

    def _check_user_session(token: str) -> str | None:
        """Returns identity if session valid, None otherwise."""
        row = con.execute(
            "SELECT identity, created_at FROM user_sessions WHERE token = ?", (token,)
        ).fetchone()
        if row and time.time_ns() - row[1] <= SESSION_TTL * NS:
            return row[0]
        return None

    def _claimed_node(identity: str) -> str | None:
        """Return the node_url owned by this identity, or None."""
        row = con.execute(
            "SELECT node_url FROM claimed_nodes WHERE google_identity = ?", (identity,)
        ).fetchone()
        return row[0] if row else None

    def _check_pending_timeouts() -> None:
        """Re-add stalled pending nodes back to the pool if still uninitialized."""
        cutoff = time.time_ns() - PENDING_TIMEOUT * NS
        rows = con.execute(
            "SELECT google_identity, pending_node_url, pending_setup_token"
            " FROM invitations WHERE pending_at IS NOT NULL AND pending_at < ? AND used_at IS NULL",
            (cutoff,)
        ).fetchall()
        for identity, node_url, setup_token in rows:
            if not node_url:
                continue
            try:
                r = httpx.get(f"{node_url}/setup/status", timeout=5)
                if not r.is_success:
                    continue
                state = r.json().get("state", "")
            except Exception:
                continue

            if state == "uninitialized":
                try:
                    tr = httpx.post(f"{node_url}/setup/refresh-token",
                                    params={"setup_token": setup_token}, timeout=5)
                    new_token = tr.json().get("setup_token", setup_token) if tr.is_success else setup_token
                except Exception:
                    new_token = setup_token
                con.execute(
                    "INSERT OR REPLACE INTO available_nodes VALUES (?, ?, ?, ?)",
                    (node_url, node_url, new_token, time.time_ns())
                )
                con.execute(
                    "UPDATE invitations"
                    " SET pending_at=NULL, pending_node_url=NULL, pending_setup_token=NULL"
                    " WHERE google_identity = ?", (identity,)
                )
                log.info("Recovered stalled node back to pool: %s (invitee: %s)", node_url, identity)
            elif state in ("locked", "running"):
                con.execute(
                    "UPDATE invitations SET used_at = ? WHERE google_identity = ?",
                    (time.time_ns(), identity)
                )
        con.commit()

    # ── node invite-status (public, no auth, CORS-open) ───────────────────────

    @app.get("/nodes/invite-status")
    def nodes_invite_status(identity: str = ""):
        if not identity:
            raise HTTPException(400, "identity required")
        if not identity.startswith("google:"):
            identity = "google:" + identity
        claimed = con.execute(
            "SELECT node_url FROM claimed_nodes WHERE google_identity = ?", (identity,)
        ).fetchone()
        if not claimed:
            return {"eligible": False, "reason": "no claimed node"}
        pending = con.execute(
            "SELECT count(*) FROM invitations WHERE created_by = ? AND used_at IS NULL",
            (identity,)
        ).fetchone()[0]
        return {"eligible": pending < USER_INVITE_LIMIT, "pending": pending, "limit": USER_INVITE_LIMIT}

    _CSS = """
      *{box-sizing:border-box}
      body{font-family:system-ui,sans-serif;background:#1a1a1a;color:#ddd;
           display:flex;align-items:center;justify-content:center;
           min-height:100vh;margin:0;padding:1rem}
      .card{background:#242424;border:1px solid #333;border-radius:8px;
            padding:2rem;width:100%;max-width:560px}
      h2{margin:0 0 1rem;font-size:1.05rem;color:#eee}
      label{display:block;font-size:.8rem;color:#888;margin-bottom:.25rem}
      input{width:100%;background:#1a1a1a;border:1px solid #444;border-radius:4px;
            color:#ddd;padding:.5rem .65rem;margin-bottom:.75rem;font-size:.9rem}
      .btn{background:#4f8ef7;color:#fff;border:none;border-radius:4px;
           padding:.5rem 1.1rem;font-size:.9rem;cursor:pointer}
      .btn:hover{background:#3a7de0}
      .list{margin-top:.5rem;max-height:200px;overflow-y:auto}
      .row{display:flex;align-items:center;gap:.6rem;padding:.45rem 0;
           border-bottom:1px solid #2a2a2a;font-size:.85rem}
      .row:last-child{border-bottom:none}
      .main{flex:1;color:#ccc}
      .sub{font-size:.75rem;color:#666;white-space:nowrap}
      .del-btn{background:none;border:none;color:#f87;font-size:1rem;
               cursor:pointer;padding:.1rem .3rem;border-radius:3px;line-height:1;flex-shrink:0}
      .del-btn:hover{background:#3a2020}
      .pending-row{display:flex;flex-direction:column;gap:.15rem;padding:.55rem 0;
                   border-bottom:1px solid #2a2a2a}
      .pending-row:last-child{border-bottom:none}
      .pending-email{font-size:.9rem;color:#ccc}
      .pending-node{font-size:.78rem;color:#7af}
      .pending-age{font-size:.75rem;color:#666;margin-top:.1rem}
      .pending-age.warn{color:#ca7}
      .empty{color:#555;font-size:.85rem;padding:.35rem 0}
      .meta{font-size:.78rem;color:#666;margin:.4rem 0 0}
      .node-url{font-size:.8rem;color:#7af;margin:.25rem 0 .75rem}
      .err{color:#f87;font-size:.85rem}
      .ok{color:#7c7;font-size:.85rem}
      a{color:#4f8ef7;text-decoration:none}
      .section{margin-top:1.5rem;padding-top:1.25rem;border-top:1px solid #333}
      .sponsor{font-size:.72rem;color:#555}
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
        pending = con.execute(
            "SELECT 1 FROM invitations WHERE pending_node_url = ? AND used_at IS NULL",
            (node_url,)
        ).fetchone()
        if pending:
            return
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
        node_url = body.node_url.rstrip("/")
        con.execute("DELETE FROM available_nodes WHERE node_id = ? OR node_id = ?",
                    (body.node_id, node_url))
        # Close out pending invitation and record ownership
        inv = con.execute(
            "SELECT google_identity FROM invitations"
            " WHERE pending_node_url = ? AND used_at IS NULL", (node_url,)
        ).fetchone()
        if inv:
            google_identity = inv[0]
            con.execute("UPDATE invitations SET used_at = ? WHERE google_identity = ?",
                        (time.time_ns(), google_identity))
            con.execute("INSERT OR REPLACE INTO claimed_nodes VALUES (?, ?, ?)",
                        (node_url, google_identity, time.time_ns()))
            log.info("Registration complete: %s → %s (node_id=%s)",
                     google_identity, node_url, body.node_id)
        con.commit()

    # ── admin UI ──────────────────────────────────────────────────────────────

    def _admin_page(s: str) -> str:
        _check_pending_timeouts()

        avail_rows = con.execute(
            "SELECT node_url FROM available_nodes ORDER BY added_at"
        ).fetchall()
        avail_html = "".join(
            f'<div class=row><span class=main>{r[0]}</span></div>' for r in avail_rows
        ) or '<p class=empty>No nodes available.</p>'

        pending_rows = con.execute(
            "SELECT google_identity, pending_at, pending_node_url FROM invitations"
            " WHERE pending_at IS NOT NULL AND used_at IS NULL ORDER BY pending_at"
        ).fetchall()
        now_ns = time.time_ns()
        pending_html = ""
        for identity, pending_at, node_url in pending_rows:
            email = identity.removeprefix("google:")
            elapsed = int((now_ns - pending_at) / NS)
            age = f"{elapsed//60}m {elapsed%60}s" if elapsed >= 60 else f"{elapsed}s"
            age_class = "pending-age warn" if elapsed > 5 * 60 else "pending-age"
            pending_html += (
                f'<div class=pending-row>'
                f'<span class=pending-email>{email}</span>'
                f'<span class=pending-node>{node_url}</span>'
                f'<span class="{age_class}">pending for {age}</span>'
                f'</div>'
            )
        if not pending_html:
            pending_html = '<p class=empty>No pending setups.</p>'

        inv_rows = con.execute(
            "SELECT google_identity, created_at, created_by FROM invitations"
            " WHERE pending_at IS NULL AND used_at IS NULL ORDER BY created_at DESC"
        ).fetchall()
        inv_html = ""
        for identity, created_at, created_by in inv_rows:
            email = identity.removeprefix("google:")
            ts = time.strftime("%Y-%m-%d", time.gmtime(created_at / NS))
            sponsor = ""
            if created_by:
                sponsor = f'<span class=sponsor>invited by {created_by.removeprefix("google:")}</span>'
            inv_html += (
                f'<div class=row>'
                f'<span class=main>{email}{" " + sponsor if sponsor else ""}</span>'
                f'<span class=sub>{ts}</span>'
                f'<form method=post action=/invite/delete style="margin:0">'
                f'<input type=hidden name=s value="{s}">'
                f'<input type=hidden name=google_identity value="{identity}">'
                f'<button type=submit class=del-btn title="Delete">🗑</button>'
                f'</form>'
                f'</div>'
            )
        if not inv_html:
            inv_html = '<p class=empty>No outstanding invitations.</p>'

        claimed_count = con.execute("SELECT count(*) FROM claimed_nodes").fetchone()[0]

        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>Invitations — contacc</title><style>{_CSS}</style></head><body>
<div class=card>
  <h2>Invite Someone</h2>
  <form method=post action="/invite/add?s={s}">
    <label>Google email</label>
    <input name=google_identity placeholder="friend@example.com" required autocomplete=off>
    <button type=submit class=btn>Add Invite</button>
  </form>

  <div class=section>
    <h2>Available Instances ({len(avail_rows)})</h2>
    <div class=list>{avail_html}</div>
  </div>

  <div class=section>
    <h2>Pending Setup ({len(pending_rows)})</h2>
    <div class=list>{pending_html}</div>
  </div>

  <div class=section>
    <h2>Outstanding Invitations ({len(inv_rows)})</h2>
    <div class=list>{inv_html}</div>
  </div>

  <p class=meta style="margin-top:1.5rem">{claimed_count} claimed node{'s' if claimed_count != 1 else ''} total</p>
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
        identity = data.get("identity", "")
        if identity != admin_identity:
            log.warning("Admin auth rejected: %s", identity)
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<p class=err>Admin access required.</p>"
                "<p><a href='/invite/admin'>Sign in as admin</a></p></div>", 403
            )
        log.info("Admin authenticated: %s", identity)
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
                "INSERT OR REPLACE INTO invitations(google_identity, created_at, created_by)"
                " VALUES (?, ?, NULL)",
                (google_identity, time.time_ns())
            )
            con.commit()
            log.info("Admin created invitation for %s", google_identity)
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
            log.info("Admin deleted invitation for %s", google_identity)
        return RedirectResponse(f"/invite/admin?s={s}", 302)

    # ── user invite UI ────────────────────────────────────────────────────────

    def _user_invite_page(s: str, identity: str) -> str:
        node_url = _claimed_node(identity)
        email = identity.removeprefix("google:")

        inv_rows = con.execute(
            "SELECT google_identity, created_at, used_at FROM invitations"
            " WHERE created_by = ? ORDER BY created_at DESC",
            (identity,)
        ).fetchall()

        pending_count = sum(1 for r in inv_rows if not r[2])
        can_invite = pending_count < USER_INVITE_LIMIT

        inv_html = ""
        for inv_identity, created_at, used_at in inv_rows:
            inv_email = inv_identity.removeprefix("google:")
            ts = time.strftime("%Y-%m-%d", time.gmtime(created_at / NS))
            if used_at:
                status = '<span class=ok>✓ accepted</span>'
                del_btn = ""
            else:
                status = '<span style="color:#888">pending</span>'
                del_btn = (
                    f'<form method=post action=/invite/friend/delete style="margin:0">'
                    f'<input type=hidden name=s value="{s}">'
                    f'<input type=hidden name=google_identity value="{inv_identity}">'
                    f'<button type=submit class=del-btn title="Delete">🗑</button>'
                    f'</form>'
                )
            inv_html += (
                f'<div class=row>'
                f'<span class=main>{inv_email} {status}</span>'
                f'<span class=sub>{ts}</span>'
                f'{del_btn}'
                f'</div>'
            )
        if not inv_html:
            inv_html = '<p class=empty>You haven\'t invited anyone yet.</p>'

        invite_form = ""
        if can_invite:
            invite_form = f"""
  <form method=post action="/invite/friend/add?s={s}">
    <label>Friend's Google email</label>
    <input name=google_identity placeholder="friend@example.com" required autocomplete=off>
    <button type=submit class=btn>Invite Friend</button>
  </form>
  <p class=meta>{USER_INVITE_LIMIT - pending_count} invite slot{'s' if USER_INVITE_LIMIT - pending_count != 1 else ''} remaining</p>"""
        else:
            invite_form = f'<p class=err>You have reached the limit of {USER_INVITE_LIMIT} pending invitations.</p>'

        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>Invite a Friend — contacc</title><style>{_CSS}</style></head><body>
<div class=card>
  <h2>Invite a Friend</h2>
  <p class=meta>Signed in as {email}</p>
  <p class=node-url>{node_url}</p>
  {invite_form}
  <div class=section>
    <h2>Your Invitations</h2>
    <div class=list>{inv_html}</div>
  </div>
</div></body></html>"""

    @app.get("/invite/friend", response_class=HTMLResponse)
    def invite_friend(s: str = ""):
        identity = _check_user_session(s) if s else None
        if not identity:
            return_to = provider_url + "/invite/friend/verify"
            return RedirectResponse(
                f"{registry_url}/auth/start?return_to={quote(return_to, safe='')}", 302
            )
        return HTMLResponse(_user_invite_page(s, identity))

    @app.get("/invite/friend/verify")
    def invite_friend_verify(proxy_token: str = ""):
        if not proxy_token:
            return RedirectResponse("/invite/friend", 302)
        data = _verify_proxy_token(proxy_token)
        identity = data.get("identity", "")
        node_url = _claimed_node(identity)
        if not node_url:
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>No node found</h2>"
                f"<p>No node registered for <b>{identity.removeprefix('google:')}</b>.</p>"
                "<p>You need to set up your node before you can invite friends.</p></div>", 403
            )
        log.info("User invite page accessed: %s", identity)
        session = _new_user_session(identity)
        return RedirectResponse(f"/invite/friend?s={session}", 302)

    @app.post("/invite/friend/add")
    async def invite_friend_add(request: Request, s: str = ""):
        identity = _check_user_session(s)
        if not identity:
            return RedirectResponse("/invite/friend", 302)
        if not _claimed_node(identity):
            return RedirectResponse("/invite/friend", 302)

        # Enforce invite limit
        pending_count = con.execute(
            "SELECT count(*) FROM invitations WHERE created_by = ? AND used_at IS NULL",
            (identity,)
        ).fetchone()[0]
        if pending_count >= USER_INVITE_LIMIT:
            return RedirectResponse(f"/invite/friend?s={s}", 302)

        form = await request.form()
        invitee = form.get("google_identity", "").strip()
        if invitee:
            if not invitee.startswith("google:"):
                invitee = "google:" + invitee
            con.execute(
                "INSERT OR REPLACE INTO invitations(google_identity, created_at, created_by)"
                " VALUES (?, ?, ?)",
                (invitee, time.time_ns(), identity)
            )
            con.commit()
            log.info("User %s created invitation for %s", identity, invitee)
        return RedirectResponse(f"/invite/friend?s={s}", 302)

    @app.post("/invite/friend/delete")
    async def invite_friend_delete(request: Request):
        form = await request.form()
        s = form.get("s", "")
        identity = _check_user_session(s)
        if not identity:
            return RedirectResponse("/invite/friend", 302)
        invitee = form.get("google_identity", "")
        if invitee:
            # Only delete invitations this user created and that are still pending
            con.execute(
                "DELETE FROM invitations WHERE google_identity = ?"
                " AND created_by = ? AND used_at IS NULL",
                (invitee, identity)
            )
            con.commit()
            log.info("User %s deleted invitation for %s", identity, invitee)
        return RedirectResponse(f"/invite/friend?s={s}", 302)

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

        # Block if already has a node
        existing = _claimed_node(identity)
        if existing:
            log.info("Duplicate node attempt blocked: %s (already has %s)", identity, existing)
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>Already registered</h2>"
                f"<p><b>{identity.removeprefix('google:')}</b> already has a node at "
                f"<a href='{existing}'>{existing}</a>.</p>"
                "<p>Each Google account may only have one node.</p></div>", 409
            )

        inv = con.execute(
            "SELECT pending_at, pending_node_url, pending_setup_token, used_at"
            " FROM invitations WHERE google_identity = ?",
            (identity,)
        ).fetchone()

        if not inv:
            log.warning("Invitation not found for: %s", identity)
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>No invitation found</h2>"
                f"<p>No invitation for <b>{identity.removeprefix('google:')}</b>.</p>"
                "<p>Please ask for an invite link at "
                f"<a href='{provider_url}/accept_invitation'>{provider_url}/accept_invitation</a>.</p>"
                "</div>", 403
            )

        pending_at, pending_node_url, pending_setup_token, used_at = inv

        if used_at:
            log.info("Invitation already used: %s", identity)
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>Already registered</h2>"
                "<p>This invitation has already been used.</p></div>", 409
            )

        if pending_node_url:
            log.info("Returning mid-setup invitee to node: %s → %s", identity, pending_node_url)
            sep = "&" if "?" in pending_node_url else "?"
            return RedirectResponse(f"{pending_node_url}{sep}setup_token={pending_setup_token}", 302)

        node_row = con.execute(
            "SELECT node_id, node_url, setup_token FROM available_nodes ORDER BY added_at LIMIT 1"
        ).fetchone()
        if not node_row:
            log.warning("No nodes available for invitee: %s", identity)
            return HTMLResponse(
                f"<style>{_CSS}</style><div class=card>"
                "<h2>No nodes available</h2>"
                "<p>All instances are currently claimed. Please try again later.</p></div>", 503
            )

        node_id, node_url, setup_token = node_row
        log.info("Assigned node to invitee: %s → %s", identity, node_url)
        con.execute(
            "UPDATE invitations SET pending_at=?, pending_node_url=?, pending_setup_token=?"
            " WHERE google_identity = ?",
            (time.time_ns(), node_url, setup_token, identity)
        )
        con.execute("DELETE FROM available_nodes WHERE node_id = ?", (node_id,))
        con.commit()

        sep = "&" if "?" in node_url else "?"
        return RedirectResponse(f"{node_url}{sep}setup_token={setup_token}", 302)

    return app


def main() -> None:
    import argparse
    import uvicorn
    from logging.handlers import RotatingFileHandler

    parser = argparse.ArgumentParser(description="Run the contacc provider")
    parser.add_argument("db", help="Path to provider SQLite database")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9520)
    args = parser.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    log_path = Path(args.db).parent / "provider.log"
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=4)
    file_handler.setFormatter(fmt)
    logging.getLogger().addHandler(file_handler)

    uvicorn.run(create_app(args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()

"""Emoji reactions on posts and comments."""
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import FederatedSigDep, OptionalAuthDep
from .db import now_ns

router = APIRouter()

ALLOWED_EMOJI = None  # any emoji allowed


async def _reactor(identity, request: Request) -> str | None:
    """Return reactor identity: '' for owner, node_id for federated, None if unidentifiable."""
    if identity.is_owner:
        return ""
    pub_key_header = request.headers.get("X-Public-Key", "")
    if not pub_key_header:
        return None
    db = request.app.state.db
    row = db.execute("SELECT node_id, server_url FROM users WHERE public_key = ?", (pub_key_header,)).fetchone()
    if not row:
        return None
    node_id, server_url = row
    if node_id:
        return node_id
    # Known contact but node_id not yet stored — fetch it on the fly.
    origin = server_url or request.headers.get("X-Origin-Server", "")
    if origin:
        try:
            import httpx as _httpx
            nr = await _httpx.AsyncClient().get(origin.rstrip("/") + "/node", timeout=3.0)
            if nr.is_success:
                nid = nr.json().get("node_id") or nr.json().get("user_id")
                if nid:
                    db.execute("UPDATE users SET node_id = ? WHERE public_key = ?", (nid, pub_key_header))
                    db.commit()
                    return nid
        except Exception:
            pass
    return None


def get_reactions(db, post_id: str, comment_id: str, viewer: str) -> list[dict]:
    """Return reactions for a post or comment, annotated with whether viewer reacted."""
    rows = db.execute(
        """SELECT emoji, reactor_identity FROM reactions
           WHERE post_id = ? AND comment_id = ?
           ORDER BY created_at""",
        (post_id, comment_id),
    ).fetchall()
    by_emoji: dict[str, list[str]] = {}
    for emoji, identity in rows:
        by_emoji.setdefault(emoji, []).append(identity)
    result = []
    for emoji, identities in by_emoji.items():
        result.append({
            "emoji": emoji,
            "count": len(identities),
            "reacted": viewer in identities,
            "reactors": identities,
        })
    result.sort(key=lambda x: (-x["count"], x["emoji"]))
    return result


class _ReactBody(BaseModel):
    emoji: str
    comment_id: str = ""


@router.post("/posts/{post_id}/react", status_code=200)
async def toggle_reaction(post_id: str, payload: _ReactBody, request: Request, identity: OptionalAuthDep, _sig: FederatedSigDep = None):
    if not payload.emoji:
        raise HTTPException(status_code=422, detail="emoji is required")

    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")

reactor = await _reactor(identity, request)
    if reactor is None:
        raise HTTPException(status_code=401, detail="Reactions require an authenticated identity")
    existing = db.execute(
        "SELECT id FROM reactions WHERE post_id = ? AND comment_id = ? AND emoji = ? AND reactor_identity = ?",
        (post_id, payload.comment_id, payload.emoji, reactor),
    ).fetchone()

    if existing:
        db.execute("DELETE FROM reactions WHERE id = ?", (existing[0],))
        reacted = False
    else:
        db.execute(
            "INSERT INTO reactions (post_id, comment_id, emoji, reactor_identity, created_at) VALUES (?, ?, ?, ?, ?)",
            (post_id, payload.comment_id, payload.emoji, reactor, now_ns()),
        )
        reacted = True
    db.commit()

    if reacted and not identity.is_owner:
        _pub = request.headers.get("X-Public-Key", "")
        _actor = None
        if _pub:
            _row = db.execute("SELECT name FROM users WHERE public_key = ?", (_pub,)).fetchone()
            _actor = _row[0] if _row else None
        elif identity.node_id:
            _row = db.execute("SELECT name FROM users WHERE node_id = ?", (identity.node_id,)).fetchone()
            _actor = _row[0] if _row else None
        import hashlib as _hl
        _nid = _hl.sha256(f"reaction:{post_id}:{reactor}:{payload.emoji}".encode()).hexdigest()[:36]
        db.execute(
            "INSERT OR IGNORE INTO mention_notifications "
            "(id, post_id, author_node_id, author_handle, received_at, notif_type, actor_name, emoji) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (_nid, post_id, reactor, '', now_ns(), 'reaction', _actor, payload.emoji)
        )
        db.commit()

    result = {"reactions": get_reactions(db, post_id, payload.comment_id, reactor), "reacted": reacted}
    from .posts import _push_post_update
    _push_post_update(post_id, "reaction", {"comment_id": payload.comment_id or "", "reactions": result["reactions"]}, request.app)
    return result

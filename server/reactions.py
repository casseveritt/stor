"""Emoji reactions on posts and comments."""
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import OptionalAuthDep

router = APIRouter()

ALLOWED_EMOJI = {"👍", "👎", "❤️", "😄", "😮", "😢", "🎉"}


def _reactor(identity, request: Request) -> str:
    """Return a non-null reactor identity string: '' for owner, public key for federated, '<anon>' otherwise."""
    if identity.is_owner:
        return ""
    origin = request.headers.get("X-Origin-Server", "")
    if origin:
        db = request.app.state.db
        row = db.execute("SELECT public_key FROM contacts WHERE server_url = ?", (origin,)).fetchone()
        if row and row[0]:
            return row[0]
    return "<anon>"


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
def toggle_reaction(post_id: str, payload: _ReactBody, request: Request, identity: OptionalAuthDep):
    if payload.emoji not in ALLOWED_EMOJI:
        raise HTTPException(status_code=422, detail=f"Emoji must be one of {sorted(ALLOWED_EMOJI)}")

    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")

    if payload.comment_id:
        if db.execute(
            "SELECT id FROM comments WHERE id = ? AND post_id = ? AND deleted = 0",
            (payload.comment_id, post_id),
        ).fetchone() is None:
            raise HTTPException(status_code=404, detail="Comment not found")

    reactor = _reactor(identity, request)
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
            (post_id, payload.comment_id, payload.emoji, reactor, time.time()),
        )
        reacted = True
    db.commit()

    return {"reactions": get_reactions(db, post_id, payload.comment_id, reactor), "reacted": reacted}

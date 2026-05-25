"""FetchComments, PostComment, RequestCommentEdit endpoints and edit approval."""
import hashlib
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import AuthDep, check_acl
from .access_log import log_access

router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────────────────

def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()


def _row_to_comment(row) -> dict:
    id_, content_hash, asset_id, parent_id, author_id, body, created_at, pred, succ, deleted, author_identity = row
    return {
        "id": id_,
        "content_hash": content_hash,
        "asset_id": asset_id,
        "parent_id": parent_id,
        "author_recipient_id": author_id,
        "author_identity": author_identity,
        "body": None if deleted else body,
        "deleted": bool(deleted),
        "created_at": created_at,
        "predecessor": pred,
        "successor": succ,
    }


def _require_asset_acl(db, asset_id: str, identity) -> None:
    if db.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not check_acl(db, asset_id, identity):
        raise HTTPException(status_code=403, detail="Access denied")


# ── endpoints ─────────────────────────────────────────────────────────────────

@router.get("/assets/{asset_id}/comments")
def fetch_comments(asset_id: str, request: Request, identity: AuthDep):
    db = request.app.state.db
    _require_asset_acl(db, asset_id, identity)
    rows = db.execute(
        """SELECT c.id, c.content_hash, c.asset_id, c.parent_id, c.author_recipient_id,
                  c.body, c.created_at, c.predecessor, c.successor, c.deleted,
                  r.identity AS author_identity
           FROM comments c
           LEFT JOIN recipients r ON r.id = c.author_recipient_id
           WHERE c.asset_id = ? ORDER BY c.created_at ASC""",
        (asset_id,),
    ).fetchall()
    log_access(db, asset_id, identity, "fetch_comments")
    return {"asset_id": asset_id, "comments": [_row_to_comment(r) for r in rows]}


class _PostCommentBody(BaseModel):
    body: str
    parent_id: str | None = None


@router.post("/assets/{asset_id}/comments", status_code=201)
def post_comment(asset_id: str, payload: _PostCommentBody, request: Request, identity: AuthDep):
    db = request.app.state.db
    _require_asset_acl(db, asset_id, identity)

    if payload.parent_id:
        parent = db.execute(
            "SELECT id FROM comments WHERE id = ? AND asset_id = ?",
            (payload.parent_id, asset_id),
        ).fetchone()
        if parent is None:
            raise HTTPException(status_code=404, detail="Parent comment not found")

    comment_id = str(uuid.uuid4())
    content_hash = _body_hash(payload.body)
    now = time.time()
    author_id = identity.recipient_id  # None when owner

    db.execute(
        """INSERT INTO comments
             (id, content_hash, asset_id, parent_id, author_recipient_id,
              body, created_at, predecessor, successor, deleted)
           VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)""",
        (comment_id, content_hash, asset_id, payload.parent_id, author_id, payload.body, now),
    )
    db.commit()

    author_identity = None
    if author_id is not None:
        row = db.execute("SELECT identity FROM recipients WHERE id = ?", (author_id,)).fetchone()
        if row:
            author_identity = row[0]

    return {
        "id": comment_id,
        "content_hash": content_hash,
        "asset_id": asset_id,
        "parent_id": payload.parent_id,
        "author_recipient_id": author_id,
        "author_identity": author_identity,
        "body": payload.body,
        "deleted": False,
        "created_at": now,
        "predecessor": None,
        "successor": None,
    }


class _RequestEditBody(BaseModel):
    new_body: str | None = None  # None = deletion request


@router.post("/assets/{asset_id}/comments/{comment_id}/edit_request", status_code=202)
def request_comment_edit(
    asset_id: str,
    comment_id: str,
    payload: _RequestEditBody,
    request: Request,
    identity: AuthDep,
):
    db = request.app.state.db
    _require_asset_acl(db, asset_id, identity)

    row = db.execute(
        "SELECT author_recipient_id FROM comments WHERE id = ? AND asset_id = ? AND deleted = 0",
        (comment_id, asset_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    author_id = row[0]
    caller_is_author = (identity.is_owner and author_id is None) or (
        not identity.is_owner and identity.recipient_id == author_id
    )
    if not caller_is_author:
        raise HTTPException(status_code=403, detail="Only the original author may request an edit")

    request_id = str(uuid.uuid4())
    db.execute(
        """INSERT INTO comment_edit_requests
             (id, comment_id, requester_recipient_id, new_body, created_at, status)
           VALUES (?, ?, ?, ?, ?, 'pending')""",
        (request_id, comment_id, identity.recipient_id, payload.new_body, time.time()),
    )
    db.commit()

    return {"request_id": request_id, "status": "pending"}


# ── owner-side edit approval (called by CLI tools) ────────────────────────────

def approve_edit(db, request_id: str) -> dict:
    req = db.execute(
        "SELECT comment_id, new_body, status FROM comment_edit_requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if req is None:
        raise ValueError("Edit request not found")
    comment_id, new_body, status = req
    if status != "pending":
        raise ValueError(f"Request is already {status}")

    old = db.execute(
        "SELECT asset_id, parent_id, author_recipient_id FROM comments WHERE id = ?",
        (comment_id,),
    ).fetchone()
    if old is None:
        raise ValueError("Comment not found")
    asset_id, parent_id, author_id = old

    if new_body is None:
        db.execute("UPDATE comments SET deleted = 1 WHERE id = ?", (comment_id,))
    else:
        new_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO comments
                 (id, content_hash, asset_id, parent_id, author_recipient_id,
                  body, created_at, predecessor, successor, deleted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)""",
            (new_id, _body_hash(new_body), asset_id, parent_id, author_id,
             new_body, time.time(), comment_id),
        )
        db.execute("UPDATE comments SET successor = ? WHERE id = ?", (new_id, comment_id))

    db.execute(
        "UPDATE comment_edit_requests SET status = 'approved' WHERE id = ?", (request_id,)
    )
    db.commit()
    return {"request_id": request_id, "status": "approved"}


def reject_edit(db, request_id: str) -> dict:
    cur = db.execute(
        "UPDATE comment_edit_requests SET status = 'rejected' WHERE id = ? AND status = 'pending'",
        (request_id,),
    )
    db.commit()
    if cur.rowcount == 0:
        raise ValueError("Request not found or not pending")
    return {"request_id": request_id, "status": "rejected"}

"""Recipient, identity-mapping, and token management endpoints (owner only)."""
import base64
import json
import time
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from .auth import OwnerDep, revoke_token
from .comments import approve_edit, reject_edit

router = APIRouter()


def _decode_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    try:
        padding = "=" * (-len(cursor) % 4)
        return json.loads(base64.urlsafe_b64decode(cursor + padding))
    except Exception:
        return None


def _encode_cursor(rowid: int) -> str:
    return base64.urlsafe_b64encode(json.dumps(rowid).encode()).rstrip(b"=").decode()


# ── recipients ────────────────────────────────────────────────────────────────

def _recipient_dict(row) -> dict:
    id_, identity, display_name = row
    return {"id": id_, "identity": identity, "display_name": display_name}


@router.get("/recipients")
def list_recipients(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        "SELECT id, identity, display_name FROM recipients ORDER BY display_name"
    ).fetchall()
    return {"recipients": [_recipient_dict(r) for r in rows]}


class _CreateRecipientBody(BaseModel):
    identity: str
    display_name: str | None = None


@router.post("/recipients", status_code=201)
def create_recipient(payload: _CreateRecipientBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE identity = ?", (payload.identity,)).fetchone():
        raise HTTPException(status_code=409, detail="Identity already exists")
    recipient_id = str(uuid.uuid4())
    display_name = payload.display_name or payload.identity
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, payload.identity, display_name),
    )
    db.commit()
    return {"id": recipient_id, "identity": payload.identity, "display_name": display_name}


@router.get("/recipients/{recipient_id}")
def get_recipient(recipient_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, identity, display_name FROM recipients WHERE id = ?", (recipient_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    return _recipient_dict(row)


@router.delete("/recipients/{recipient_id}", status_code=204)
def delete_recipient(recipient_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE id = ?", (recipient_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    db.execute("DELETE FROM acl WHERE recipient_id = ?", (recipient_id,))
    db.execute("DELETE FROM identity_mappings WHERE recipient_id = ?", (recipient_id,))
    db.execute("UPDATE tokens SET revoked = 1 WHERE recipient_id = ?", (recipient_id,))
    db.execute("DELETE FROM recipients WHERE id = ?", (recipient_id,))
    db.commit()


# ── identity mappings ─────────────────────────────────────────────────────────

class _SetMappingBody(BaseModel):
    recipient_id: str


@router.post("/identity-mappings", status_code=201)
def set_identity_mapping(payload: _SetMappingBody, request: Request, identity: OwnerDep,
                         mapped_identity: str = Query(..., alias="identity")):
    db = request.app.state.db
    if db.execute("SELECT id FROM recipients WHERE id = ?", (payload.recipient_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    db.execute(
        "INSERT OR REPLACE INTO identity_mappings (identity, recipient_id) VALUES (?, ?)",
        (mapped_identity, payload.recipient_id),
    )
    db.commit()
    return {"identity": mapped_identity, "recipient_id": payload.recipient_id}


@router.delete("/identity-mappings", status_code=204)
def delete_identity_mapping(request: Request, identity: OwnerDep,
                             mapped_identity: str = Query(..., alias="identity")):
    db = request.app.state.db
    cur = db.execute("DELETE FROM identity_mappings WHERE identity = ?", (mapped_identity,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Mapping not found")


# ── tokens ────────────────────────────────────────────────────────────────────

@router.get("/tokens")
def list_tokens(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        """SELECT t.id, t.recipient_id, t.expiry, r.identity
           FROM tokens t
           LEFT JOIN recipients r ON r.id = t.recipient_id
           WHERE t.revoked = 0 AND t.expiry > ?
           ORDER BY t.expiry DESC""",
        (time.time(),),
    ).fetchall()
    return {
        "tokens": [
            {
                "id": r[0],
                "recipient_id": r[1],
                "expiry": r[2],
                "recipient_identity": r[3],
            }
            for r in rows
        ]
    }


@router.post("/tokens/{token_id}/revoke")
def revoke_token_endpoint(token_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if not revoke_token(db, token_id):
        raise HTTPException(status_code=404, detail="Token not found")
    return {"token_id": token_id, "status": "revoked"}


# ── access log ────────────────────────────────────────────────────────────────

def _access_log_row(row) -> dict:
    id_, asset_id, recipient_id, share_identity, endpoint, accessed_at, rec_identity = row
    return {
        "id": id_,
        "asset_id": asset_id,
        "recipient_id": recipient_id,
        "share_identity": share_identity,
        "recipient_identity": rec_identity,
        "endpoint": endpoint,
        "accessed_at": accessed_at,
    }


@router.get("/access-log")
def get_access_log(
    request: Request,
    identity: OwnerDep,
    asset_id: str | None = Query(default=None),
    recipient_id: str | None = Query(default=None),
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    db = request.app.state.db
    conditions = []
    params: list = []

    if asset_id is not None:
        conditions.append("al.asset_id = ?")
        params.append(asset_id)
    if recipient_id is not None:
        conditions.append("al.recipient_id = ?")
        params.append(recipient_id)
    if since is not None:
        conditions.append("al.accessed_at >= ?")
        params.append(since)
    if until is not None:
        conditions.append("al.accessed_at <= ?")
        params.append(until)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.extend([limit, offset])

    rows = db.execute(
        f"""SELECT al.id, al.asset_id, al.recipient_id, al.share_identity,
                   al.endpoint, al.accessed_at, r.identity AS recipient_identity
            FROM access_log al
            LEFT JOIN recipients r ON r.id = al.recipient_id
            {where}
            ORDER BY al.accessed_at DESC
            LIMIT ? OFFSET ?""",
        params,
    ).fetchall()

    total = db.execute(
        f"SELECT COUNT(*) FROM access_log al {where}", params[:-2]
    ).fetchone()[0]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_access_log_row(r) for r in rows],
    }


@router.get("/assets/{asset_id}/access-log")
def get_asset_access_log(
    asset_id: str,
    request: Request,
    identity: OwnerDep,
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    db = request.app.state.db
    if db.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    conditions = ["al.asset_id = ?"]
    params: list = [asset_id]

    if since is not None:
        conditions.append("al.accessed_at >= ?")
        params.append(since)
    if until is not None:
        conditions.append("al.accessed_at <= ?")
        params.append(until)

    where = "WHERE " + " AND ".join(conditions)
    params.extend([limit, offset])

    rows = db.execute(
        f"""SELECT al.id, al.asset_id, al.recipient_id, al.share_identity,
                   al.endpoint, al.accessed_at, r.identity AS recipient_identity
            FROM access_log al
            LEFT JOIN recipients r ON r.id = al.recipient_id
            {where}
            ORDER BY al.accessed_at DESC
            LIMIT ? OFFSET ?""",
        params,
    ).fetchall()

    total = db.execute(
        f"SELECT COUNT(*) FROM access_log al {where}", params[:-2]
    ).fetchone()[0]

    return {
        "asset_id": asset_id,
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_access_log_row(r) for r in rows],
    }


# ── node statistics ───────────────────────────────────────────────────────────

@router.get("/stats")
def get_stats(request: Request, identity: OwnerDep):
    db = request.app.state.db
    now = time.time()

    asset_total, asset_deleted, asset_size = db.execute(
        "SELECT COUNT(*), SUM(deleted), COALESCE(SUM(CASE WHEN deleted=0 THEN size ELSE 0 END), 0) FROM assets"
    ).fetchone()
    asset_deleted = asset_deleted or 0

    recipient_total = db.execute("SELECT COUNT(*) FROM recipients").fetchone()[0]

    active_tokens = db.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expiry > ?", (now,)
    ).fetchone()[0]

    comment_total, comment_deleted = db.execute(
        "SELECT COUNT(*), SUM(deleted) FROM comments"
    ).fetchone()
    comment_deleted = comment_deleted or 0

    access_log_total = db.execute("SELECT COUNT(*) FROM access_log").fetchone()[0]

    return {
        "assets": {
            "total": asset_total,
            "active": asset_total - asset_deleted,
            "deleted": asset_deleted,
            "total_size_bytes": asset_size,
        },
        "recipients": {"total": recipient_total},
        "tokens": {"active": active_tokens},
        "comments": {
            "total": comment_total,
            "active": comment_total - comment_deleted,
            "deleted": comment_deleted,
        },
        "access_log": {"total": access_log_total},
    }


# ── per-recipient analytics ───────────────────────────────────────────────────

@router.get("/recipients/{recipient_id}/stats")
def get_recipient_stats(recipient_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, identity, display_name FROM recipients WHERE id = ?", (recipient_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    _, rec_identity, display_name = row

    acl_count = db.execute(
        "SELECT COUNT(*) FROM acl WHERE recipient_id = ?", (recipient_id,)
    ).fetchone()[0]

    active_tokens = db.execute(
        "SELECT COUNT(*) FROM tokens WHERE recipient_id = ? AND revoked = 0 AND expiry > ?",
        (recipient_id, time.time()),
    ).fetchone()[0]

    access_row = db.execute(
        """SELECT COUNT(*), MAX(accessed_at),
                  COUNT(DISTINCT asset_id)
           FROM access_log WHERE recipient_id = ?""",
        (recipient_id,),
    ).fetchone()
    total_accesses, last_accessed_at, unique_assets = access_row
    total_accesses = total_accesses or 0
    unique_assets = unique_assets or 0

    by_endpoint = {}
    for ep_row in db.execute(
        "SELECT endpoint, COUNT(*) FROM access_log WHERE recipient_id = ? GROUP BY endpoint",
        (recipient_id,),
    ).fetchall():
        by_endpoint[ep_row[0]] = ep_row[1]

    return {
        "recipient_id": recipient_id,
        "identity": rec_identity,
        "display_name": display_name,
        "acl": {"asset_count": acl_count},
        "tokens": {"active": active_tokens},
        "access": {
            "total": total_accesses,
            "last_accessed_at": last_accessed_at,
            "unique_assets_accessed": unique_assets,
            "by_endpoint": by_endpoint,
        },
    }


# ── edit request management ───────────────────────────────────────────────────

def _edit_request_row(row) -> dict:
    req_id, comment_id, asset_id, orig_body, new_body, status, created_at, req_rid, req_identity = row
    return {
        "id": req_id,
        "comment_id": comment_id,
        "asset_id": asset_id,
        "original_body": orig_body,
        "new_body": new_body,
        "action": "delete" if new_body is None else "edit",
        "status": status,
        "created_at": created_at,
        "requester_recipient_id": req_rid,
        "requester_identity": req_identity,
    }


@router.get("/edit-requests")
def list_edit_requests(
    request: Request,
    identity: OwnerDep,
    status: str = Query(default="pending"),
    asset_id: str | None = Query(default=None),
):
    db = request.app.state.db
    conditions = ["r.status = ?"]
    params: list = [status]
    if asset_id is not None:
        conditions.append("c.asset_id = ?")
        params.append(asset_id)

    where = "WHERE " + " AND ".join(conditions)
    rows = db.execute(
        f"""SELECT r.id, r.comment_id, c.asset_id, c.body AS original_body,
                   r.new_body, r.status, r.created_at,
                   r.requester_recipient_id, rec.identity AS requester_identity
            FROM comment_edit_requests r
            JOIN comments c ON c.id = r.comment_id
            LEFT JOIN recipients rec ON rec.id = r.requester_recipient_id
            {where}
            ORDER BY r.created_at ASC""",
        params,
    ).fetchall()
    return {"status": status, "requests": [_edit_request_row(r) for r in rows]}


@router.post("/edit-requests/{request_id}/approve")
def approve_edit_endpoint(request_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    try:
        return approve_edit(db, request_id)
    except ValueError as e:
        raise HTTPException(status_code=404 if "not found" in str(e).lower() else 409, detail=str(e))


@router.post("/edit-requests/{request_id}/reject")
def reject_edit_endpoint(request_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    try:
        return reject_edit(db, request_id)
    except ValueError as e:
        raise HTTPException(status_code=404 if "not found" in str(e).lower() else 409, detail=str(e))


# ── tag enumeration ───────────────────────────────────────────────────────────

@router.get("/tags")
def list_tags(request: Request, identity: OwnerDep):
    db = request.app.state.db
    rows = db.execute(
        """SELECT je.value AS tag, COUNT(*) AS count
           FROM assets a, json_each(a.tags) je
           WHERE a.deleted = 0
           GROUP BY je.value
           ORDER BY count DESC, je.value ASC"""
    ).fetchall()
    return {"tags": [{"tag": r[0], "count": r[1]} for r in rows]}


# ── recipient feed preview ────────────────────────────────────────────────────

@router.get("/recipients/{recipient_id}/feed")
def get_recipient_feed(
    recipient_id: str,
    request: Request,
    identity: OwnerDep,
    since: float | None = Query(default=None),
    until: float | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    include_superseded: bool = Query(default=False),
):
    db = request.app.state.db
    row = db.execute(
        "SELECT id, identity FROM recipients WHERE id = ?", (recipient_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    _, rec_identity = row

    until_ts = until if until is not None else time.time()
    conditions = [
        "deleted = 0", "created_at <= ?",
        "EXISTS (SELECT 1 FROM acl WHERE asset_id = assets.id AND recipient_id = ?)",
    ]
    params: list = [until_ts, recipient_id]

    if since is not None:
        conditions.append("created_at >= ?")
        params.append(since)
    if not include_superseded:
        conditions.append("successor IS NULL")

    last_rowid = _decode_cursor(cursor)
    if last_rowid is not None:
        conditions.append("rowid < ?")
        params.append(last_rowid)

    params.append(limit + 1)
    where = " AND ".join(conditions)

    rows = db.execute(
        f"""SELECT rowid, id, content_hash, media_type, size, created_at,
                   title, tags, predecessor, successor,
                   (SELECT COUNT(*) FROM comments
                    WHERE comments.asset_id = assets.id
                      AND comments.parent_id IS NULL AND comments.deleted = 0) AS comment_count
            FROM assets WHERE {where}
            ORDER BY rowid DESC LIMIT ?""",
        params,
    ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]

    node_url = str(request.base_url).rstrip("/")
    assets = [
        {
            "id": r[1], "node": node_url, "content_hash": r[2],
            "media_type": r[3], "size": r[4], "created_at": r[5],
            "title": r[6], "tags": json.loads(r[7]) if r[7] else [],
            "predecessor": r[8], "successor": r[9], "comment_count": r[10],
        }
        for r in rows
    ]
    next_cursor = _encode_cursor(rows[-1][0]) if has_more and rows else None

    return {
        "recipient_id": recipient_id,
        "recipient_identity": rec_identity,
        "since": since,
        "until": until_ts,
        "include_superseded": include_superseded,
        "assets": assets,
        **({"next_cursor": next_cursor} if next_cursor else {}),
    }

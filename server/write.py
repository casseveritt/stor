"""Write operations: PublishAsset, UpdateMetadata, UpdateACL, IssueShareToken."""
import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from .auth import OwnerDep, issue_share_token
from .crypto import encrypt_bytes

router = APIRouter()


# ── publish asset ─────────────────────────────────────────────────────────────

@router.post("/assets", status_code=201)
async def publish_asset(
    request: Request,
    identity: OwnerDep,
    file: UploadFile = File(...),
    title: str | None = Form(default=None),
    tags: str = Form(default="[]"),
    predecessor: str | None = Form(default=None),
    acl: str = Form(default="[]"),
):
    content = await file.read()
    media_type = file.content_type or "application/octet-stream"

    content_hash = hashlib.sha256(content).hexdigest()

    try:
        tags_list = json.loads(tags)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="tags must be a JSON array")

    try:
        acl_list = json.loads(acl)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="acl must be a JSON array")

    db = request.app.state.db

    if predecessor is not None:
        if db.execute("SELECT id FROM assets WHERE id = ?", (predecessor,)).fetchone() is None:
            raise HTTPException(status_code=404, detail="Predecessor asset not found")

    for recipient_id in acl_list:
        if db.execute("SELECT id FROM recipients WHERE id = ?", (recipient_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail=f"Recipient {recipient_id} not found")

    store_path: Path = request.app.state.store_path
    file_dir = store_path / "files" / content_hash[:2]
    file_dir.mkdir(parents=True, exist_ok=True)
    file_path = file_dir / content_hash
    if not file_path.exists():
        file_key = request.app.state.file_key
        file_path.write_bytes(encrypt_bytes(content, file_key))

    asset_id = str(uuid.uuid4())
    now = time.time()

    db.execute(
        """INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags, predecessor, successor)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
        (asset_id, content_hash, media_type, len(content), now,
         title, json.dumps(tags_list), predecessor),
    )
    if predecessor is not None:
        db.execute("UPDATE assets SET successor = ? WHERE id = ?", (asset_id, predecessor))
    for recipient_id in acl_list:
        db.execute("INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)", (asset_id, recipient_id))
    db.commit()

    return {
        "id": asset_id,
        "content_hash": content_hash,
        "media_type": media_type,
        "size": len(content),
        "created_at": now,
        "title": title,
        "tags": tags_list,
        "predecessor": predecessor,
        "successor": None,
        "comment_count": 0,
    }


# ── update metadata ───────────────────────────────────────────────────────────

class _UpdateMetaBody(BaseModel):
    title: str | None = None
    tags: list[str] | None = None


@router.patch("/assets/{asset_id}")
def update_metadata(asset_id: str, payload: _UpdateMetaBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = db.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    updates = []
    params = []
    if payload.title is not None or "title" in payload.model_fields_set:
        updates.append("title = ?")
        params.append(payload.title)
    if payload.tags is not None:
        updates.append("tags = ?")
        params.append(json.dumps(payload.tags))

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    params.append(asset_id)
    db.execute(f"UPDATE assets SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()

    row = db.execute(
        """SELECT id, content_hash, media_type, size, created_at, title, tags, predecessor, successor,
                  (SELECT COUNT(*) FROM comments
                   WHERE comments.asset_id = assets.id
                     AND comments.parent_id IS NULL AND comments.deleted = 0) AS comment_count
           FROM assets WHERE id = ?""",
        (asset_id,),
    ).fetchone()
    id_, content_hash, media_type, size, created_at, title, tags_json, pred, succ, comment_count = row
    return {
        "id": id_,
        "content_hash": content_hash,
        "media_type": media_type,
        "size": size,
        "created_at": created_at,
        "title": title,
        "tags": json.loads(tags_json) if tags_json else [],
        "predecessor": pred,
        "successor": succ,
        "comment_count": comment_count,
    }


# ── update ACL ────────────────────────────────────────────────────────────────

class _UpdateACLBody(BaseModel):
    add: list[str] = []
    remove: list[str] = []


@router.put("/assets/{asset_id}/acl")
def update_acl(asset_id: str, payload: _UpdateACLBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    for recipient_id in payload.add:
        if db.execute("SELECT id FROM recipients WHERE id = ?", (recipient_id,)).fetchone() is None:
            raise HTTPException(status_code=404, detail=f"Recipient {recipient_id} not found")
        db.execute(
            "INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)",
            (asset_id, recipient_id),
        )

    for recipient_id in payload.remove:
        db.execute(
            "DELETE FROM acl WHERE asset_id = ? AND recipient_id = ?",
            (asset_id, recipient_id),
        )

    db.commit()

    rows = db.execute(
        "SELECT recipient_id FROM acl WHERE asset_id = ?", (asset_id,)
    ).fetchall()
    return {"asset_id": asset_id, "recipients": [r[0] for r in rows]}


# ── read ACL ─────────────────────────────────────────────────────────────────

@router.get("/assets/{asset_id}/acl")
def get_acl(asset_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM assets WHERE id = ? AND deleted = 0", (asset_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    rows = db.execute(
        """SELECT r.id, r.identity, r.display_name
           FROM acl a JOIN recipients r ON r.id = a.recipient_id
           WHERE a.asset_id = ?
           ORDER BY r.display_name""",
        (asset_id,),
    ).fetchall()
    return {
        "asset_id": asset_id,
        "recipients": [
            {"id": r[0], "identity": r[1], "display_name": r[2]} for r in rows
        ],
    }


# ── delete asset ──────────────────────────────────────────────────────────────

@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    cur = db.execute(
        "UPDATE assets SET deleted = 1 WHERE id = ? AND deleted = 0", (asset_id,)
    )
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Asset not found")


# ── issue share token ─────────────────────────────────────────────────────────

class _IssueShareTokenBody(BaseModel):
    identity: str
    asset_ids: list[str] | None = None  # None = node-wide
    ttl_seconds: int = 86400 * 30


@router.post("/share-tokens", status_code=201)
def issue_share_token_endpoint(
    payload: _IssueShareTokenBody,
    request: Request,
    identity: OwnerDep,
):
    db = request.app.state.db
    if payload.asset_ids is not None:
        for asset_id in payload.asset_ids:
            if db.execute("SELECT id FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
                raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")

    token = issue_share_token(payload.identity, payload.asset_ids, payload.ttl_seconds)
    return {"token": token, "identity": payload.identity, "asset_ids": payload.asset_ids}

"""Post CRUD: create posts with optional inline media attachments."""
import hashlib
import json
import re
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel

from .auth import AuthDep, OptionalAuthDep, OwnerDep
from .crypto import encrypt_bytes

router = APIRouter()

_ASSET_REF = re.compile(r"\[asset:([0-9a-f-]+)\]")


def _asset_ids_in_order(body: str) -> list[str]:
    """Return asset UUIDs referenced in body, in order of first appearance."""
    seen: set[str] = set()
    result = []
    for m in _ASSET_REF.finditer(body):
        aid = m.group(1)
        if aid not in seen:
            seen.add(aid)
            result.append(aid)
    return result


def _store_file(request: Request, content: bytes) -> str:
    content_hash = hashlib.sha256(content).hexdigest()
    store_path: Path = request.app.state.store_path
    file_dir = store_path / "files" / content_hash[:2]
    file_dir.mkdir(parents=True, exist_ok=True)
    file_path = file_dir / content_hash
    if not file_path.exists():
        file_path.write_bytes(encrypt_bytes(content, request.app.state.file_key))
    return content_hash


def _get_post_assets(db, post_id: str, body: str) -> list[dict]:
    asset_ids = _asset_ids_in_order(body)
    if not asset_ids:
        return []
    placeholders = ",".join("?" * len(asset_ids))
    rows = db.execute(
        f"""SELECT a.id, a.media_type, a.size, a.title
            FROM assets a
            WHERE a.id IN ({placeholders}) AND a.deleted = 0""",
        asset_ids,
    ).fetchall()
    by_id = {r[0]: {"id": r[0], "media_type": r[1], "size": r[2], "title": r[3]} for r in rows}
    return [by_id[aid] for aid in asset_ids if aid in by_id]


def _comment_count(db, post_id: str) -> int:
    row = db.execute(
        "SELECT COUNT(*) FROM comments WHERE post_id = ? AND parent_id IS NULL AND deleted = 0",
        (post_id,),
    ).fetchone()
    return row[0] if row else 0


_VALID_POST_TYPES = {"post", "inner_monologue"}


_POST_COLS = "p.id, p.body, p.created_at, p.tags, p.visibility, p.comment_access, p.deleted, p.post_type"
_POST_COLS_NO_ALIAS = "id, body, created_at, tags, visibility, comment_access, deleted, post_type"

_VALID_VISIBILITY = ("private", "contacts", "authenticated", "public")
_VALID_COMMENT_ACCESS = ("contacts", "authenticated", "public")


def _post_dict(row, db, viewer: str = "") -> dict:
    from .reactions import get_reactions
    id_, body, created_at, tags_json, visibility, comment_access, deleted, post_type = row
    assets = _get_post_assets(db, id_, body)
    return {
        "id": id_,
        "body": body,
        "tags": json.loads(tags_json) if tags_json else [],
        "created_at": created_at,
        "visibility": visibility or "private",
        "comment_access": comment_access or "contacts",
        "public": (visibility or "private") == "public",  # backwards compat
        "post_type": post_type or "post",
        "assets": assets,
        "comment_count": _comment_count(db, id_),
        "deleted": bool(deleted),
        "reactions": get_reactions(db, id_, "", viewer),
    }


# ── create post ───────────────────────────────────────────────────────────────

@router.post("/posts", status_code=201)
async def create_post(
    request: Request,
    identity: OwnerDep,
    body: str = Form(default=""),
    tags: str = Form(default="[]"),
    public: str = Form(default=""),        # legacy — ignored if visibility set
    visibility: str = Form(default="contacts"),
    comment_access: str = Form(default="contacts"),
    post_type: str = Form(default="post"),
    files: list[UploadFile] = File(default=[]),
):
    try:
        tags_list = json.loads(tags)
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="tags must be a JSON array")

    if post_type not in _VALID_POST_TYPES:
        raise HTTPException(status_code=422, detail=f"post_type must be one of {_VALID_POST_TYPES}")
    if post_type == "inner_monologue":
        visibility = "private"

    # legacy boolean shim
    if public and visibility == "contacts":
        visibility = "public" if public.lower() in ("true", "1", "yes") else "contacts"
    if visibility not in _VALID_VISIBILITY:
        raise HTTPException(status_code=422, detail=f"visibility must be one of {_VALID_VISIBILITY}")
    if comment_access not in _VALID_COMMENT_ACCESS:
        raise HTTPException(status_code=422, detail=f"comment_access must be one of {_VALID_COMMENT_ACCESS}")

    is_public = visibility == "public"
    db = request.app.state.db
    post_id = str(uuid.uuid4())
    now = time.time()

    # validate any pre-existing asset refs in body
    inline_ids = _asset_ids_in_order(body)
    for aid in inline_ids:
        if db.execute("SELECT id FROM assets WHERE id = ? AND deleted = 0", (aid,)).fetchone() is None:
            raise HTTPException(status_code=422, detail=f"Asset {aid} not found")

    # store uploaded files as assets, append refs to body
    appended = []
    for upload in files:
        content = await upload.read()
        media_type = upload.content_type or "application/octet-stream"
        content_hash = _store_file(request, content)
        asset_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO assets (id, content_hash, media_type, size, created_at,
                                   title, tags, predecessor, successor, deleted)
               VALUES (?, ?, ?, ?, ?, NULL, '[]', NULL, NULL, 0)""",
            (asset_id, content_hash, media_type, len(content), now),
        )
        appended.append(asset_id)

    if appended:
        suffix = "\n" + "\n".join(f"[asset:{aid}]" for aid in appended)
        body = body + suffix

    # record all referenced assets in post_assets
    all_ids = _asset_ids_in_order(body)
    db.execute(
        "INSERT INTO posts (id, body, created_at, tags, is_public, deleted, post_type, visibility, comment_access)"
        " VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
        (post_id, body, now, json.dumps(tags_list), int(is_public), post_type, visibility, comment_access),
    )
    for aid in all_ids:
        db.execute("INSERT OR IGNORE INTO post_assets (post_id, asset_id) VALUES (?, ?)", (post_id, aid))
    for tag in tags_list:
        db.execute("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)", (post_id, tag))
    if is_public and all_ids:
        db.execute(
            f"UPDATE assets SET is_public = 1 WHERE id IN ({','.join('?'*len(all_ids))})", all_ids
        )
    db.commit()

    row = db.execute(
        f"SELECT {_POST_COLS_NO_ALIAS} FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    return _post_dict(row, db)


# ── post feed ─────────────────────────────────────────────────────────────────

@router.get("/posts")
def get_posts(
    request: Request,
    identity: OptionalAuthDep,
    limit: int = Query(default=20, ge=1, le=100),
    cursor: str = Query(default=""),
    tags: list[str] = Query(default=[]),
    q: str = Query(default=""),
    post_type: str = Query(default="post"),
):
    db = request.app.state.db
    params: list = []
    conditions = ["p.deleted = 0"]

    if identity.is_owner:
        if post_type not in _VALID_POST_TYPES:
            raise HTTPException(status_code=422, detail=f"post_type must be one of {_VALID_POST_TYPES}")
        conditions.append("p.post_type = ?")
        params.append(post_type)
    else:
        # non-owners never see inner_monologue regardless of filters
        conditions.append("p.post_type = 'post'")

    if not identity.is_owner:
        origin_server = request.headers.get("X-Origin-Server", "")
        is_contact = bool(origin_server and db.execute(
            "SELECT 1 FROM contacts WHERE server_url = ?", (origin_server,)
        ).fetchone())
        if identity.is_share:
            if identity.share_post_ids is not None:
                placeholders = ",".join("?" * len(identity.share_post_ids))
                conditions.append(f"(p.visibility = 'public' OR p.id IN ({placeholders}))")
                params.extend(identity.share_post_ids)
        elif identity.recipient_id is not None:
            conditions.append(
                "(p.visibility = 'public' OR EXISTS (SELECT 1 FROM post_acl WHERE post_id = p.id AND recipient_id = ?))"
            )
            params.append(identity.recipient_id)
        elif is_contact:
            conditions.append("p.visibility IN ('contacts', 'authenticated', 'public')")
        elif origin_server:
            conditions.append("p.visibility IN ('authenticated', 'public')")
        else:
            conditions.append("p.visibility = 'public'")

    if q:
        from . import node as _node
        handle = _node._registry_handle or ""
        profile_row = db.execute("SELECT display_name FROM profile WHERE id = 1").fetchone()
        display_name = (profile_row[0] or "") if profile_row else ""
        q_lower = q.lower()
        if q_lower in handle.lower() or (display_name and q_lower in display_name.lower()):
            pass  # query matches this node's identity — return all posts unfiltered
        else:
            conditions.append(
                "(p.body LIKE ? OR EXISTS ("
                "  SELECT 1 FROM comments c"
                "  WHERE c.post_id = p.id AND c.body LIKE ? AND c.deleted = 0"
                "))"
            )
            params.extend([f"%{q}%", f"%{q}%"])

    if cursor:
        conditions.append("p.created_at < ?")
        params.append(float(cursor))

    if tags:
        placeholders = ",".join("?" * len(tags))
        conditions.append(
            f"""p.id IN (
                SELECT post_id FROM post_tags
                WHERE tag IN ({placeholders})
                GROUP BY post_id HAVING COUNT(DISTINCT tag) = ?
            )"""
        )
        params.extend(tags)
        params.append(len(tags))

    viewer = "" if identity.is_owner else (request.headers.get("X-Origin-Server", "") or "__anon__")
    where = " AND ".join(conditions)
    rows = db.execute(
        f"SELECT {_POST_COLS} FROM posts p WHERE {where} ORDER BY p.created_at DESC LIMIT ?",
        [*params, limit + 1],
    ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    result: dict = {"posts": [_post_dict(r, db, viewer) for r in rows]}
    if has_more:
        result["next_cursor"] = str(rows[-1][2])
    return result


# ── get / update / delete post ────────────────────────────────────────────────

@router.get("/posts/{post_id}")
def get_post(post_id: str, request: Request, identity: OptionalAuthDep):
    db = request.app.state.db
    row = db.execute(
        f"SELECT {_POST_COLS_NO_ALIAS} FROM posts WHERE id = ? AND deleted = 0", (post_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Post not found")
    visibility, post_type = row[4], row[7]
    if not identity.is_owner:
        origin_server = request.headers.get("X-Origin-Server", "")
        if post_type == "inner_monologue":
            raise HTTPException(status_code=404, detail="Post not found")
        if visibility == "private":
            raise HTTPException(status_code=403, detail="Access denied")
        if visibility in ("contacts", "authenticated"):
            is_contact = bool(origin_server and db.execute(
                "SELECT 1 FROM contacts WHERE server_url = ?", (origin_server,)
            ).fetchone())
            is_authenticated = bool(origin_server)
            passes = is_authenticated if visibility == "authenticated" else is_contact
            if not passes and not _check_post_access(db, post_id, identity):
                raise HTTPException(status_code=403, detail="Access denied")
    viewer = "" if identity.is_owner else (request.headers.get("X-Origin-Server", "") or "__anon__")
    return _post_dict(row, db, viewer)


class _UpdatePostBody(BaseModel):
    body: str | None = None
    tags: list[str] | None = None
    public: bool | None = None             # legacy shim
    visibility: str | None = None
    comment_access: str | None = None


@router.patch("/posts/{post_id}")
def update_post(post_id: str, payload: _UpdatePostBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")

    # legacy shim: map public bool to visibility
    if payload.public is not None and payload.visibility is None:
        payload.visibility = "public" if payload.public else "contacts"

    updates, params = [], []
    if "body" in payload.model_fields_set:
        updates.append("body = ?")
        params.append(payload.body)
    if payload.tags is not None:
        updates.append("tags = ?")
        params.append(json.dumps(payload.tags))
    if payload.visibility is not None:
        if payload.visibility not in _VALID_VISIBILITY:
            raise HTTPException(status_code=422, detail=f"visibility must be one of {_VALID_VISIBILITY}")
        updates.append("visibility = ?")
        updates.append("is_public = ?")
        params.append(payload.visibility)
        params.append(int(payload.visibility == "public"))
    if payload.comment_access is not None:
        if payload.comment_access not in _VALID_COMMENT_ACCESS:
            raise HTTPException(status_code=422, detail=f"comment_access must be one of {_VALID_COMMENT_ACCESS}")
        updates.append("comment_access = ?")
        params.append(payload.comment_access)

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    params.append(post_id)
    db.execute(f"UPDATE posts SET {', '.join(updates)} WHERE id = ?", params)

    if payload.visibility is not None:
        db.execute(
            "UPDATE assets SET is_public = ? WHERE id IN (SELECT asset_id FROM post_assets WHERE post_id = ?)",
            (int(payload.visibility == "public"), post_id),
        )

    if payload.tags is not None:
        db.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
        for tag in payload.tags:
            db.execute("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)", (post_id, tag))

    if "body" in payload.model_fields_set and payload.body is not None:
        db.execute("DELETE FROM post_assets WHERE post_id = ?", (post_id,))
        for aid in _asset_ids_in_order(payload.body):
            if db.execute("SELECT id FROM assets WHERE id = ? AND deleted = 0", (aid,)).fetchone():
                db.execute("INSERT OR IGNORE INTO post_assets (post_id, asset_id) VALUES (?, ?)", (post_id, aid))

    db.commit()
    row = db.execute(
        f"SELECT {_POST_COLS_NO_ALIAS} FROM posts WHERE id = ?", (post_id,)
    ).fetchone()
    return _post_dict(row, db)


@router.delete("/posts/{post_id}", status_code=204)
def delete_post(post_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    cur = db.execute("UPDATE posts SET deleted = 1 WHERE id = ? AND deleted = 0", (post_id,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Post not found")


# ── post comments ─────────────────────────────────────────────────────────────

def _check_post_access(db, post_id: str, identity) -> bool:
    if identity.is_share:
        if identity.share_post_ids is None:
            return True  # node-wide share
        return post_id in identity.share_post_ids
    if identity.recipient_id:
        return db.execute(
            "SELECT 1 FROM post_acl WHERE post_id = ? AND recipient_id = ?", (post_id, identity.recipient_id)
        ).fetchone() is not None
    return False


def _require_post_access(db, post_id: str, identity, origin_server: str | None = None) -> None:
    """Check that the requester can view AND comment on this post."""
    row = db.execute(
        "SELECT visibility, comment_access, post_type FROM posts WHERE id = ? AND deleted = 0", (post_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Post not found")
    visibility, comment_access, post_type = row
    if identity.is_owner:
        return
    if post_type == "inner_monologue":
        raise HTTPException(status_code=404, detail="Post not found")

    is_authenticated = bool(origin_server)
    is_contact = bool(origin_server and _is_known_contact(db, origin_server))
    has_explicit = _check_post_access(db, post_id, identity)

    def _passes(level: str) -> bool:
        if level == "public": return True
        if level == "authenticated": return is_authenticated or has_explicit
        if level == "contacts": return is_contact or has_explicit
        return False  # private

    if not _passes(visibility):
        raise HTTPException(status_code=403, detail="Access denied")
    if not _passes(comment_access):
        raise HTTPException(status_code=403, detail="Comments restricted")


def _is_known_contact(db, server_url: str) -> bool:
    return db.execute(
        "SELECT 1 FROM contacts WHERE server_url = ?", (server_url,)
    ).fetchone() is not None


@router.get("/posts/{post_id}/comments")
def fetch_post_comments(post_id: str, request: Request, identity: OptionalAuthDep):
    from .reactions import get_reactions
    db = request.app.state.db
    _require_post_access(db, post_id, identity, request.headers.get("X-Origin-Server"))
    rows = db.execute(
        """SELECT c.id, c.content_hash, c.post_id, c.parent_id, c.author_recipient_id,
                  c.body, c.created_at, c.predecessor, c.successor, c.deleted,
                  COALESCE(c.author_identity, r.identity)
           FROM comments c
           LEFT JOIN recipients r ON r.id = c.author_recipient_id
           WHERE c.post_id = ? ORDER BY c.created_at ASC""",
        (post_id,),
    ).fetchall()
    viewer = "" if identity.is_owner else (request.headers.get("X-Origin-Server", "") or "__anon__")
    comments = []
    for row in rows:
        id_, ch, pid, parent_id, author_id, body, created_at, pred, succ, deleted, author_identity = row
        comments.append({
            "id": id_, "content_hash": ch, "post_id": pid, "parent_id": parent_id,
            "author_recipient_id": author_id, "author_identity": author_identity,
            "body": None if deleted else body, "deleted": bool(deleted),
            "created_at": created_at, "predecessor": pred, "successor": succ,
            "reactions": get_reactions(db, post_id, id_, viewer),
        })
    return {"post_id": post_id, "comments": comments}


class _CommentBody(BaseModel):
    body: str
    parent_id: str | None = None


@router.post("/posts/{post_id}/comments", status_code=201)
def post_comment(post_id: str, payload: _CommentBody, request: Request, identity: OptionalAuthDep):
    db = request.app.state.db
    origin_server = request.headers.get("X-Origin-Server")
    _require_post_access(db, post_id, identity, origin_server)

    if payload.parent_id:
        if db.execute(
            "SELECT id FROM comments WHERE id = ? AND post_id = ?", (payload.parent_id, post_id)
        ).fetchone() is None:
            raise HTTPException(status_code=404, detail="Parent comment not found")

    comment_id = str(uuid.uuid4())
    content_hash = hashlib.sha256(payload.body.encode()).hexdigest()
    now = time.time()
    author_id = identity.recipient_id

    author_identity = None
    if author_id:
        row = db.execute("SELECT identity FROM recipients WHERE id = ?", (author_id,)).fetchone()
        if row:
            author_identity = row[0]
    elif not identity.is_owner and origin_server:
        row = db.execute("SELECT public_key FROM contacts WHERE server_url = ?", (origin_server,)).fetchone()
        author_identity = row[0] if row and row[0] else origin_server

    db.execute(
        """INSERT INTO comments
             (id, content_hash, asset_id, post_id, parent_id, author_recipient_id,
              author_identity, body, created_at, predecessor, successor, deleted)
           VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, NULL, 0)""",
        (comment_id, content_hash, post_id, payload.parent_id, author_id,
         author_identity, payload.body, now),
    )
    db.commit()

    return {
        "id": comment_id, "content_hash": content_hash,
        "post_id": post_id, "parent_id": payload.parent_id,
        "author_recipient_id": author_id, "author_identity": author_identity,
        "body": payload.body, "deleted": False,
        "created_at": now, "predecessor": None, "successor": None,
    }


# ── post ACL ──────────────────────────────────────────────────────────────────

@router.get("/posts/{post_id}/acl")
def get_post_acl(post_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")
    rows = db.execute(
        """SELECT r.id, r.identity, r.display_name
           FROM post_acl pa JOIN recipients r ON r.id = pa.recipient_id
           WHERE pa.post_id = ?""",
        (post_id,),
    ).fetchall()
    return {"post_id": post_id, "recipients": [
        {"id": r[0], "identity": r[1], "display_name": r[2]} for r in rows
    ]}


class _AclUpdateBody(BaseModel):
    add: list[str] = []
    remove: list[str] = []


@router.patch("/posts/{post_id}/acl")
def update_post_acl(post_id: str, payload: _AclUpdateBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")
    for rid in payload.add:
        if db.execute("SELECT id FROM recipients WHERE id = ?", (rid,)).fetchone() is None:
            raise HTTPException(status_code=404, detail=f"Recipient {rid} not found")
    for rid in payload.add:
        db.execute("INSERT OR IGNORE INTO post_acl (post_id, recipient_id) VALUES (?, ?)", (post_id, rid))
    for rid in payload.remove:
        db.execute("DELETE FROM post_acl WHERE post_id = ? AND recipient_id = ?", (post_id, rid))
    db.commit()
    rows = db.execute(
        """SELECT r.id, r.identity, r.display_name
           FROM post_acl pa JOIN recipients r ON r.id = pa.recipient_id
           WHERE pa.post_id = ?""",
        (post_id,),
    ).fetchall()
    return {"post_id": post_id, "recipients": [
        {"id": r[0], "identity": r[1], "display_name": r[2]} for r in rows
    ]}

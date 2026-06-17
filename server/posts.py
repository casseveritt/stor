"""Post CRUD: create posts with optional inline media attachments."""
import hashlib
import json
import re
import secrets
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel

from .auth import AuthDep, FederatedOrTokenDep, FederatedSigDep, OptionalAuthDep, OwnerDep
from .crypto import encrypt_bytes
from .db import now_ns

router = APIRouter()

_ASSET_REF = re.compile(r"\[asset:([0-9a-f-]+)\]")
_MENTION_RE = re.compile(r"\[([^\|\]]+)\|([^\]]+)\]")

# ── post subscriptions (ephemeral, in-memory) ─────────────────────────────────
# post_id → list of (callback_url, expires_at)
_post_subscriptions: dict[str, list[tuple[str, float]]] = {}
_SUB_MAX_PER_POST = 20
_SUB_MAX_TOTAL = 200


def _sub_cleanup() -> None:
    now = time.time()
    for pid in list(_post_subscriptions):
        _post_subscriptions[pid] = [(u, e) for u, e in _post_subscriptions[pid] if e > now]
        if not _post_subscriptions[pid]:
            del _post_subscriptions[pid]


def _push_post_update(post_id: str, event: str, data: dict, app) -> None:
    """Fire-and-forget push to all active subscribers for a post."""
    import threading
    subs = _post_subscriptions.get(post_id, [])
    if not subs:
        return
    now = time.time()
    active = [(u, e) for u, e in subs if e > now]
    if not active:
        return
    payload = {"post_id": post_id, "event": event, "data": data}

    def _send():
        import httpx as _hx
        for callback_url, _ in active:
            try:
                _hx.post(callback_url, json=payload, timeout=5)
            except Exception:
                pass
    threading.Thread(target=_send, daemon=True).start()


class SubscribeBody(BaseModel):
    callback_url: str
    ttl: int = 300  # seconds, max 600


@router.post("/posts/{post_id}/subscribe", status_code=204)
def subscribe_post(post_id: str, body: SubscribeBody):
    """Register a callback URL to receive updates for this post for TTL seconds."""
    ttl = max(10, min(body.ttl, 600))
    expires = time.time() + ttl
    _sub_cleanup()
    if sum(len(v) for v in _post_subscriptions.values()) >= _SUB_MAX_TOTAL:
        return  # silently drop if too many global subs
    existing = _post_subscriptions.setdefault(post_id, [])
    # replace existing sub for this callback_url, or add new
    existing[:] = [(u, e) for u, e in existing if u != body.callback_url]
    if len(existing) < _SUB_MAX_PER_POST:
        existing.append((body.callback_url, expires))



def _notify_mentions(body: str, post_id: str, app) -> None:
    """Best-effort federated notification to any nodes mentioned in body."""
    import threading
    mentions = _MENTION_RE.findall(body)
    if not mentions:
        return
    config = app.state.config if hasattr(app.state, "config") else None
    node_address = getattr(app.state, "node_address", "") or ""
    own_node_id = getattr(app.state, "node_id", "") or ""
    registry_url = ""
    handle = ""
    if config:
        try:
            from .config import NodeConfig
            cfg = NodeConfig.load(app.state.config_path)
            registry_url = (cfg.registry_url or cfg.identity_proxy_url or "").rstrip("/")
            handle = cfg.registry_handle or ""
        except Exception:
            pass

    def _send():
        import httpx as _hx, time as _t, base64 as _b64, hashlib as _hl, json as _json
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = getattr(app.state, "private_key", None)
        for user_id, _label in mentions:
            try:
                # Look up the mentioned node's server URL via registry
                target_url = None
                if registry_url:
                    r = _hx.get(f"{registry_url}/nodes/{user_id}", timeout=5)
                    if r.is_success:
                        d = r.json()
                        target_url = d.get("web_url") or d.get("server_url")

                if not target_url:
                    continue

                ts = str(int(_t.time()))
                payload = {
                    "post_id": post_id,
                    "author_node_id": own_node_id,
                    "author_handle": handle,
                    "timestamp": int(ts),
                    "post_node_id": own_node_id,
                }
                headers = {"Content-Type": "application/json"}
                if priv:
                    body_bytes = _json.dumps(payload).encode()
                    body_hash = _hl.sha256(body_bytes).hexdigest()
                    canonical = f"POST\n/notifications/mention\n{ts}\n{body_hash}"
                    sig = _b64.b64encode(priv.sign(canonical.encode())).decode()
                    pub_b64 = _b64.b64encode(
                        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                    ).decode()
                    headers.update({"X-Public-Key": pub_b64, "X-Timestamp": ts,
                                    "X-Signature": sig, "X-Origin-Server": node_address})
                _hx.post(f"{target_url.rstrip('/')}/notifications/mention",
                         json=payload, headers=headers, timeout=5)
            except Exception:
                pass

    threading.Thread(target=_send, daemon=True).start()


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
        f"""SELECT a.id, a.media_type, a.size, a.title, a.content_hash, a.successor
            FROM assets a
            WHERE a.id IN ({placeholders}) AND a.deleted = 0""",
        asset_ids,
    ).fetchall()
    by_id = {r[0]: {"id": r[0], "media_type": r[1], "size": r[2], "title": r[3],
                    "content_hash": r[4], "successor": r[5]} for r in rows}
    return [by_id[aid] for aid in asset_ids if aid in by_id]



def _reply_count(db, post_id: str) -> int:
    local = db.execute(
        "SELECT COUNT(*) FROM posts WHERE parent_id = ? AND deleted = 0", (post_id,)
    ).fetchone()[0]
    remote = db.execute(
        "SELECT COUNT(*) FROM reply_refs WHERE parent_post_id = ?", (post_id,)
    ).fetchone()[0]
    return local + remote


_VALID_POST_TYPES = {"post", "inner_monologue"}


_POST_COLS = (
    "p.id, p.body, p.created_at, p.tags, p.visibility, p.deleted, p.post_type, p.nonce,"
    " p.parent_id, p.parent_node_id, p.supersedes, p.visibility_list_id"
)
_POST_COLS_NO_ALIAS = (
    "id, body, created_at, tags, visibility, deleted, post_type, nonce,"
    " parent_id, parent_node_id, supersedes, visibility_list_id"
)

_VALID_VISIBILITY = ("private", "contacts", "authenticated", "public")


def _post_dict(row, db, viewer: str = "") -> dict:
    from .reactions import get_reactions
    (id_, body, created_at, tags_json, visibility, deleted, post_type, nonce,
     parent_id, parent_node_id, supersedes, visibility_list_id) = row
    assets = _get_post_assets(db, id_, body)
    successor_row = db.execute(
        "SELECT id FROM posts WHERE parent_id = ? AND supersedes = '1' AND deleted = 0 LIMIT 1", (id_,)
    ).fetchone()
    return {
        "id": id_,
        "body": body,
        "tags": json.loads(tags_json) if tags_json else [],
        "created_at": created_at,
        "visibility": visibility or "private",
        "public": (visibility or "private") == "public",  # backwards compat
        "post_type": post_type or "post",
        "nonce": nonce,
        "parent_id": parent_id,
        "parent_node_id": parent_node_id,
        "supersedes": bool(supersedes),
        "superseded_by": successor_row[0] if successor_row else None,
        "visibility_list_id": visibility_list_id,
        "assets": assets,
        "reply_count": _reply_count(db, id_),
        "deleted": bool(deleted),
        "reactions": get_reactions(db, id_, "", viewer),
    }


# ── standalone asset upload ───────────────────────────────────────────────────

@router.post("/assets", status_code=201)
async def upload_asset(request: Request, identity: OwnerDep, file: UploadFile = File(...)):
    """Upload a file as a standalone asset and return its ID for use in post bodies."""
    db = request.app.state.db
    content = await file.read()
    media_type = file.content_type or "application/octet-stream"
    content_hash = _store_file(request, content)
    asset_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags, predecessor, successor, deleted)"
        " VALUES (?, ?, ?, ?, ?, ?, '[]', NULL, NULL, 0)",
        (asset_id, content_hash, media_type, len(content), now_ns(), file.filename or None),
    )
    db.commit()
    return {"id": asset_id, "media_type": media_type, "size": len(content), "title": file.filename}


# ── create post ───────────────────────────────────────────────────────────────

@router.post("/posts", status_code=201)
async def create_post(
    request: Request,
    identity: OwnerDep,
    body: str = Form(default=""),
    tags: str = Form(default="[]"),
    public: str = Form(default=""),        # legacy — ignored if visibility set
    visibility: str = Form(default="contacts"),
    post_type: str = Form(default="post"),
    parent_id: str = Form(default=""),
    parent_node_id: str = Form(default=""),
    supersedes: str = Form(default=""),   # boolean: "1" = this post supersedes its parent
    visibility_list_id: str = Form(default=""),
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

    is_public = visibility == "public"
    db = request.app.state.db
    now = now_ns()

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

    # normalise optional fields
    parent_id = parent_id or None
    parent_node_id = parent_node_id or None
    is_supersession = supersedes.lower() in ("1", "true", "yes") if supersedes else False
    if is_supersession and parent_node_id:
        raise HTTPException(status_code=422, detail="parent_node_id must not be set when supersedes is true")
    node_id = getattr(request.app.state, "node_id", "") or ""
    if is_supersession:
        if not parent_id:
            raise HTTPException(status_code=422, detail="parent_id is required when supersedes is true")
        if db.execute("SELECT 1 FROM posts WHERE id = ? AND deleted = 0", (parent_id,)).fetchone() is None:
            raise HTTPException(status_code=422, detail="parent_id not found on this node")
        parent_node_id = node_id
    elif parent_id and not parent_node_id:
        # auto-fill parent_node_id when parent lives on this node
        if db.execute("SELECT 1 FROM posts WHERE id = ?", (parent_id,)).fetchone() is not None:
            parent_node_id = node_id
    supersedes_stored = "1" if is_supersession else None

    # visibility_list_id: replies inherit from parent; top-level posts use what the client provides
    visibility_list_id = visibility_list_id or None
    if parent_id:
        parent_row = db.execute("SELECT visibility_list_id FROM posts WHERE id = ?", (parent_id,)).fetchone()
        if parent_row:
            visibility_list_id = parent_row[0]

    # compute content-addressable post ID after body is finalized
    nonce = secrets.token_hex(16)
    post_id = hashlib.sha256(
        f"{node_id}\n{body}\n{now}\n{nonce}\n{parent_id or ''}\n{1 if is_supersession else 0}".encode()
    ).hexdigest()

    # record all referenced assets in post_assets
    all_ids = _asset_ids_in_order(body)
    db.execute(
        "INSERT INTO posts"
        " (id, body, created_at, tags, is_public, deleted, post_type, visibility,"
        "  nonce, parent_id, parent_node_id, supersedes, visibility_list_id)"
        " VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)",
        (post_id, body, now, json.dumps(tags_list), int(is_public), post_type, visibility,
         nonce, parent_id, parent_node_id, supersedes_stored, visibility_list_id),
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
    _notify_mentions(body, post_id, request.app)
    return _post_dict(row, db)


def _notify_parent_of_reply(parent_node_id: str, parent_post_id: str,
                             reply_node_id: str, reply_post_id: str, app) -> None:
    """Best-effort notification to the parent node that a reply exists."""
    import threading

    def _send():
        import httpx as _hx, time as _t, base64 as _b64
        db = app.state.db
        priv = getattr(app.state, "private_key", None)
        node_address = getattr(app.state, "node_address", "") or ""

        row = db.execute("SELECT server_url FROM users WHERE node_id = ?", (parent_node_id,)).fetchone()
        server_url = row[0] if row else None

        def _get_registry_url():
            try:
                from .config import NodeConfig
                cfg = NodeConfig.load(app.state.config_path)
                return (cfg.registry_url or cfg.identity_proxy_url or "").rstrip("/")
            except Exception:
                return ""

        def _build_headers(ts):
            headers = {"Content-Type": "application/json"}
            if priv:
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                sig_msg = f"contacc:notify-reply:{parent_post_id}:{ts}".encode()
                sig = _b64.b64encode(priv.sign(sig_msg)).decode()
                pub_b64 = _b64.b64encode(
                    priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                ).decode()
                headers.update({"X-Public-Key": pub_b64, "X-Timestamp": str(ts),
                                 "X-Signature": sig, "X-Origin-Server": node_address})
            return headers

        def _try_deliver(url):
            ts = int(_t.time())
            r = _hx.post(
                url.rstrip("/") + f"/posts/{parent_post_id}/notify-reply",
                json={"reply_node_id": reply_node_id, "reply_post_id": reply_post_id},
                headers=_build_headers(ts),
                timeout=5,
            )
            return r

        def _lookup_fresh_url():
            reg_url = _get_registry_url()
            if not reg_url:
                return None
            try:
                r = _hx.get(f"{reg_url}/nodes/{parent_node_id}", timeout=5)
                if not r.is_success:
                    return None
                d = r.json()
                fresh = d.get("server_url")
                if fresh and fresh != server_url:
                    db.execute("UPDATE users SET server_url = ? WHERE node_id = ?",
                               (fresh, parent_node_id))
                    db.commit()
                return fresh
            except Exception:
                return None

        try:
            if not server_url:
                server_url_to_use = _lookup_fresh_url()
            else:
                server_url_to_use = server_url

            if not server_url_to_use:
                return

            r = _try_deliver(server_url_to_use)
            if r.status_code in (404, 410) or r.status_code >= 500:
                # Cached URL may be stale — re-lookup and retry once
                fresh = _lookup_fresh_url()
                if fresh and fresh != server_url_to_use:
                    _try_deliver(fresh)
        except Exception:
            # Connection failed — try registry re-lookup once
            try:
                fresh = _lookup_fresh_url()
                if fresh:
                    _try_deliver(fresh)
            except Exception:
                pass

    threading.Thread(target=_send, daemon=True).start()


# ── post feed ─────────────────────────────────────────────────────────────────

@router.get("/posts")
def get_posts(
    request: Request,
    identity: OptionalAuthDep,
    _sig: FederatedSigDep = None,
    limit: int = Query(default=20, ge=1, le=100),
    cursor: str = Query(default=""),
    tags: list[str] = Query(default=[]),
    q: str = Query(default=""),
    post_type: str = Query(default="post"),
):
    db = request.app.state.db
    params: list = []
    conditions = ["p.deleted = 0", "(p.parent_id IS NULL OR p.parent_id = '')"]  # feed shows top-level posts only

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
        origin_pub_key = request.headers.get("X-Public-Key", "")
        is_contact = _is_known_contact(db, origin_server, origin_pub_key)
        if identity.is_share:
            if identity.share_post_ids is not None:
                placeholders = ",".join("?" * len(identity.share_post_ids))
                conditions.append(f"(p.visibility = 'public' OR p.id IN ({placeholders}))")
                params.extend(identity.share_post_ids)
        elif identity.node_id is not None:
            conditions.append(
                "(p.visibility = 'public' OR "
                "EXISTS (SELECT 1 FROM post_acl WHERE post_id = p.id AND node_id = ?) OR "
                "(p.visibility_list_id IS NOT NULL AND "
                " EXISTS (SELECT 1 FROM node_list_members WHERE list_id = p.visibility_list_id AND node_id = ?)))"
            )
            params.extend([identity.node_id, identity.node_id])
        elif is_contact:
            conditions.append("p.visibility IN ('contacts', 'authenticated', 'public')")
        elif getattr(request.state, 'sig_verified', False):
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
                "(p.body LIKE ? OR EXISTS (SELECT 1 FROM post_tags WHERE post_id = p.id AND tag LIKE ?))"
            )
            params.extend([f"%{q}%", f"%{q}%"])

    if cursor:
        conditions.append("p.created_at < ?")
        params.append(int(cursor))

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
def get_post(post_id: str, request: Request, identity: OptionalAuthDep, _sig: FederatedSigDep = None):
    db = request.app.state.db
    row = db.execute(
        f"SELECT {_POST_COLS_NO_ALIAS} FROM posts WHERE id = ? AND deleted = 0", (post_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Post not found")
    visibility, post_type = row[4], row[6]
    if not identity.is_owner:
        origin_server = request.headers.get("X-Origin-Server", "")
        if post_type == "inner_monologue":
            raise HTTPException(status_code=404, detail="Post not found")
        if visibility == "private":
            raise HTTPException(status_code=403, detail="Access denied")
        if visibility in ("contacts", "authenticated"):
            origin_pub_key = request.headers.get("X-Public-Key", "")
            is_contact = _is_known_contact(db, origin_server, origin_pub_key)
            is_authenticated = getattr(request.state, 'sig_verified', False)
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


# ── reply refs ────────────────────────────────────────────────────────────────

class _ReplyNotification(BaseModel):
    reply_node_id: str
    reply_post_id: str


@router.post("/posts/{post_id}/notify-reply", status_code=204)
def notify_reply(post_id: str, payload: _ReplyNotification, request: Request,
                 identity: FederatedOrTokenDep):
    db = request.app.state.db
    app = request.app
    own_node_id = getattr(app.state, "node_id", "") or ""
    if db.execute("SELECT 1 FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")
    db.execute(
        "INSERT OR IGNORE INTO reply_refs (reply_post_id, reply_node_id, parent_post_id, received_at)"
        " VALUES (?, ?, ?, ?)",
        (payload.reply_post_id, payload.reply_node_id, post_id, now_ns()),
    )
    if not identity.is_owner:
        import hashlib as _hl
        replier_node_id = payload.reply_node_id or (identity.node_id or '')
        if own_node_id and own_node_id == replier_node_id:
            # Don't notify the replier's node about its own reply
            db.commit()
        else:
            actor_row = db.execute("SELECT name FROM users WHERE node_id = ?", (replier_node_id,)).fetchone()
            actor_name = actor_row[0] if actor_row else None
            # nid is unique per (reply, recipient-node) so each node sees at most one notification per reply
            nid = _hl.sha256(f"reply:{payload.reply_post_id}:{own_node_id}".encode()).hexdigest()[:36]
            is_new = db.execute("SELECT 1 FROM mention_notifications WHERE id = ?", (nid,)).fetchone() is None
            db.execute(
                "INSERT INTO mention_notifications "
                "(id, post_id, post_node_id, author_node_id, author_handle, received_at, notif_type, actor_name, emoji) "
                "VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET post_id=excluded.post_id, post_node_id=excluded.post_node_id, actor_name=excluded.actor_name",
                (nid, payload.reply_post_id, replier_node_id, replier_node_id, '', now_ns(), 'reply', actor_name, None),
            )
            db.commit()
            if is_new:
                # Propagate up the ancestor chain — each remote node gets notified once
                _propagate_reply_up(post_id, payload.reply_post_id, replier_node_id, own_node_id, db, app)
    else:
        db.commit()


def _propagate_reply_up(start_post_id: str, reply_post_id: str, reply_node_id: str,
                         own_node_id: str, db, app) -> None:
    """Walk up the local parent chain and notify the first remote ancestor node.
    That node repeats the process, propagating the chain recursively."""
    current_post_id = start_post_id
    while True:
        row = db.execute(
            "SELECT parent_id, parent_node_id FROM posts WHERE id = ? AND deleted = 0",
            (current_post_id,)
        ).fetchone()
        if not row or not row[0] or not row[1]:
            break
        parent_post_id, parent_node_id = row
        if parent_node_id == own_node_id:
            # Local ancestor — same nid already covers it, keep walking to find remote ancestors
            current_post_id = parent_post_id
            continue
        if parent_node_id == reply_node_id:
            # Don't notify the replier's node about its own reply; stop propagation
            break
        # Remote ancestor — send notification; that node will propagate further
        _notify_parent_of_reply(parent_node_id, parent_post_id, reply_node_id, reply_post_id, app)
        break


@router.get("/posts/{post_id}/replies")
def get_replies(post_id: str, request: Request, identity: OptionalAuthDep,
                _sig: FederatedSigDep = None):
    db = request.app.state.db
    row = db.execute(
        "SELECT visibility FROM posts WHERE id = ? AND deleted = 0", (post_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Post not found")

    own_node_id = getattr(request.app.state, "node_id", "") or ""

    # local replies: posts on this node whose parent_id = post_id
    local_rows = db.execute(
        "SELECT id FROM posts WHERE parent_id = ? AND deleted = 0", (post_id,)
    ).fetchall()
    local_refs = [{"reply_post_id": r[0], "reply_node_id": own_node_id} for r in local_rows]

    # cached remote reply refs
    ref_rows = db.execute(
        "SELECT reply_post_id, reply_node_id FROM reply_refs WHERE parent_post_id = ?", (post_id,)
    ).fetchall()
    remote_refs = [{"reply_post_id": r[0], "reply_node_id": r[1]} for r in ref_rows]

    # merge, dedup by (node_id, post_id)
    seen: set[tuple] = set()
    replies = []
    for ref in local_refs + remote_refs:
        key = (ref["reply_node_id"], ref["reply_post_id"])
        if key not in seen:
            seen.add(key)
            replies.append(ref)

    return {"replies": replies}


# ── post access helpers ───────────────────────────────────────────────────────

def _check_post_access(db, post_id: str, identity) -> bool:
    if identity.is_share:
        if identity.share_post_ids is None:
            return True  # node-wide share
        return post_id in identity.share_post_ids
    if identity.node_id:
        if db.execute(
            "SELECT 1 FROM post_acl WHERE post_id = ? AND node_id = ?", (post_id, identity.node_id)
        ).fetchone() is not None:
            return True
        row = db.execute("SELECT visibility_list_id FROM posts WHERE id = ?", (post_id,)).fetchone()
        if row and row[0]:
            from .node_lists import get_list_members_set
            return identity.node_id in get_list_members_set(db, row[0])
    return False


def _is_known_contact(db, server_url: str, public_key: str | None = None) -> bool:
    if not public_key:
        return False
    row = db.execute(
        "SELECT id, server_url FROM users WHERE public_key = ? AND relationship = 'contact'", (public_key,)
    ).fetchone()
    if not row:
        return False
    if server_url and row[1] != server_url:
        db.execute("UPDATE users SET server_url = ? WHERE id = ?", (server_url, row[0]))
        db.commit()
    return True


# ── post ACL ──────────────────────────────────────────────────────────────────

@router.get("/posts/{post_id}/acl")
def get_post_acl(post_id: str, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")
    rows = db.execute(
        """SELECT pa.node_id, u.name
           FROM post_acl pa LEFT JOIN users u ON u.node_id = pa.node_id
           WHERE pa.post_id = ?""",
        (post_id,),
    ).fetchall()
    return {"post_id": post_id, "recipients": [
        {"node_id": r[0], "display_name": r[1] or r[0]} for r in rows
    ]}


class _AclUpdateBody(BaseModel):
    add: list[str] = []
    remove: list[str] = []


@router.patch("/posts/{post_id}/acl")
def update_post_acl(post_id: str, payload: _AclUpdateBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    if db.execute("SELECT id FROM posts WHERE id = ? AND deleted = 0", (post_id,)).fetchone() is None:
        raise HTTPException(status_code=404, detail="Post not found")
    for nid in payload.add:
        db.execute("INSERT OR IGNORE INTO post_acl (post_id, node_id) VALUES (?, ?)", (post_id, nid))
    for nid in payload.remove:
        db.execute("DELETE FROM post_acl WHERE post_id = ? AND node_id = ?", (post_id, nid))
    db.commit()
    rows = db.execute(
        """SELECT pa.node_id, u.name
           FROM post_acl pa LEFT JOIN users u ON u.node_id = pa.node_id
           WHERE pa.post_id = ?""",
        (post_id,),
    ).fetchall()
    return {"post_id": post_id, "recipients": [
        {"node_id": r[0], "display_name": r[1] or r[0]} for r in rows
    ]}

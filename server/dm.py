"""Direct messages — 1:1 encrypted messaging between nodes.

Encryption: X25519 DH + HKDF derives a per-thread symmetric key. Both parties
independently compute the same thread key from their DH key pair + peer's public key.
Messages are encrypted with AES-256-GCM; the thread key is never stored.
"""
import base64
import time
import uuid

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from .auth import InternalOrOwnerDep, FederatedOrTokenDep
from .db import NS, now_ns
from .crypto import make_thread_id, derive_thread_key, encrypt_dm, decrypt_dm

router = APIRouter()

# In-memory queue so the client's fast poll picks up new inbound DMs quickly.
_incoming_dm_updates: list[dict] = []
_DM_UPDATES_MAX = 200


def _push_dm_update(event: str, data: dict) -> None:
    _incoming_dm_updates.append({"type": "dm", "event": event, **data})
    if len(_incoming_dm_updates) > _DM_UPDATES_MAX:
        del _incoming_dm_updates[:100]


def drain_dm_updates() -> list[dict]:
    updates = list(_incoming_dm_updates)
    _incoming_dm_updates.clear()
    return updates


def _get_thread_key(app, thread_id: str, peer_dh_pub: str) -> bytes:
    """Derive thread key from app's DH private key + peer's public key."""
    return derive_thread_key(app.state.dh_private_key, peer_dh_pub, thread_id)


def _peer_dh_pub(db, thread_id: str) -> str | None:
    row = db.execute("SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (thread_id,)).fetchone()
    return row[0] if row else None


def _upsert_thread(db, thread_id: str, peer_node_id: str, peer_url: str,
                   peer_name: str | None, peer_dh_pub: str | None) -> None:
    db.execute("""
        INSERT INTO dm_threads (thread_id, peer_node_id, peer_url, peer_name, peer_dh_pub, last_msg_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(thread_id) DO UPDATE SET
            peer_url = excluded.peer_url,
            peer_name = COALESCE(excluded.peer_name, peer_name),
            peer_dh_pub = COALESCE(excluded.peer_dh_pub, peer_dh_pub)
    """, (thread_id, peer_node_id, peer_url, peer_name, peer_dh_pub, 0))


# ── incoming receive endpoint (federated, called by other nodes) ──────────────

class ReceiveBody(BaseModel):
    id: str
    thread_id: str
    sender_node_id: str
    sender_url: str
    sender_name: str | None = None
    sender_dh_pub: str
    body_enc: str
    created_at: int


@router.post("/dm/receive", status_code=204)
async def dm_receive(body: ReceiveBody, request: Request, identity: FederatedOrTokenDep):
    """Receive an inbound DM from another node.

    Auth: any node with a valid federated signature is accepted (not contact-only).
    The FederatedOrTokenDep will verify against known contacts or do an on-the-fly
    /node fetch if the sender's key is unknown (requires X-Origin-Server header).
    """
    if not identity.is_owner and identity.recipient_id is None:
        raise HTTPException(403, "Valid federated signature required")

    db = request.app.state.db

    # Deduplicate
    if db.execute("SELECT 1 FROM dm_messages WHERE id = ?", (body.id,)).fetchone():
        return  # already stored

    _upsert_thread(db, body.thread_id, body.sender_node_id, body.sender_url,
                   body.sender_name, body.sender_dh_pub)
    db.execute("""
        INSERT INTO dm_messages (id, thread_id, direction, body_enc, created_at)
        VALUES (?, ?, 'in', ?, ?)
    """, (body.id, body.thread_id, body.body_enc, body.created_at))
    db.execute("""
        UPDATE dm_threads SET unread_count = unread_count + 1, last_msg_at = ?
        WHERE thread_id = ?
    """, (body.created_at, body.thread_id))
    db.commit()
    _push_dm_update("new_message", {"thread_id": body.thread_id, "message_id": body.id})


# ── owner endpoints ───────────────────────────────────────────────────────────

def _do_merge(db, app, keep_id: str, drop_id: str) -> None:
    """Re-encrypt messages from drop_id into keep_id and delete the duplicate."""
    keep = db.execute("SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (keep_id,)).fetchone()
    drop = db.execute("SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (drop_id,)).fetchone()
    if not keep or not drop:
        return
    keep_dh = keep[0]
    drop_dh = drop[0] or keep_dh
    if keep_dh:
        keep_key = _get_thread_key(app, keep_id, keep_dh)
        drop_key = _get_thread_key(app, drop_id, drop_dh)
        for r in db.execute(
            "SELECT id, direction, body_enc, created_at, delivered_at, seen_at FROM dm_messages WHERE thread_id = ?",
            (drop_id,)
        ).fetchall():
            if db.execute("SELECT 1 FROM dm_messages WHERE id = ? AND thread_id = ?", (r[0], keep_id)).fetchone():
                continue
            try:
                new_enc = encrypt_dm(keep_key, decrypt_dm(drop_key, r[2]))
            except Exception:
                new_enc = r[2]
            db.execute(
                "INSERT OR IGNORE INTO dm_messages (id, thread_id, direction, body_enc, created_at, delivered_at, seen_at) VALUES (?,?,?,?,?,?,?)",
                (r[0], keep_id, r[1], new_enc, r[3], r[4], r[5])
            )
    db.execute("DELETE FROM dm_messages WHERE thread_id = ?", (drop_id,))
    db.execute("DELETE FROM dm_threads WHERE thread_id = ?", (drop_id,))
    if keep_dh:
        db.execute("""
            UPDATE dm_threads SET
                last_msg_at = (SELECT COALESCE(MAX(created_at),0) FROM dm_messages WHERE thread_id = ?),
                unread_count = (SELECT COUNT(*) FROM dm_messages WHERE thread_id = ? AND direction='in' AND seen_at IS NULL)
            WHERE thread_id = ?
        """, (keep_id, keep_id, keep_id))


@router.post("/dm/threads/dedup", status_code=200)
def dedup_threads(request: Request, _: InternalOrOwnerDep):
    """Merge duplicate threads by peer_node_id and by peer_url."""
    db = request.app.state.db
    app = request.app
    merged_count = 0

    # Collect groups of thread_ids that belong to the same peer.
    # Key: canonical peer identity → list of (thread_id, last_msg_at)
    groups: dict[str, list[tuple[str, int]]] = {}
    for row in db.execute("SELECT thread_id, peer_node_id, peer_url, last_msg_at FROM dm_threads").fetchall():
        tid, nid, url, ts = row
        key = nid or url or tid  # node_id is authoritative; fall back to url
        groups.setdefault(key, []).append((tid, ts))

    # Also unify groups that share a peer_url across different node_ids
    url_to_key: dict[str, str] = {}
    for row in db.execute("SELECT thread_id, peer_node_id, peer_url FROM dm_threads").fetchall():
        tid, nid, url = row
        key = nid or url or tid
        if url:
            existing = url_to_key.get(url)
            if existing and existing != key:
                # Merge the two groups
                groups.setdefault(key, []).extend(groups.pop(existing, []))
                url_to_key[url] = key
            else:
                url_to_key[url] = key

    for group in groups.values():
        if len(group) < 2:
            continue
        group.sort(key=lambda x: x[1], reverse=True)
        keep_id = group[0][0]
        for drop_id, _ in group[1:]:
            _do_merge(db, app, keep_id, drop_id)
            merged_count += 1

    db.commit()
    return {"merged": merged_count}


@router.get("/dm/threads")
def list_threads(request: Request, _: InternalOrOwnerDep):
    db = request.app.state.db
    rows = db.execute("""
        SELECT thread_id, peer_node_id, peer_url, peer_name, last_msg_at, unread_count
        FROM dm_threads ORDER BY last_msg_at DESC
    """).fetchall()
    return {"threads": [
        {"thread_id": r[0], "peer_node_id": r[1], "peer_url": r[2],
         "peer_name": r[3], "last_msg_at": r[4], "unread_count": r[5]}
        for r in rows
    ]}


@router.get("/dm/updates")
def get_dm_updates(_: InternalOrOwnerDep):
    return {"updates": drain_dm_updates()}


class GetMessagesParams(BaseModel):
    since: int = 0
    limit: int = 50


@router.get("/dm/messages/{thread_id}")
def get_messages(thread_id: str, request: Request, _: InternalOrOwnerDep, since: int = 0, limit: int = 50):
    db = request.app.state.db
    app = request.app
    thread = db.execute(
        "SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (thread_id,)
    ).fetchone()
    if not thread:
        raise HTTPException(404, "Thread not found")

    peer_dh_pub = thread[0]
    if not peer_dh_pub:
        raise HTTPException(400, "No DH key for peer — cannot decrypt")

    thread_key = _get_thread_key(app, thread_id, peer_dh_pub)

    rows = db.execute("""
        SELECT id, direction, body_enc, created_at, delivered_at, seen_at
        FROM dm_messages
        WHERE thread_id = ? AND created_at > ?
        ORDER BY created_at ASC LIMIT ?
    """, (thread_id, since, min(limit, 200))).fetchall()

    messages = []
    for r in rows:
        try:
            body = decrypt_dm(thread_key, r[2])
        except Exception:
            body = "[decryption failed]"
        messages.append({
            "id": r[0], "direction": r[1], "body": body,
            "created_at": r[3], "delivered_at": r[4], "seen_at": r[5],
        })
    return {"messages": messages}


class SendBody(BaseModel):
    peer_node_id: str
    peer_url: str
    body: str


@router.post("/dm/send", status_code=201)
async def send_message(payload: SendBody, request: Request, _: InternalOrOwnerDep):
    db = request.app.state.db
    app = request.app

    my_node_id = getattr(app.state, "node_id", "") or ""
    if not my_node_id:
        raise HTTPException(500, "Node ID not configured")

    thread_id = make_thread_id(my_node_id, payload.peer_node_id)

    # Fetch peer's DH public key if we don't have it yet
    peer_dh_pub = _peer_dh_pub(db, thread_id)
    if not peer_dh_pub:
        try:
            async with httpx.AsyncClient() as hc:
                nr = await hc.get(payload.peer_url.rstrip("/") + "/node", timeout=8)
            if not nr.is_success:
                raise HTTPException(502, "Could not reach peer node")
            peer_dh_pub = nr.json().get("dh_public_key")
            if not peer_dh_pub:
                raise HTTPException(400, "Peer node does not support DM encryption")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(502, f"Could not fetch peer node info: {e}")

    peer_name = None
    try:
        async with httpx.AsyncClient() as hc:
            nr2 = await hc.get(payload.peer_url.rstrip("/") + "/node", timeout=5)
        if nr2.is_success:
            nd = nr2.json()
            peer_name = nd.get("display_name") or nd.get("handle")
            peer_dh_pub = nd.get("dh_public_key", peer_dh_pub)
    except Exception:
        pass

    _upsert_thread(db, thread_id, payload.peer_node_id, payload.peer_url, peer_name, peer_dh_pub)

    thread_key = _get_thread_key(app, thread_id, peer_dh_pub)
    body_enc = encrypt_dm(thread_key, payload.body)
    msg_id = str(uuid.uuid4())
    created_at = now_ns()

    db.execute("""
        INSERT INTO dm_messages (id, thread_id, direction, body_enc, created_at)
        VALUES (?, ?, 'out', ?, ?)
    """, (msg_id, thread_id, body_enc, created_at))
    db.execute("""
        UPDATE dm_threads SET last_msg_at = ? WHERE thread_id = ?
    """, (created_at, thread_id))
    db.commit()

    # Push to peer (best-effort; heartbeat retries undelivered messages)
    my_url = app.state.node_address
    my_dh_pub = app.state.dh_public_key
    my_name = None
    try:
        row = app.state.db.execute("SELECT display_name FROM profile LIMIT 1").fetchone()
        my_name = row[0] if row else None
    except Exception:
        pass
    push_body = {
        "id": msg_id, "thread_id": thread_id,
        "sender_node_id": my_node_id, "sender_url": my_url,
        "sender_name": my_name,
        "sender_dh_pub": my_dh_pub,
        "body_enc": body_enc, "created_at": created_at,
    }
    import json as _json
    from .auth import sign_federated_request
    push_body_bytes = _json.dumps(push_body).encode()
    fed_headers = sign_federated_request(
        app.state.private_key, "POST", "/dm/receive", push_body_bytes
    )
    fed_headers["Content-Type"] = "application/json"
    fed_headers["X-Origin-Server"] = my_url
    try:
        async with httpx.AsyncClient() as hc:
            r = await hc.post(payload.peer_url.rstrip("/") + "/dm/receive",
                              content=push_body_bytes, headers=fed_headers, timeout=8)
        if r.is_success:
            db.execute("UPDATE dm_messages SET delivered_at = ? WHERE id = ?",
                       (now_ns(), msg_id))
            db.commit()
    except Exception:
        pass  # heartbeat will retry

    return {"id": msg_id, "thread_id": thread_id, "created_at": created_at}


@router.post("/dm/threads/{thread_id}/seen", status_code=204)
def mark_seen(thread_id: str, request: Request, _: InternalOrOwnerDep):
    db = request.app.state.db
    now = now_ns()
    db.execute("""
        UPDATE dm_messages SET seen_at = ? WHERE thread_id = ? AND direction = 'in' AND seen_at IS NULL
    """, (now, thread_id))
    db.execute("UPDATE dm_threads SET unread_count = 0 WHERE thread_id = ?", (thread_id,))
    db.commit()


@router.post("/dm/threads/{keep_id}/merge/{drop_id}", status_code=200)
def merge_threads(keep_id: str, drop_id: str, request: Request, _: InternalOrOwnerDep):
    """Merge drop_id into keep_id: re-encrypt messages and delete the duplicate."""
    db = request.app.state.db
    app = request.app

    keep = db.execute("SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (keep_id,)).fetchone()
    drop = db.execute("SELECT peer_dh_pub FROM dm_threads WHERE thread_id = ?", (drop_id,)).fetchone()
    if not keep:
        raise HTTPException(404, f"Thread {keep_id} not found")
    if not drop:
        raise HTTPException(404, f"Thread {drop_id} not found")

    keep_dh = keep[0]
    drop_dh = drop[0] or keep_dh  # fall back to keep's key if drop has none
    if not keep_dh:
        raise HTTPException(400, "Keep thread has no DH key — cannot re-encrypt")

    keep_key = _get_thread_key(app, keep_id, keep_dh)
    drop_key = _get_thread_key(app, drop_id, drop_dh)

    rows = db.execute(
        "SELECT id, direction, body_enc, created_at, delivered_at, seen_at FROM dm_messages WHERE thread_id = ?",
        (drop_id,)
    ).fetchall()

    moved = 0
    for r in rows:
        if db.execute("SELECT 1 FROM dm_messages WHERE id = ?", (r[0],)).fetchone() and \
           db.execute("SELECT 1 FROM dm_messages WHERE id = ? AND thread_id = ?", (r[0], keep_id)).fetchone():
            continue  # already in keep thread
        try:
            body = decrypt_dm(drop_key, r[2])
            new_enc = encrypt_dm(keep_key, body)
        except Exception:
            new_enc = r[2]  # keep as-is if decryption fails
        db.execute(
            "INSERT OR IGNORE INTO dm_messages (id, thread_id, direction, body_enc, created_at, delivered_at, seen_at) VALUES (?,?,?,?,?,?,?)",
            (r[0], keep_id, r[1], new_enc, r[3], r[4], r[5])
        )
        moved += 1

    # Update keep thread's last_msg_at and unread_count
    db.execute("""
        UPDATE dm_threads SET
            last_msg_at = MAX(last_msg_at, (SELECT COALESCE(MAX(created_at),0) FROM dm_messages WHERE thread_id = ?)),
            unread_count = (SELECT COUNT(*) FROM dm_messages WHERE thread_id = ? AND direction='in' AND seen_at IS NULL)
        WHERE thread_id = ?
    """, (keep_id, keep_id, keep_id))

    db.execute("DELETE FROM dm_messages WHERE thread_id = ?", (drop_id,))
    db.execute("DELETE FROM dm_threads WHERE thread_id = ?", (drop_id,))
    db.commit()
    return {"merged": moved, "dropped": drop_id, "kept": keep_id}

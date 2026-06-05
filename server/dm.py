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

from .auth import OwnerDep, FederatedOrTokenDep
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
                   None, body.sender_dh_pub)
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

@router.get("/dm/threads")
def list_threads(request: Request, _: OwnerDep):
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
def get_dm_updates(_: OwnerDep):
    return {"updates": drain_dm_updates()}


class GetMessagesParams(BaseModel):
    since: int = 0
    limit: int = 50


@router.get("/dm/messages/{thread_id}")
def get_messages(thread_id: str, request: Request, _: OwnerDep, since: int = 0, limit: int = 50):
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
async def send_message(payload: SendBody, request: Request, _: OwnerDep):
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
    push_body = {
        "id": msg_id, "thread_id": thread_id,
        "sender_node_id": my_node_id, "sender_url": my_url,
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
def mark_seen(thread_id: str, request: Request, _: OwnerDep):
    db = request.app.state.db
    now = now_ns()
    db.execute("""
        UPDATE dm_messages SET seen_at = ? WHERE thread_id = ? AND direction = 'in' AND seen_at IS NULL
    """, (now, thread_id))
    db.execute("UPDATE dm_threads SET unread_count = 0 WHERE thread_id = ?", (thread_id,))
    db.commit()

"""Direct messages — 1:1 encrypted messaging between nodes.

Encryption: X25519 DH + HKDF derives a per-thread symmetric key. Both parties
independently compute the same thread key from their DH key pair + peer's public key.
Messages are encrypted with AES-256-GCM; the thread key is never stored.
"""
import asyncio
import base64
import json
import logging
import time
import uuid

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .auth import InternalOrOwnerDep, FederatedOrTokenDep
from .db import NS, now_ns
from .crypto import make_thread_id, derive_thread_key, encrypt_dm, decrypt_dm

log = logging.getLogger("contacc.dm")

router = APIRouter()

# In-memory queue so the client's fast poll picks up new inbound DMs quickly.
_incoming_dm_updates: list[dict] = []
_DM_UPDATES_MAX = 200

# SSE queues — one per connected client process; events pushed here in real time.
_dm_sse_queues: list[asyncio.Queue] = []


def _push_dm_update(event: str, data: dict) -> None:
    update = {"type": "dm", "event": event, **data}
    _incoming_dm_updates.append(update)
    if len(_incoming_dm_updates) > _DM_UPDATES_MAX:
        del _incoming_dm_updates[:100]
    for q in list(_dm_sse_queues):
        try:
            q.put_nowait(update)
        except asyncio.QueueFull:
            pass


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


# ── group DM wire format ──────────────────────────────────────────────────────
#
# Groups relay through the creator: members exchange ciphertext only with the
# creator, over their existing pairwise 1:1 thread (a member's group-thread row
# reuses peer_node_id/peer_url/peer_dh_pub to mean "the creator"). So the wire
# format below — ReceiveBody, /dm/receive, push + heartbeat retry — is untouched;
# the only difference is that the *decrypted* body is a JSON envelope rather than
# free text. Three envelope types cover the whole feature, distinguished purely
# by their plaintext "type", with no new transport-level fields:
#
#   group_state         creator -> union(members before change, members after change)
#     {"type": "group_state", "group_id", "group_name", "members": [node_id, ...]}
#     Sent on creation and every membership/rename change. Carries the full
#     roster, so recipients just replace their local copy — no separate
#     "added"/"removed"/"renamed" types. A removed member learns of it by
#     finding themselves absent from `members`; a new member's first
#     group_state IS their invitation (their group thread is created from the
#     underlying push's sender_* fields, which are the creator's — exactly
#     what a brand-new group thread needs, mirroring how a 1:1 thread is
#     created from the first inbound message).
#
#   chat_message        member -> creator -> union(other members)
#     {"type": "chat_message", "group_id", "body", "sender_node_id"?}
#     `sender_node_id` attributes a relayed copy to its original author; it's
#     present only on the creator's outgoing relay (the inbound leg from
#     member to creator omits it, since ReceiveBody.sender_node_id already
#     names the author there). The creator assigns the canonical `created_at`
#     (the ordinary top-level ReceiveBody field) when relaying — giving the
#     group an authoritative, clock-skew-proof message order for free.
#
#   membership_request  member -> creator only (never relayed)
#     {"type": "membership_request", "group_id", "action": "add"|"remove", "target_node_id"}
#     "add" is evaluated against the group's add policy (v1: any current member
#     may add). "remove" is honored only as self-removal — target_node_id must
#     equal the requester — which is the whole of "leaving a group" in v1;
#     removing *other* members is a harder policy question deferred for now.
#     Either way, on approval the creator updates membership and sends
#     group_state to the old∪new roster.
#
# All three are carried as plain DM bodies — encrypted, sent, received, retried
# and stored exactly like 1:1 text. `group_id` ties them to a group; everything
# else about members (url, dh key, display name) is resolved indirectly through
# the signed registry cache, never duplicated here.
#
# Crypto: no new primitive is needed, and there's no asymmetric case to special-
# case either. `peer_node_id` always names "the group's creator" — including on
# the creator's own thread row, where that's simply themselves (see create_group).
# So _peer_dh_pub/_get_thread_key resolve correctly everywhere: a member derives
# the ordinary pairwise key shared with the creator, and the creator, asking for
# their own public key back, gets the X25519 self-DH shared secret — valid, and
# reproducible only by them (it requires their private key). Either way it's the
# exact same `_get_thread_key(app, thread_id, _peer_dh_pub(db, thread_id))` call
# 1:1 threads already use to encrypt, store, and reread their own messages.

GROUP_STATE = "group_state"
CHAT_MESSAGE = "chat_message"
MEMBERSHIP_REQUEST = "membership_request"
_GROUP_ENVELOPE_TYPES = {GROUP_STATE, CHAT_MESSAGE, MEMBERSHIP_REQUEST}


def parse_group_envelope(body: str) -> dict | None:
    """Return the parsed envelope if `body` is a recognized group message, else None.

    Shared by creator-side and member-side receive handling so both can tell
    group protocol messages apart from ordinary 1:1 text with one check.
    """
    try:
        envelope = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(envelope, dict) and envelope.get("type") in _GROUP_ENVELOPE_TYPES \
            and isinstance(envelope.get("group_id"), str):
        return envelope
    return None


# ── registry resolution (node_id -> server_url, for reaching new group members) ──
#
# `/dm/send` sidesteps this for 1:1 — the caller already knows `peer_url` for an
# existing contact. A group creator, though, may need to reach someone they've
# never exchanged DMs with. This mirrors the client's verified-signed-record
# proxy chain (client/main.py api_registry_node / _verify_registry_record) at
# the same TTLs, so freshness is handled the same way — refreshed lazily on
# read, never hand-maintained. Verified records are cached in `registry_cache`,
# which incidentally is what makes /registry-cache/{node_id} useful to peers.

_REGISTRY_TTL = 4 * 3600        # records younger than this are served from cache
_REGISTRY_MAX_AGE = 8 * 3600    # records older than this are refreshed unconditionally


def _registry_url(app) -> str:
    from .config import NodeConfig
    cfg = NodeConfig.load(app.state.config_path)
    return (cfg.registry_url or cfg.identity_proxy_url or "").rstrip("/")


async def _registry_pub_key(app) -> str | None:
    """Fetch + cache the registry's Ed25519 signing key (GET /meta), once per process."""
    cached = getattr(app.state, "registry_pub_key", None)
    if cached:
        return cached
    url = _registry_url(app)
    if not url:
        return None
    try:
        async with httpx.AsyncClient() as hc:
            r = await hc.get(url + "/meta", timeout=5)
        if r.is_success:
            pub = r.json().get("public_key")
            if pub:
                app.state.registry_pub_key = pub
            return pub
    except Exception:
        pass
    return None


def _verify_registry_record(record: dict, pub_key_b64: str) -> bool:
    """Check a signed node record's Ed25519 signature against the registry's key.

    Canonical string and field set must match registry/main.py _sign_record.
    """
    queried_at = record.get("queried_at")
    sig = record.get("registry_signature")
    if not queried_at or not sig:
        return False
    canonical = (f"contacc:node-record:{queried_at}:{record.get('node_id', '')}:"
                 f"{record.get('server_url', '')}:"
                 f"{record.get('handle', '') or ''}:{record.get('display_name', '') or ''}")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_key_b64 + "=="))
        pub.verify(base64.b64decode(sig + "=="), canonical.encode())
        return True
    except Exception:
        return False


async def resolve_node(app, db, node_id: str) -> dict | None:
    """Resolve node_id -> a verified {server_url, display_name, handle, ...} record.

    Served from the local signed cache when fresh (same TTL the client uses for
    its registry-cache proxy), refreshed from the registry on a miss or staleness.
    Returns None if the node can't be found or its record fails verification —
    callers treat that as "can't reach this member right now" and move on.
    """
    now = int(time.time())
    row = db.execute("SELECT record FROM registry_cache WHERE node_id = ?", (node_id,)).fetchone()
    if row:
        try:
            cached = json.loads(row[0])
            if now - cached.get("queried_at", 0) < _REGISTRY_TTL:
                return cached
        except Exception:
            pass

    url = _registry_url(app)
    pub_key = await _registry_pub_key(app)
    if not url or not pub_key:
        return row and json.loads(row[0])  # serve a stale-but-verified cache entry over nothing

    try:
        async with httpx.AsyncClient() as hc:
            r = await hc.get(f"{url}/nodes/{node_id}", timeout=8)
        if not r.is_success:
            return None
        record = r.json()
    except Exception:
        return row and json.loads(row[0])

    if not _verify_registry_record(record, pub_key):
        return None

    db.execute(
        "INSERT OR REPLACE INTO registry_cache (node_id, record, cached_at) VALUES (?, ?, ?)",
        (node_id, json.dumps(record), now_ns())
    )
    db.commit()
    return record


async def _fetch_node_info(url: str) -> dict | None:
    """Live GET {url}/node — the only source for a node's current DH key (the
    registry doesn't carry it). Mirrors the lookup send_message already does
    for unknown peers."""
    try:
        async with httpx.AsyncClient() as hc:
            r = await hc.get(url.rstrip("/") + "/node", timeout=8)
        if r.is_success:
            return r.json()
    except Exception:
        pass
    return None


async def _resolve_member(app, db, node_id: str) -> dict | None:
    """Resolve a group member to {node_id, url, dh_pub, name} for relay.

    Checked in order of trust-and-freshness: an existing 1:1 thread is itself a
    verified, continuously-refreshed record of this peer (populated through
    signed federated exchange — see _upsert_thread), so prefer it over a fresh
    round-trip. Otherwise fall back to the registry for the URL and a cached or
    live /node fetch for the DH key. The DH key is stored in registry_cache
    alongside the registry record so repeated relay calls skip the /node round-trip.
    """
    row = db.execute(
        "SELECT peer_url, peer_dh_pub, peer_name FROM dm_threads WHERE peer_node_id = ? AND group_id IS NULL",
        (node_id,)
    ).fetchone()
    if row and row[0] and row[1]:
        return {"node_id": node_id, "url": row[0], "dh_pub": row[1], "name": row[2]}

    record = await resolve_node(app, db, node_id)
    if not record or not record.get("server_url"):
        return None
    url = record["server_url"]

    # Use DH key cached alongside the registry record (stored on first successful
    # /node fetch below) to avoid a live network call on every relay.
    dh_pub = record.get("dh_public_key")
    name = record.get("display_name")
    if not dh_pub:
        info = await _fetch_node_info(url)
        if info and info.get("dh_public_key"):
            dh_pub = info["dh_public_key"]
            name = info.get("display_name") or info.get("handle") or name
            # Persist the DH key into the cached record so future calls are cache-only.
            record["dh_public_key"] = dh_pub
            db.execute(
                "INSERT OR REPLACE INTO registry_cache (node_id, record, cached_at) VALUES (?, ?, ?)",
                (node_id, json.dumps(record), now_ns())
            )
            db.commit()
        else:
            # /node unreachable — serve a stale DH key from a previous fetch if present.
            stale = db.execute("SELECT record FROM registry_cache WHERE node_id = ?", (node_id,)).fetchone()
            if stale:
                try:
                    dh_pub = json.loads(stale[0]).get("dh_public_key")
                except Exception:
                    pass
    if not dh_pub:
        log.warning("_resolve_member: could not get DH key for %s (url=%s)", node_id, url)
        return None
    return {"node_id": node_id, "url": url, "dh_pub": dh_pub, "name": name}


def _my_display_name(db) -> str | None:
    try:
        row = db.execute("SELECT display_name FROM profile LIMIT 1").fetchone()
        return row[0] if row else None
    except Exception:
        return None


async def _push_envelope(app, recipient: dict, thread_id: str, envelope_json: str,
                         *, created_at: int | None = None, msg_id: str | None = None) -> bool:
    """Encrypt a group envelope with the pairwise key for (recipient, thread_id)
    and push it to their /dm/receive — the same wire path and retry-free best
    effort as a 1:1 message, just carrying structured JSON instead of free text.

    `created_at` lets a relay carry the creator's canonical timestamp through to
    the recipient's stored copy (see CHAT_MESSAGE in the wire-format note).
    """
    db = app.state.db
    my_node_id = app.state.node_id
    thread_key = derive_thread_key(app.state.dh_private_key, recipient["dh_pub"], thread_id)
    push_body = {
        "id": msg_id or str(uuid.uuid4()),
        "thread_id": thread_id,
        "sender_node_id": my_node_id,
        "sender_url": app.state.node_address,
        "sender_name": _my_display_name(db),
        "sender_dh_pub": app.state.dh_public_key,
        "body_enc": encrypt_dm(thread_key, envelope_json),
        "created_at": created_at if created_at is not None else now_ns(),
    }
    from .auth import sign_federated_request
    push_body_bytes = json.dumps(push_body).encode()
    fed_headers = sign_federated_request(app.state.private_key, "POST", "/dm/receive", push_body_bytes)
    fed_headers["Content-Type"] = "application/json"
    fed_headers["X-Origin-Server"] = app.state.node_address
    try:
        async with httpx.AsyncClient() as hc:
            r = await hc.post(recipient["url"].rstrip("/") + "/dm/receive",
                              content=push_body_bytes, headers=fed_headers, timeout=8)
        if not r.is_success:
            log.warning("group relay to %s failed: HTTP %s", recipient["node_id"], r.status_code)
        return r.is_success
    except Exception as e:
        log.warning("group relay to %s failed: %s", recipient["node_id"], e)
        return False  # best-effort fan-out; no per-recipient retry in v1 (see ROADMAP)


# ── creator-side group logic ──────────────────────────────────────────────────
#
# Everything below runs on the creator's node: creating a group, relaying
# chat_message to the rest of the roster with a canonical timestamp, handling
# membership_request, and the three roster-changing operations — all of which
# funnel through _broadcast_group_state so the old∪new send-list rule lives in
# exactly one place.

def _group_roster(db, group_id: str) -> set[str]:
    return {r[0] for r in db.execute(
        "SELECT member_node_id FROM group_members WHERE group_id = ?", (group_id,)
    ).fetchall()}


async def _broadcast_group_state(app, db, group_id: str, send_to: set[str]) -> None:
    """Push the group's current state to every node_id in `send_to` (the union
    of pre- and post-change rosters — see the wire-format note's group_state
    section for why this single rule covers create/add/remove/rename)."""
    row = db.execute("SELECT thread_id, group_name FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row:
        return
    thread_id, group_name = row
    my_node_id = app.state.node_id
    envelope = json.dumps({
        "type": GROUP_STATE, "group_id": group_id,
        "group_name": group_name, "members": sorted(_group_roster(db, group_id)),
    })
    for node_id in send_to:
        if node_id == my_node_id:
            continue
        info = await _resolve_member(app, db, node_id)
        if info:
            await _push_envelope(app, info, thread_id, envelope)


async def create_group(app, db, group_name: str, member_node_ids: list[str]) -> dict:
    """Create a group and send its founding group_state to every initial member."""
    my_node_id = app.state.node_id
    others = sorted(set(member_node_ids) - {my_node_id})
    if not others:
        raise HTTPException(400, "A group needs at least one other member")

    group_id = uuid.uuid4().hex
    thread_id = group_id  # the group's one shared relay channel; see wire-format note

    # peer_node_id always names "the group's creator" — for the creator's own
    # row that's themselves, which conveniently makes their thread structurally
    # identical to a 1:1 thread too: _peer_dh_pub/_get_thread_key derive exactly
    # the self-shared-secret they need to store and reread their own messages,
    # with no special-casing anywhere (see the wire-format note above).
    db.execute("""
        INSERT INTO dm_threads (thread_id, peer_node_id, peer_url, peer_name, peer_dh_pub,
                                last_msg_at, group_id, group_name, group_creator_id)
        VALUES (?, ?, ?, NULL, ?, 0, ?, ?, ?)
    """, (thread_id, my_node_id, app.state.node_address, app.state.dh_public_key,
          group_id, group_name, my_node_id))
    for node_id in [my_node_id] + others:
        db.execute("INSERT OR IGNORE INTO group_members (group_id, member_node_id) VALUES (?, ?)",
                   (group_id, node_id))
    db.commit()

    await _broadcast_group_state(app, db, group_id, set(others))  # old=∅, new=roster ⇒ union=others
    return {"group_id": group_id, "thread_id": thread_id, "group_name": group_name}


async def add_group_member(app, db, group_id: str, node_id: str) -> None:
    before = _group_roster(db, group_id)
    db.execute("INSERT OR IGNORE INTO group_members (group_id, member_node_id) VALUES (?, ?)",
               (group_id, node_id))
    db.commit()
    await _broadcast_group_state(app, db, group_id, before | _group_roster(db, group_id))


async def remove_group_member(app, db, group_id: str, node_id: str) -> None:
    before = _group_roster(db, group_id)
    db.execute("DELETE FROM group_members WHERE group_id = ? AND member_node_id = ?", (group_id, node_id))
    db.commit()
    await _broadcast_group_state(app, db, group_id, before | _group_roster(db, group_id))


async def rename_group(app, db, group_id: str, new_name: str) -> None:
    db.execute("UPDATE dm_threads SET group_name = ? WHERE group_id = ?", (new_name, group_id))
    db.commit()
    await _broadcast_group_state(app, db, group_id, _group_roster(db, group_id))


async def _creator_relay_chat_message(app, db, group_id: str, sender_id: str, text: str) -> dict:
    """The relay-hub core: stamp `text` with the canonical timestamp, store our
    own copy, and fan it out to everyone but its author. Used both for inbound
    chat_message envelopes from members (_creator_handle_chat_message) and for
    messages the creator composes locally (send_group_message) — the creator
    is just another sender from this function's point of view, so the two
    paths converge here instead of duplicating the stamp/store/fan-out dance.

    Our own group thread's peer_* columns hold our own info (see create_group),
    so the ordinary thread-key machinery already gives us a key only we can
    derive — no special-casing needed to store and later reread our own copy."""
    thread_id = db.execute("SELECT thread_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()[0]
    created_at = now_ns()
    msg_id = str(uuid.uuid4())
    my_node_id = app.state.node_id
    direction = 'out' if sender_id == my_node_id else 'in'

    # Use self-DH key directly from app state — this is the correct at-rest key for
    # the creator's copy regardless of what peer_dh_pub says in the DB (which can
    # be corrupted by the 1:1 fallthrough path if a non-group-envelope message arrives).
    self_key = derive_thread_key(app.state.dh_private_key, app.state.dh_public_key, thread_id)
    db.execute("""
        INSERT INTO dm_messages (id, thread_id, direction, body_enc, created_at, sender_node_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (msg_id, thread_id, direction, encrypt_dm(self_key, text), created_at, sender_id))
    if direction == 'in':
        db.execute("UPDATE dm_threads SET unread_count = unread_count + 1, last_msg_at = ? WHERE thread_id = ?",
                   (created_at, thread_id))
    else:
        db.execute("UPDATE dm_threads SET last_msg_at = ? WHERE thread_id = ?", (created_at, thread_id))
    db.commit()
    _push_dm_update("new_message", {"thread_id": thread_id, "message_id": msg_id})

    relay = json.dumps({"type": CHAT_MESSAGE, "group_id": group_id, "sender_node_id": sender_id, "body": text})
    for node_id in _group_roster(db, group_id):
        if node_id in (my_node_id, sender_id):
            continue
        info = await _resolve_member(app, db, node_id)
        if info:
            await _push_envelope(app, info, thread_id, relay, created_at=created_at)
    return {"id": msg_id, "thread_id": thread_id, "created_at": created_at}


async def _creator_handle_chat_message(app, db, body: "ReceiveBody", envelope: dict) -> None:
    """A member posted to the group — validate membership, then hand off to the
    shared relay-hub core to stamp, store, and fan it out."""
    group_id = envelope["group_id"]
    sender_id = body.sender_node_id

    if not db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND member_node_id = ?",
                      (group_id, sender_id)).fetchone():
        return  # not a current member — ignore (e.g. a removal in flight)

    await _creator_relay_chat_message(app, db, group_id, sender_id, envelope.get("body", ""))


async def _creator_handle_membership_request(app, db, body: "ReceiveBody", envelope: dict) -> None:
    """A member asked to add someone, or to remove themselves (leave).

    v1 "add" policy: any current member may add — there's no stored per-group
    policy yet, so trusting membership itself is the simplest rule that
    fulfils 'request the creator if policy allows'. A real policy system
    (e.g. creator-only, vote, invite links) is a natural follow-up that would
    slot in right here without disturbing anything else.

    "remove" is honored only as self-removal (target_node_id == requester_id)
    — the whole of "leaving a group" in v1. Removing *other* members raises
    the same hard policy question as restrictive add-policies and is deferred
    alongside it; a member can always remove themselves though, so that much
    needs no policy at all."""
    group_id = envelope.get("group_id")
    requester_id = body.sender_node_id
    target_id = envelope.get("target_node_id")
    action = envelope.get("action")
    if not target_id or action not in ("add", "remove"):
        return
    if not db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND member_node_id = ?",
                      (group_id, requester_id)).fetchone():
        return  # not a current member — ignore

    if action == "add":
        if db.execute("SELECT 1 FROM group_members WHERE group_id = ? AND member_node_id = ?",
                      (group_id, target_id)).fetchone():
            return
        await add_group_member(app, db, group_id, target_id)
    else:
        if target_id != requester_id:
            return  # removing others is a deferred policy question — ignore
        await remove_group_member(app, db, group_id, target_id)


# ── member-side group logic ───────────────────────────────────────────────────
#
# A member's group thread is, structurally, just a 1:1 thread with the
# creator whose thread_id happens to equal the group_id (see create_group and
# the wire-format note) — so applying group_state, storing relayed
# chat_message, sending, and asking to join/leave all reduce to the ordinary
# 1:1 send/receive primitives plus envelope wrapping/unwrapping.

async def _member_handle_group_state(app, db, body: "ReceiveBody", envelope: dict) -> None:
    """Apply a creator-issued roster/name update. The very first one IS our
    welcome — exactly like a 1:1 thread bootstraps from its first inbound
    message, a brand-new group thread bootstraps from this push's sender_*
    fields (the creator's identity). Later updates are accepted only from the
    creator we already trust, to stop other members from forging roster state.

    We store the roster exactly as given, including the case where we're no
    longer in it — that absence (checkable via _group_roster) *is* the implicit
    "you've been removed" notice the wire-format note describes; no separate
    flag or message type is needed to represent it."""
    group_id = envelope["group_id"]
    group_name = envelope.get("group_name")
    members = envelope.get("members") or []
    sender_id = body.sender_node_id

    row = db.execute("SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if row:
        thread_id, creator_id = row
        if sender_id != creator_id:
            return  # not from the creator we already trust — ignore
        db.execute("""
            UPDATE dm_threads SET group_name = ?, peer_url = ?, peer_dh_pub = ?,
                                  peer_name = COALESCE(?, peer_name)
            WHERE group_id = ?
        """, (group_name, body.sender_url, body.sender_dh_pub, body.sender_name, group_id))
    else:
        thread_id = group_id  # thread_id == group_id, minted by the creator — see wire-format note
        db.execute("""
            INSERT INTO dm_threads (thread_id, peer_node_id, peer_url, peer_name, peer_dh_pub,
                                    last_msg_at, group_id, group_name, group_creator_id)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
        """, (thread_id, sender_id, body.sender_url, body.sender_name, body.sender_dh_pub,
              group_id, group_name, sender_id))

    db.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    for node_id in members:
        db.execute("INSERT OR IGNORE INTO group_members (group_id, member_node_id) VALUES (?, ?)",
                   (group_id, node_id))
    db.commit()
    _push_dm_update("group_state", {"thread_id": thread_id, "group_id": group_id})


async def _member_handle_chat_message(app, db, body: "ReceiveBody", envelope: dict) -> None:
    """Store a creator-relayed group message, attributed to its original
    author via the embedded sender_node_id (our pairwise link is only to the
    creator, so ReceiveBody.sender_node_id always names *them*, not the
    author — see the wire-format note's chat_message section).

    We re-encrypt the plaintext under our own pairwise key with the creator —
    the same key _get_thread_key/_peer_dh_pub derive for every other read of
    this thread — so the stored copy reads back as plain text exactly like
    any other message. (The relay envelope's own encryption only ever needed
    to protect the message in flight; storage uses the thread's at-rest key,
    same as _creator_relay_chat_message does for the creator's copy.)"""
    group_id = envelope["group_id"]
    text = envelope.get("body", "")
    author_id = envelope.get("sender_node_id") or body.sender_node_id

    row = db.execute("SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row or body.sender_node_id != row[1]:
        return  # unknown group, or relay not from the creator we trust — ignore
    thread_id, _creator_id = row

    thread_key = _get_thread_key(app, thread_id, _peer_dh_pub(db, thread_id))
    db.execute("""
        INSERT INTO dm_messages (id, thread_id, direction, body_enc, created_at, sender_node_id)
        VALUES (?, ?, 'in', ?, ?, ?)
    """, (body.id, thread_id, encrypt_dm(thread_key, text), body.created_at, author_id))
    db.execute("UPDATE dm_threads SET unread_count = unread_count + 1, last_msg_at = ? WHERE thread_id = ?",
               (body.created_at, thread_id))
    db.commit()
    _push_dm_update("new_message", {"thread_id": thread_id, "message_id": body.id})


async def send_group_message(app, db, group_id: str, text: str) -> dict:
    """Send to a group — the group-thread analogue of send_message.

    If we're the creator, we *are* the relay hub: _creator_relay_chat_message
    assigns the canonical timestamp, stores, and fans out, exactly as it does
    for an inbound member chat_message — composing locally is just another
    way to arrive at the same place. If we're a member, relay-through-creator
    means the creator is the only node we can reach directly: we keep our own
    locally-timestamped copy (precisely how a 1:1 'out' message already
    works — the sender always trusts their own clock for their own copy) and
    ship a chat_message envelope for the creator to canonically stamp and
    relay onward to everyone else."""
    row = db.execute("SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    thread_id, creator_id = row
    my_node_id = app.state.node_id

    if creator_id == my_node_id:
        return await _creator_relay_chat_message(app, db, group_id, my_node_id, text)

    created_at = now_ns()
    msg_id = str(uuid.uuid4())
    thread_key = _get_thread_key(app, thread_id, _peer_dh_pub(db, thread_id))
    db.execute("""
        INSERT INTO dm_messages (id, thread_id, direction, body_enc, created_at, sender_node_id)
        VALUES (?, ?, 'out', ?, ?, ?)
    """, (msg_id, thread_id, encrypt_dm(thread_key, text), created_at, my_node_id))
    db.execute("UPDATE dm_threads SET last_msg_at = ? WHERE thread_id = ?", (created_at, thread_id))
    db.commit()

    info = await _resolve_member(app, db, creator_id)
    if info:
        envelope = json.dumps({"type": CHAT_MESSAGE, "group_id": group_id, "body": text})
        await _push_envelope(app, info, thread_id, envelope)
    return {"id": msg_id, "thread_id": thread_id, "created_at": created_at}


async def request_add_group_member(app, db, group_id: str, target_node_id: str) -> None:
    """Ask the creator to add someone (v1 policy: any current member may ask
    and it's granted — see _creator_handle_membership_request). If we *are*
    the creator there's no one to ask — add directly, same end state, zero
    network round-trip; this lets a single API endpoint (#5) serve both."""
    row = db.execute("SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    thread_id, creator_id = row
    if creator_id == app.state.node_id:
        await add_group_member(app, db, group_id, target_node_id)
        return
    info = await _resolve_member(app, db, creator_id)
    if not info:
        raise HTTPException(502, "Could not reach group creator")
    envelope = json.dumps({
        "type": MEMBERSHIP_REQUEST, "group_id": group_id,
        "action": "add", "target_node_id": target_node_id,
    })
    await _push_envelope(app, info, thread_id, envelope)


async def leave_group(app, db, group_id: str) -> None:
    """Ask the creator to remove us — self-removal needs no policy check (see
    _creator_handle_membership_request), so it's the whole of "leaving" in v1.

    The creator can't leave their own group this way: doing so would orphan
    the relay hub mid-flight. Surrogate-creator failover, which would make
    creator departure safe, is explicitly deferred (see the wire-format note);
    until it exists a creator's only "exit" is to stop participating, leaving
    the group inert for everyone — better surfaced to the user as a known
    limitation (#6) than silently accepted here."""
    row = db.execute("SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    thread_id, creator_id = row
    my_node_id = app.state.node_id
    if creator_id == my_node_id:
        raise HTTPException(400, "The group's creator can't leave it yet — surrogate-creator failover isn't implemented")
    info = await _resolve_member(app, db, creator_id)
    if not info:
        raise HTTPException(502, "Could not reach group creator")
    envelope = json.dumps({
        "type": MEMBERSHIP_REQUEST, "group_id": group_id,
        "action": "remove", "target_node_id": my_node_id,
    })
    await _push_envelope(app, info, thread_id, envelope)


async def purge_stillborn_group(app, db, group_id: str) -> None:
    """Delete a group we created whose founding broadcast never reached
    anyone — `last_msg_at == 0` means no chat message has ever been sent or
    received on it, which (since group_state pushes don't bump that column)
    is only possible if every member is still in the dark about the group's
    existence. Safe to erase with zero network side effects: there's no one
    to tell, because no one was ever told.

    Scoped to creator + no-activity so this can never make a *live* group
    disappear out from under members who already know about it — that's
    "dissolving" a group, a different (and harder, #6-adjacent) operation."""
    row = db.execute(
        "SELECT thread_id, group_creator_id, last_msg_at FROM dm_threads WHERE group_id = ?",
        (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    thread_id, creator_id, last_msg_at = row
    if creator_id != app.state.node_id:
        raise HTTPException(403, "Only the group's creator can purge it")
    if last_msg_at:
        raise HTTPException(400, "This group has activity — purge only covers stillborn groups")
    db.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    db.execute("DELETE FROM dm_messages WHERE thread_id = ?", (thread_id,))
    db.execute("DELETE FROM dm_threads WHERE thread_id = ?", (thread_id,))
    db.commit()


async def _route_group_envelope(app, db, body: "ReceiveBody", envelope: dict, identity) -> None:
    """Branch a decrypted group envelope to creator-side relay/policy handling
    or member-side state application.

    We can only be a group's creator if we created it (and so already hold a
    dm_threads row naming ourselves group_creator_id) — an unrecognized
    group_id therefore always means we're a prospective or existing member.
    """
    group_id = envelope.get("group_id")
    msg_type = envelope.get("type")
    row = db.execute("SELECT group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    am_creator = bool(row and row[0] == app.state.node_id)

    if am_creator:
        if msg_type == CHAT_MESSAGE:
            await _creator_handle_chat_message(app, db, body, envelope)
        elif msg_type == MEMBERSHIP_REQUEST:
            await _creator_handle_membership_request(app, db, body, envelope)
        # A group_state addressed to our own group but not from us would mean a
        # forged or confused sender — ignored rather than risking corrupted state.
    else:
        if msg_type == GROUP_STATE:
            await _member_handle_group_state(app, db, body, envelope)
        elif msg_type == CHAT_MESSAGE:
            await _member_handle_chat_message(app, db, body, envelope)
        # membership_request only makes sense addressed to the creator; one
        # arriving here (e.g. stale routing after a removal) is just ignored.


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

    app = request.app
    db = app.state.db

    # Deduplicate
    if db.execute("SELECT 1 FROM dm_messages WHERE id = ?", (body.id,)).fetchone():
        return  # already stored

    # Classify before falling into generic storage: a recognized group envelope
    # gets routed to specialized handling instead. Decrypting here is harmless
    # for ordinary 1:1 messages too — it's the same derivation _get_thread_key
    # would do on read, just eagerly, and plain text is correctly recognized as
    # "not a group message" by parse_group_envelope.
    try:
        thread_key = derive_thread_key(app.state.dh_private_key, body.sender_dh_pub, body.thread_id)
        envelope = parse_group_envelope(decrypt_dm(thread_key, body.body_enc))
    except Exception:
        envelope = None
    if envelope is not None:
        await _route_group_envelope(app, db, body, envelope, identity)
        return

    # If this thread_id belongs to a known group, falling through to 1:1 storage
    # would corrupt the group thread row's peer_dh_pub — drop the message instead.
    if db.execute(
        "SELECT 1 FROM dm_threads WHERE thread_id = ? AND group_id IS NOT NULL",
        (body.thread_id,)
    ).fetchone():
        log.warning("dm_receive: unrecognized msg for group thread %s from %s — dropped",
                    body.thread_id, body.sender_node_id)
        return

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
    """Merge duplicate 1:1 threads by peer_node_id (group threads are never merged this way —
    a user may legitimately have a 1:1 thread and group thread(s) sharing the same peer_node_id,
    since group threads repurpose that column to mean "the group's creator")."""
    db = request.app.state.db
    app = request.app
    merged_count = 0

    # Group threads by peer_node_id
    groups: dict[str, list[tuple[str, int]]] = {}
    for row in db.execute(
        "SELECT thread_id, peer_node_id, last_msg_at FROM dm_threads WHERE group_id IS NULL"
    ).fetchall():
        tid, nid, ts = row
        if nid:
            groups.setdefault(nid, []).append((tid, ts))

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


def _member_names(db, group_id: str, own_node_id: str | None = None) -> dict:
    """Map node_id → display name for all group members."""
    roster = _group_roster(db, group_id)
    names = {}
    own_profile = db.execute("SELECT display_name FROM profile WHERE id = 1").fetchone()
    for node_id in roster:
        # Own node: use local profile display_name.
        if node_id == own_node_id and own_profile and own_profile[0]:
            names[node_id] = own_profile[0]
            continue
        # 1. Local users/contacts table
        row = db.execute("SELECT name FROM users WHERE node_id = ?", (node_id,)).fetchone()
        if row and row[0]:
            names[node_id] = row[0]
            continue
        # 2. Peer name from any 1:1 DM thread with this node
        t = db.execute(
            "SELECT peer_name FROM dm_threads WHERE peer_node_id = ? AND group_id IS NULL", (node_id,)
        ).fetchone()
        if t and t[0]:
            names[node_id] = t[0]
            continue
        # 3. Registry cache
        rc = db.execute("SELECT record FROM registry_cache WHERE node_id = ?", (node_id,)).fetchone()
        if rc:
            try:
                rec = json.loads(rc[0])
                name = rec.get("display_name") or rec.get("handle")
                if name:
                    names[node_id] = name
            except Exception:
                pass
    return names


@router.get("/dm/threads")
def list_threads(request: Request, _: InternalOrOwnerDep):
    db = request.app.state.db
    own_node_id = getattr(request.app.state, "node_id", None)
    rows = db.execute("""
        SELECT thread_id, peer_node_id, peer_url, peer_name, last_msg_at, unread_count,
               group_id, group_name, group_creator_id
        FROM dm_threads ORDER BY last_msg_at DESC
    """).fetchall()
    return {"threads": [
        {"thread_id": r[0], "peer_node_id": r[1], "peer_url": r[2],
         "peer_name": r[3], "last_msg_at": r[4], "unread_count": r[5],
         "group_id": r[6], "group_name": r[7], "group_creator_id": r[8],
         "members": sorted(_group_roster(db, r[6])) if r[6] else None,
         "member_names": _member_names(db, r[6], own_node_id) if r[6] else None}
        for r in rows
    ]}


@router.get("/dm/updates")
def get_dm_updates(_: InternalOrOwnerDep):
    return {"updates": drain_dm_updates()}


@router.get("/dm/events")
async def dm_events(_: InternalOrOwnerDep):
    """SSE stream — client process subscribes to receive DM updates with zero polling latency."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _dm_sse_queues.append(queue)

    async def _generate():
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                _dm_sse_queues.remove(queue)
            except ValueError:
                pass

    return StreamingResponse(_generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


class GetMessagesParams(BaseModel):
    since: int = 0
    limit: int = 50


@router.get("/dm/messages/{thread_id}")
def get_messages(thread_id: str, request: Request, _: InternalOrOwnerDep, since: int = 0, limit: int = 50):
    db = request.app.state.db
    app = request.app
    thread = db.execute(
        "SELECT peer_dh_pub, group_creator_id, group_id FROM dm_threads WHERE thread_id = ?", (thread_id,)
    ).fetchone()
    if not thread:
        raise HTTPException(404, "Thread not found")

    peer_dh_pub, group_creator_id, group_id = thread
    if not peer_dh_pub:
        raise HTTPException(400, "No DH key for peer — cannot decrypt")

    # Creator's at-rest key is the self-DH key derived from this node's own keys.
    # For group threads, also build a list of per-member fallback keys so we can
    # recover messages stored via the 1:1 fallthrough path (body_enc = raw transit
    # ciphertext, encrypted with the sender's pairwise key — one per member).
    # AESGCM auth tags make wrong-key attempts unambiguous failures, so trying
    # multiple keys is safe.
    my_node_id = getattr(app.state, "node_id", None)
    if group_creator_id and group_creator_id == my_node_id:
        thread_key = derive_thread_key(app.state.dh_private_key, app.state.dh_public_key, thread_id)
        # Collect a fallback key + node_id for every group member whose DH pub we
        # can find — from 1:1 threads (most reliable) or registry_cache.
        fallback_keys: list[tuple[bytes, str]] = []  # [(key, member_node_id), ...]
        for (member_id,) in db.execute(
            "SELECT member_node_id FROM group_members WHERE group_id = ?", (group_id,)
        ).fetchall():
            if member_id == my_node_id:
                continue
            dh_pub = None
            row = db.execute(
                "SELECT peer_dh_pub FROM dm_threads WHERE peer_node_id = ? AND group_id IS NULL",
                (member_id,)
            ).fetchone()
            if row and row[0]:
                dh_pub = row[0]
            else:
                rc = db.execute("SELECT record FROM registry_cache WHERE node_id = ?", (member_id,)).fetchone()
                if rc:
                    try:
                        dh_pub = json.loads(rc[0]).get("dh_public_key")
                    except Exception:
                        pass
            if dh_pub and dh_pub != app.state.dh_public_key:
                try:
                    fallback_keys.append((
                        derive_thread_key(app.state.dh_private_key, dh_pub, thread_id),
                        member_id,
                    ))
                except Exception:
                    pass
    else:
        thread_key = _get_thread_key(app, thread_id, peer_dh_pub)
        # Build fallback keys for member nodes: try alternative DH pubs in case
        # peer_dh_pub (creator's pub) is stale/corrupted, and try other member pubs
        # for pre-relay messages sent directly between members using the group thread_id.
        fallback_keys: list[tuple[bytes, str]] = []
        if group_creator_id and group_id:
            seen_pubs = {peer_dh_pub, app.state.dh_public_key}
            # Creator first, then other members.
            candidate_ids = [group_creator_id] + [
                mid for (mid,) in db.execute(
                    "SELECT member_node_id FROM group_members WHERE group_id = ?", (group_id,)
                ).fetchall()
                if mid not in (my_node_id, group_creator_id)
            ]
            for mid in candidate_ids:
                dh_pub = None
                row = db.execute(
                    "SELECT peer_dh_pub FROM dm_threads WHERE peer_node_id = ? AND group_id IS NULL",
                    (mid,)
                ).fetchone()
                if row and row[0] and row[0] not in seen_pubs:
                    dh_pub = row[0]
                if not dh_pub:
                    rc = db.execute("SELECT record FROM registry_cache WHERE node_id = ?", (mid,)).fetchone()
                    if rc:
                        try:
                            candidate = json.loads(rc[0]).get("dh_public_key")
                            if candidate and candidate not in seen_pubs:
                                dh_pub = candidate
                        except Exception:
                            pass
                if dh_pub:
                    seen_pubs.add(dh_pub)
                    try:
                        fallback_keys.append((
                            derive_thread_key(app.state.dh_private_key, dh_pub, thread_id),
                            mid,
                        ))
                    except Exception:
                        pass

    rows = db.execute("""
        SELECT id, direction, body_enc, created_at, delivered_at, seen_at, sender_node_id
        FROM dm_messages
        WHERE thread_id = ? AND created_at > ?
        ORDER BY created_at ASC LIMIT ?
    """, (thread_id, since, min(limit, 200))).fetchall()

    messages = []
    for r in rows:
        sender_node_id = r[6]
        inferred_sender = None
        try:
            body = decrypt_dm(thread_key, r[2])
        except Exception:
            body = "[decryption failed]"
            for fkey, fmember in fallback_keys:
                try:
                    body = decrypt_dm(fkey, r[2])
                    inferred_sender = fmember
                    break
                except Exception:
                    pass
        # Messages stored via the 1:1 fallthrough path have body_enc = raw transit
        # ciphertext, so decryption gives the relay envelope JSON rather than plain
        # text.  Unwrap it to recover the actual message body and sender identity.
        if body != "[decryption failed]":
            env = parse_group_envelope(body)
            if env is not None:
                body = env.get("body", body)
                if not sender_node_id:
                    sender_node_id = env.get("sender_node_id")
            # If still no sender_node_id, infer from whichever member key decrypted.
            if not sender_node_id and inferred_sender:
                sender_node_id = inferred_sender
        messages.append({
            "id": r[0], "direction": r[1], "body": body,
            "created_at": r[3], "delivered_at": r[4], "seen_at": r[5],
            "sender_node_id": sender_node_id,
        })
    return {"messages": messages}


class SendBody(BaseModel):
    peer_node_id: str | None = None
    peer_url: str | None = None
    group_id: str | None = None
    body: str


@router.post("/dm/send", status_code=201)
async def send_message(payload: SendBody, request: Request, _: InternalOrOwnerDep):
    db = request.app.state.db
    app = request.app

    # Group send: hand off to the group-thread analogue of everything below —
    # it stamps/stores/relays exactly the way this function sends/stores for
    # 1:1, just shaped for the relay-through-creator architecture.
    if payload.group_id:
        return await send_group_message(app, db, payload.group_id, payload.body)

    if not payload.peer_node_id or not payload.peer_url:
        raise HTTPException(400, "peer_node_id and peer_url are required for 1:1 messages")

    my_node_id = getattr(app.state, "node_id", "") or ""
    if not my_node_id:
        raise HTTPException(500, "Node ID not configured")

    # Reuse existing thread if one already exists for this peer (thread_id may differ after identity migration)
    existing = db.execute(
        "SELECT thread_id FROM dm_threads WHERE peer_node_id = ? AND group_id IS NULL",
        (payload.peer_node_id,)
    ).fetchone()
    thread_id = existing[0] if existing else make_thread_id(my_node_id, payload.peer_node_id)

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


# ── group endpoints ───────────────────────────────────────────────────────────
#
# Thin wrappers over the group logic in the "creator-side"/"member-side"
# sections above — the functions already handle both roles (e.g.
# request_add_group_member adds directly when the caller is the creator), so
# each endpoint here is a single call plus the owner-auth dependency.

class CreateGroupBody(BaseModel):
    name: str
    member_node_ids: list[str]


@router.post("/dm/groups", status_code=201)
async def api_create_group(payload: CreateGroupBody, request: Request, _: InternalOrOwnerDep):
    return await create_group(request.app, request.app.state.db, payload.name, payload.member_node_ids)


class AddMemberBody(BaseModel):
    node_id: str


@router.post("/dm/groups/{group_id}/members", status_code=204)
async def api_request_add_group_member(group_id: str, payload: AddMemberBody, request: Request, _: InternalOrOwnerDep):
    await request_add_group_member(request.app, request.app.state.db, group_id, payload.node_id)


@router.delete("/dm/groups/{group_id}/members/{node_id}", status_code=204)
async def api_remove_group_member(group_id: str, node_id: str, request: Request, _: InternalOrOwnerDep):
    """Creator-only: remove any member by node_id (e.g. to clean up dead/migrated nodes)."""
    app = request.app
    db = app.state.db
    if db.execute("SELECT group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()[0] != app.state.node_id:
        raise HTTPException(403, "Only the group creator can remove members")
    await remove_group_member(app, db, group_id, node_id)


@router.post("/dm/groups/{group_id}/leave", status_code=204)
async def api_leave_group(group_id: str, request: Request, _: InternalOrOwnerDep):
    await leave_group(request.app, request.app.state.db, group_id)


@router.delete("/dm/groups/{group_id}", status_code=204)
async def api_delete_group(group_id: str, request: Request, _: InternalOrOwnerDep):
    """Creator-only: permanently delete a group and all its messages from this node.
    Sends a final empty-roster group_state to inform members before deleting locally."""
    app = request.app
    db = app.state.db
    row = db.execute(
        "SELECT thread_id, group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    thread_id, creator_id = row
    if creator_id != app.state.node_id:
        raise HTTPException(403, "Only the group's creator can delete it")
    roster = _group_roster(db, group_id)
    group_name = db.execute("SELECT group_name FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    group_name = group_name[0] if group_name else ""
    # Notify all members with an empty roster so their node knows the group is gone.
    dissolve_env = json.dumps({
        "type": GROUP_STATE, "group_id": group_id,
        "group_name": group_name, "members": [],
    })
    for member_id in roster:
        if member_id == app.state.node_id:
            continue
        info = await _resolve_member(app, db, member_id)
        if info:
            try:
                await _push_envelope(app, info, thread_id, dissolve_env)
            except Exception:
                pass
    db.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    db.execute("DELETE FROM dm_messages WHERE thread_id = ?", (thread_id,))
    db.execute("DELETE FROM dm_threads WHERE thread_id = ?", (thread_id,))
    db.commit()


@router.post("/dm/groups/{group_id}/purge", status_code=204)
async def api_purge_stillborn_group(group_id: str, request: Request, _: InternalOrOwnerDep):
    """Clean-up valve for groups whose founding broadcast never went out —
    e.g. ones created during the app.state.config bug, which committed their
    dm_threads/group_members rows locally but threw before reaching _push_envelope
    for any member. See purge_stillborn_group for the safety scoping."""
    await purge_stillborn_group(request.app, request.app.state.db, group_id)


class RenameGroupBody(BaseModel):
    name: str


@router.post("/dm/groups/{group_id}/rename", status_code=204)
async def api_rename_group(group_id: str, payload: RenameGroupBody, request: Request, _: InternalOrOwnerDep):
    """Renaming changes nothing about membership, so unlike add/leave it has no
    natural "ask the creator" path — only the creator may originate it (they're
    the only one whose group_state updates other members will accept; see
    _member_handle_group_state's sender check)."""
    app = request.app
    db = app.state.db
    row = db.execute("SELECT group_creator_id FROM dm_threads WHERE group_id = ?", (group_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Group not found")
    if row[0] != app.state.node_id:
        raise HTTPException(403, "Only the group's creator can rename it")
    await rename_group(app, db, group_id, payload.name)


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

import base64
from fastapi import APIRouter, Request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .auth import OwnerDep
from .db import NS, now_ns

router = APIRouter()

_node_address: str = ""
_public_key_b64: str = ""
_watermark_enabled: bool = False
_registry_handle: str | None = None
_user_id: str = ""       # legacy alias; prefer owner_id/node_id
_owner_id: str = ""
_node_id: str = ""


def setup(node_address: str, private_key: Ed25519PrivateKey, watermark_enabled: bool,
          registry_handle: str | None = None, user_id: str = "",
          owner_id: str = "", node_id: str = "") -> None:
    global _node_address, _public_key_b64, _watermark_enabled, _registry_handle, _user_id, _owner_id, _node_id
    _node_address = node_address
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _public_key_b64 = base64.b64encode(pub_bytes).decode()
    _watermark_enabled = watermark_enabled
    _registry_handle = registry_handle
    _user_id = user_id
    _owner_id = owner_id or user_id
    _node_id = node_id


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/node")
def node_metadata(request: Request):
    import time as _time
    db = request.app.state.db
    public_posts = db.execute("SELECT COUNT(*) FROM posts WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    public_assets = db.execute("SELECT COUNT(*) FROM assets WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    profile_row = db.execute(
        "SELECT display_name, photo_content_hash FROM profile WHERE id = 1"
    ).fetchone()
    week_ago = now_ns() - 7 * 86400 * NS
    posts_7d = db.execute("SELECT COUNT(*) FROM posts WHERE created_at > ? AND deleted = 0", (week_ago,)).fetchone()[0]
    comments_7d = db.execute("SELECT COUNT(*) FROM comments WHERE created_at > ? AND deleted = 0", (week_ago,)).fetchone()[0]
    last_post = db.execute("SELECT MAX(created_at) FROM posts WHERE deleted = 0").fetchone()[0] or 0
    last_comment = db.execute("SELECT MAX(created_at) FROM comments WHERE deleted = 0").fetchone()[0] or 0
    last_reaction = db.execute("SELECT MAX(created_at) FROM reactions").fetchone()[0] or 0
    result = {
        "api_version": 1,
        "extensions": ["reactions", "mention_notifications", "push_subscriptions"],
        "node": _node_address,
        "public_key": _public_key_b64,
        "watermark_policy": "enabled" if _watermark_enabled else "disabled",
        "public_posts": public_posts,
        "public_assets": public_assets,
        "posts_7d": posts_7d,
        "comments_7d": comments_7d,
        "last_activity_at": max(last_post, last_comment, last_reaction),
    }
    if _registry_handle:
        result["handle"] = _registry_handle
    if _owner_id:
        result["owner_id"] = _owner_id
    if _node_id:
        result["node_id"] = _node_id
    if _user_id:
        result["user_id"] = _user_id  # legacy alias
    if profile_row and profile_row[0]:
        result["display_name"] = profile_row[0]
    if profile_row and profile_row[1]:
        result["photo_url"] = f"{_node_address}/profile/photo"
    return result


@router.get("/node/stats")
def node_stats(request: Request, identity: OwnerDep):
    db = request.app.state.db
    total_posts = db.execute("SELECT COUNT(*) FROM posts WHERE deleted = 0").fetchone()[0]
    public_posts = db.execute("SELECT COUNT(*) FROM posts WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    total_assets = db.execute("SELECT COUNT(*) FROM assets WHERE deleted = 0").fetchone()[0]
    public_assets = db.execute("SELECT COUNT(*) FROM assets WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    total_storage = db.execute("SELECT COALESCE(SUM(size), 0) FROM assets WHERE deleted = 0").fetchone()[0]
    recipients = db.execute("SELECT COUNT(*) FROM recipients").fetchone()[0]
    total_comments = db.execute("SELECT COUNT(*) FROM comments WHERE deleted = 0").fetchone()[0]
    return {
        "posts": {"total": total_posts, "public": public_posts, "private": total_posts - public_posts},
        "assets": {"total": total_assets, "public": public_assets, "private": total_assets - public_assets},
        "storage_bytes": total_storage,
        "recipients": recipients,
        "comments": total_comments,
    }

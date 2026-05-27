import base64
from fastapi import APIRouter, Request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .auth import OwnerDep

router = APIRouter()

_node_address: str = ""
_public_key_b64: str = ""
_watermark_enabled: bool = False
_registry_handle: str | None = None


def setup(node_address: str, private_key: Ed25519PrivateKey, watermark_enabled: bool, registry_handle: str | None = None) -> None:
    global _node_address, _public_key_b64, _watermark_enabled, _registry_handle
    _node_address = node_address
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _public_key_b64 = base64.b64encode(pub_bytes).decode()
    _watermark_enabled = watermark_enabled
    _registry_handle = registry_handle


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/node")
def node_metadata(request: Request):
    db = request.app.state.db
    public_posts = db.execute("SELECT COUNT(*) FROM posts WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    public_assets = db.execute("SELECT COUNT(*) FROM assets WHERE is_public = 1 AND deleted = 0").fetchone()[0]
    result = {
        "node": _node_address,
        "public_key": _public_key_b64,
        "watermark_policy": "enabled" if _watermark_enabled else "disabled",
        "public_posts": public_posts,
        "public_assets": public_assets,
    }
    if _registry_handle:
        result["handle"] = _registry_handle
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

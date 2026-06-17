"""FetchAsset, FetchAssetMeta, FetchThumbnail endpoints."""
import io
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .auth import AuthDep, FederatedOrTokenDep, check_acl
from .crypto import decrypt_bytes
from . import watermark as watermark_module
from .watermark import WatermarkError
from .access_log import log_access

router = APIRouter(prefix="/assets")

THUMB_SIZE = (640, 640)


def _build_history_chain(db, asset_id: str) -> list[dict]:
    """Follow predecessor and successor links to build the full version chain."""
    def fetch(id_):
        row = db.execute(
            """SELECT id, content_hash, media_type, size, created_at,
                      title, tags, predecessor, successor, deleted
               FROM assets WHERE id = ?""",
            (id_,),
        ).fetchone()
        if row is None:
            return None
        id_, ch, mt, sz, ca, t, tj, pred, succ, del_ = row
        return {
            "id": id_, "content_hash": ch, "media_type": mt, "size": sz,
            "created_at": ca, "title": t, "tags": json.loads(tj) if tj else [],
            "predecessor": pred, "successor": succ, "deleted": bool(del_),
        }

    current = fetch(asset_id)
    if current is None:
        return []

    chain = [current]
    visited = {asset_id}

    while chain[0]["predecessor"] and chain[0]["predecessor"] not in visited:
        prev = fetch(chain[0]["predecessor"])
        if prev is None:
            break
        visited.add(prev["id"])
        chain.insert(0, prev)

    while chain[-1]["successor"] and chain[-1]["successor"] not in visited:
        nxt = fetch(chain[-1]["successor"])
        if nxt is None:
            break
        visited.add(nxt["id"])
        chain.append(nxt)

    return chain


def _get_asset_row(db, asset_id: str) -> dict | None:
    row = db.execute(
        """SELECT id, content_hash, media_type, size, created_at,
                  title, tags, predecessor, successor, is_public
           FROM assets WHERE id = ? AND deleted = 0""",
        (asset_id,),
    ).fetchone()
    if row is None:
        return None
    id_, content_hash, media_type, size, created_at, title, tags_json, predecessor, successor, is_public = row
    return {
        "id": id_,
        "content_hash": content_hash,
        "media_type": media_type,
        "size": size,
        "created_at": created_at,
        "title": title,
        "tags": json.loads(tags_json) if tags_json else [],
        "predecessor": predecessor,
        "successor": successor,
        "public": bool(is_public),
    }


def _read_content(store_path: Path, content_hash: str, file_key: bytes) -> bytes:
    file_path = store_path / "files" / content_hash[:2] / content_hash
    if not file_path.exists():
        raise FileNotFoundError
    return decrypt_bytes(file_path.read_bytes(), file_key)


def _require_acl(db, asset_id: str, identity, request: Request | None = None):
    if check_acl(db, asset_id, identity):
        return
    if identity.node_id is not None:
        row = db.execute(
            "SELECT p.visibility FROM posts p JOIN post_assets pa ON p.id = pa.post_id "
            "WHERE pa.asset_id = ? "
            "ORDER BY CASE p.visibility WHEN 'public' THEN 0 WHEN 'authenticated' THEN 1 "
            "WHEN 'contacts' THEN 2 ELSE 3 END LIMIT 1",
            (asset_id,),
        ).fetchone()
        if row:
            vis = row[0]
            if vis == "public":
                return
            if vis == "authenticated":
                return
            if vis == "contacts" and identity.is_contact:
                return
    raise HTTPException(status_code=403, detail="Access denied")


def _apply_watermark_if_needed(content: bytes, media_type: str, request: Request, identity) -> bytes:
    if not request.app.state.watermark_enabled or identity.is_owner:
        return content
    if identity.is_share:
        wm_identity = identity.share_identity
    else:
        if not identity.node_id:
            return content
        wm_identity = identity.node_id
    try:
        return watermark_module.apply(content, media_type, wm_identity)
    except WatermarkError:
        raise HTTPException(status_code=500, detail="Watermarking failed")


@router.get("/{asset_id}/meta")
async def fetch_asset_meta(asset_id: str, request: Request, identity: FederatedOrTokenDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity, request)
    log_access(db, asset_id, identity, "fetch_meta")
    asset["node"] = str(request.base_url).rstrip("/")
    return asset


@router.get("/{asset_id}/thumb")
async def fetch_thumbnail(asset_id: str, request: Request, identity: FederatedOrTokenDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity, request)

    if not asset["media_type"].startswith("image/"):
        raise HTTPException(status_code=415, detail="Thumbnail not available for this media type")

    try:
        content = _read_content(
            request.app.state.store_path,
            asset["content_hash"],
            request.app.state.file_key,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Asset content not found")

    from PIL import Image, ImageOps
    img = ImageOps.exif_transpose(Image.open(io.BytesIO(content)))
    img.thumbnail(THUMB_SIZE)
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    thumb_bytes = _apply_watermark_if_needed(buf.getvalue(), "image/jpeg", request, identity)
    log_access(db, asset_id, identity, "fetch_thumbnail")

    return Response(
        content=thumb_bytes,
        media_type="image/jpeg",
        headers={"X-Content-Hash": asset["content_hash"]},
    )


@router.get("/{asset_id}")
async def fetch_asset(asset_id: str, request: Request, identity: FederatedOrTokenDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity, request)

    try:
        content = _read_content(
            request.app.state.store_path,
            asset["content_hash"],
            request.app.state.file_key,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Asset content not found")

    content = _apply_watermark_if_needed(content, asset["media_type"], request, identity)
    log_access(db, asset_id, identity, "fetch_asset")

    return Response(
        content=content,
        media_type=asset["media_type"],
        headers={"X-Content-Hash": asset["content_hash"]},
    )


@router.get("/{asset_id}/history")
async def fetch_asset_history(asset_id: str, request: Request, identity: FederatedOrTokenDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity, request)

    chain = _build_history_chain(db, asset_id)
    return {
        "asset_id": asset_id,
        "count": len(chain),
        "history": [
            {**entry, "is_current": entry["id"] == asset_id}
            for entry in chain
        ],
    }

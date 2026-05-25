"""FetchAsset, FetchAssetMeta, FetchThumbnail endpoints."""
import io
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .auth import AuthDep, check_acl
from .crypto import decrypt_bytes
from . import watermark as watermark_module
from .watermark import WatermarkError

router = APIRouter(prefix="/assets")

THUMB_SIZE = (256, 256)


def _get_asset_row(db, asset_id: str) -> dict | None:
    row = db.execute(
        """SELECT id, content_hash, media_type, size, created_at,
                  title, tags, predecessor, successor
           FROM assets WHERE id = ?""",
        (asset_id,),
    ).fetchone()
    if row is None:
        return None
    id_, content_hash, media_type, size, created_at, title, tags_json, predecessor, successor = row
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
    }


def _read_content(store_path: Path, content_hash: str, file_key: bytes) -> bytes:
    file_path = store_path / "files" / content_hash[:2] / content_hash
    if not file_path.exists():
        raise FileNotFoundError
    return decrypt_bytes(file_path.read_bytes(), file_key)


def _require_acl(db, asset_id: str, identity):
    if not check_acl(db, asset_id, identity):
        raise HTTPException(status_code=403, detail="Access denied")


def _apply_watermark_if_needed(content: bytes, media_type: str, request: Request, identity) -> bytes:
    if not request.app.state.watermark_enabled or identity.is_owner:
        return content
    row = request.app.state.db.execute(
        "SELECT identity FROM recipients WHERE id = ?", (identity.recipient_id,)
    ).fetchone()
    if row is None:
        return content
    try:
        return watermark_module.apply(content, media_type, row[0])
    except WatermarkError:
        raise HTTPException(status_code=500, detail="Watermarking failed")


@router.get("/{asset_id}/meta")
def fetch_asset_meta(asset_id: str, request: Request, identity: AuthDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity)
    asset["node"] = str(request.base_url).rstrip("/")
    return asset


@router.get("/{asset_id}/thumb")
def fetch_thumbnail(asset_id: str, request: Request, identity: AuthDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity)

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

    from PIL import Image
    img = Image.open(io.BytesIO(content))
    img.thumbnail(THUMB_SIZE)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    thumb_bytes = _apply_watermark_if_needed(buf.getvalue(), "image/jpeg", request, identity)

    return Response(
        content=thumb_bytes,
        media_type="image/jpeg",
        headers={"X-Content-Hash": asset["content_hash"]},
    )


@router.get("/{asset_id}")
def fetch_asset(asset_id: str, request: Request, identity: AuthDep):
    db = request.app.state.db
    asset = _get_asset_row(db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    _require_acl(db, asset_id, identity)

    try:
        content = _read_content(
            request.app.state.store_path,
            asset["content_hash"],
            request.app.state.file_key,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Asset content not found")

    content = _apply_watermark_if_needed(content, asset["media_type"], request, identity)

    return Response(
        content=content,
        media_type=asset["media_type"],
        headers={"X-Content-Hash": asset["content_hash"]},
    )

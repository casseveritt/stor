"""FetchAsset, FetchAssetMeta, FetchThumbnail endpoints."""
import io
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from .auth import AuthDep
from .crypto import decrypt_bytes

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


@router.get("/{asset_id}/meta")
def fetch_asset_meta(asset_id: str, request: Request, _auth: AuthDep):
    asset = _get_asset_row(request.app.state.db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    asset["node"] = str(request.base_url).rstrip("/")
    return asset


@router.get("/{asset_id}/thumb")
def fetch_thumbnail(asset_id: str, request: Request, _auth: AuthDep):
    asset = _get_asset_row(request.app.state.db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

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
    return Response(
        content=buf.getvalue(),
        media_type="image/jpeg",
        headers={"X-Content-Hash": asset["content_hash"]},
    )


@router.get("/{asset_id}")
def fetch_asset(asset_id: str, request: Request, _auth: AuthDep):
    asset = _get_asset_row(request.app.state.db, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    try:
        content = _read_content(
            request.app.state.store_path,
            asset["content_hash"],
            request.app.state.file_key,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Asset content not found")

    return Response(
        content=content,
        media_type=asset["media_type"],
        headers={"X-Content-Hash": asset["content_hash"]},
    )

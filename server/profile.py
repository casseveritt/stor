"""Public profile: display name and photo."""
import hashlib
import io
import threading
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import Response
from PIL import Image
from pydantic import BaseModel

from .auth import OwnerDep, OptionalAuthDep
from .crypto import decrypt_bytes, encrypt_bytes

router = APIRouter(prefix="/profile")

MAX_PHOTO_BYTES = 5 * 1024 * 1024
PHOTO_THUMB = (256, 256)


def _get_row(db):
    return db.execute(
        "SELECT display_name, photo_content_hash, photo_media_type FROM profile WHERE id = 1"
    ).fetchone()


def _save(db, display_name, photo_hash, photo_mt):
    db.execute("DELETE FROM profile")
    db.execute(
        "INSERT INTO profile (id, display_name, photo_content_hash, photo_media_type) VALUES (1, ?, ?, ?)",
        (display_name, photo_hash, photo_mt),
    )
    db.commit()


def _photo_url(node_address: str, photo_hash) -> str | None:
    return f"{node_address}/profile/photo" if photo_hash else None


@router.get("")
def get_profile(request: Request):
    from . import node as node_module
    db = request.app.state.db
    node_address = request.app.state.node_address
    row = _get_row(db)
    return {
        "handle": node_module._registry_handle,
        "display_name": row[0] if row else None,
        "photo_url": _photo_url(node_address, row[1] if row else None),
        "public_key": node_module._public_key_b64 or None,
    }


class _ProfileBody(BaseModel):
    display_name: str


@router.put("")
def update_profile(body: _ProfileBody, request: Request, identity: OwnerDep):
    db = request.app.state.db
    row = _get_row(db)
    _save(db, body.display_name, row[1] if row else None, row[2] if row else None)
    fn = getattr(request.app.state, "trigger_heartbeat", None)
    if fn:
        threading.Thread(target=fn, daemon=True).start()
    return {
        "display_name": body.display_name,
        "photo_url": _photo_url(request.app.state.node_address, row[1] if row else None),
    }


@router.put("/photo")
async def update_photo(request: Request, identity: OwnerDep, file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_PHOTO_BYTES:
        raise HTTPException(status_code=413, detail="Photo too large (max 5 MB)")
    media_type = (file.content_type or "").lower()
    if not media_type.startswith("image/"):
        raise HTTPException(status_code=415, detail="Photo must be an image")

    # Convert to JPEG at ingest — normalises WebP, PNG, HEIC, etc.
    try:
        from PIL import ImageOps
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(raw)))
        img.thumbnail(PHOTO_THUMB)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=90)
        content = buf.getvalue()
    except Exception:
        raise HTTPException(status_code=415, detail="Could not decode image")

    content_hash = hashlib.sha256(content).hexdigest()
    store_path: Path = request.app.state.store_path
    file_dir = store_path / "files" / content_hash[:2]
    file_dir.mkdir(parents=True, exist_ok=True)
    file_path = file_dir / content_hash
    if not file_path.exists():
        file_path.write_bytes(encrypt_bytes(content, request.app.state.file_key))

    db = request.app.state.db
    row = _get_row(db)
    _save(db, row[0] if row else None, content_hash, "image/jpeg")

    fn = getattr(request.app.state, "trigger_heartbeat", None)
    if fn:
        threading.Thread(target=fn, daemon=True).start()

    return {"content_hash": content_hash}


class _PrivateKeyBody(BaseModel):
    passphrase: str


@router.post("/private-key")
def get_private_key(body: _PrivateKeyBody, request: Request, identity: OwnerDep):
    private_key = getattr(request.app.state, "private_key", None)
    if not private_key:
        raise HTTPException(status_code=503, detail="Node is locked — private key not available")
    # Verify passphrase by re-deriving and comparing public keys
    try:
        from .config import NodeConfig
        from .crypto import derive_master_key, decrypt_bytes
        import base64
        config = NodeConfig.load(request.app.state.config_path)
        salt = bytes.fromhex(config.argon2_salt)
        master_key = derive_master_key(body.passphrase, salt,
                                       config.argon2_time_cost,
                                       config.argon2_memory_cost,
                                       config.argon2_parallelism)
        privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    except Exception:
        raise HTTPException(status_code=401, detail="Wrong passphrase")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    verified_key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    pem = verified_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=contacc-private-key.pem"},
    )


@router.get("/photo")
def get_photo(request: Request, identity: OptionalAuthDep):
    # Allow: owner Bearer token, federated X-Public-Key, or own-client proxy (x-contacc-internal).
    # The middleware already validates x-contacc-internal; its presence here means the request
    # came through the local client, which is sufficient for "authenticated" visibility.
    if (not (identity and identity.is_owner)
            and not request.headers.get("X-Public-Key")
            and not request.headers.get("x-contacc-internal")):
        raise HTTPException(status_code=403, detail="Profile photo requires authentication")
    db = request.app.state.db
    row = _get_row(db)
    if not row or not row[1]:
        raise HTTPException(status_code=404, detail="No profile photo set")

    content_hash, media_type = row[1], row[2] or "image/jpeg"
    store_path: Path = request.app.state.store_path
    file_path = store_path / "files" / content_hash[:2] / content_hash
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Photo file not found")

    raw = decrypt_bytes(file_path.read_bytes(), request.app.state.file_key)

    # New uploads are pre-converted to JPEG; legacy stored files may be other formats.
    media_type = row[2] or "image/jpeg"
    if media_type == "image/jpeg":
        content = raw
    else:
        img = Image.open(io.BytesIO(raw))
        img.thumbnail(PHOTO_THUMB)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        content = buf.getvalue()

    return Response(
        content=content,
        media_type="image/jpeg",
        headers={"Cache-Control": "public, max-age=3600"},
    )

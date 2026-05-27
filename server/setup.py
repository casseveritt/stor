"""First-run setup, unlock, and restore endpoints."""
import base64
import io
import json
import os
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from .crypto import decrypt_bytes, derive_master_key
from .db import WrongPassphraseError

router = APIRouter(prefix="/setup")


def _state(app) -> str:
    if not Path(app.state.config_path).exists():
        return "uninitialized"
    if not app.state.initialized:
        return "locked"
    return "running"


@router.get("/status")
def setup_status(request: Request):
    return {"state": _state(request.app)}


class NewBody(BaseModel):
    passphrase: str
    confirm_passphrase: str
    owner_identity: str


@router.post("/new")
def setup_new(body: NewBody, request: Request):
    app = request.app
    if _state(app) != "uninitialized":
        raise HTTPException(400, "Server already initialized")
    if body.passphrase != body.confirm_passphrase:
        raise HTTPException(400, "Passphrases do not match")
    if not body.owner_identity.startswith("google:"):
        raise HTTPException(400, "Owner identity must be in the form google:you@example.com")

    config_path = Path(app.state.config_path)
    node_address = app.state.node_address or ""
    identity_proxy_url = os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://starkville.hopto.org:8421")

    _create_node_config(config_path, node_address, identity_proxy_url, body.owner_identity, body.passphrase)

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    return {"status": "ok", "node_address": node_address}


class UnlockBody(BaseModel):
    passphrase: str


@router.post("/unlock")
def setup_unlock(body: UnlockBody, request: Request):
    app = request.app
    if _state(app) == "running":
        return {"status": "ok"}
    if _state(app) == "uninitialized":
        raise HTTPException(400, "Server not initialized — use /setup/new first")
    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(403, "Wrong passphrase")
    return {"status": "ok"}


@router.post("/restore")
async def setup_restore(request: Request, bundle: UploadFile = File(...), passphrase: str = Form(...)):
    app = request.app
    if _state(app) == "running":
        raise HTTPException(400, "Server already running — stop it before restoring")

    data = await bundle.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid bundle: not a zip file")

    names = zf.namelist()
    if "node_config.json" not in names:
        raise HTTPException(400, "Invalid bundle: missing node_config.json")
    if "db" not in names:
        raise HTTPException(400, "Invalid bundle: missing db")

    # Verify passphrase before writing anything
    try:
        config_data = json.loads(zf.read("node_config.json"))
        salt = bytes.fromhex(config_data["argon2_salt"])
        master_key = derive_master_key(
            passphrase, salt,
            config_data.get("argon2_time_cost", 3),
            config_data.get("argon2_memory_cost", 65536),
            config_data.get("argon2_parallelism", 4),
        )
        decrypt_bytes(base64.b64decode(config_data["encrypted_private_key"]), master_key)
    except (InvalidTag, KeyError, ValueError):
        raise HTTPException(403, "Wrong passphrase or invalid bundle")

    # Extract to data directory
    store_path = Path(app.state.config_path).parent
    for name in names:
        dest = store_path / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zf.read(name))

    try:
        app.state.do_initialize(passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after restore")

    return {"status": "ok"}


def _create_node_config(
    config_path: Path,
    node_address: str,
    identity_proxy_url: str,
    owner_identity: str,
    passphrase: str,
) -> None:
    """Generate keys, initialize DB, and write node_config.json."""
    import os as _os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from .crypto import (
        derive_master_key as _derive, derive_subkeys, encrypt_bytes,
        ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    )
    from .db import open_db, init_schema

    store_path = config_path.parent
    store_path.mkdir(parents=True, exist_ok=True)
    (store_path / "files").mkdir(exist_ok=True)

    salt = _os.urandom(16)
    master_key = _derive(passphrase, salt)
    db_key, _ = derive_subkeys(master_key)

    private_key = Ed25519PrivateKey.generate()
    privkey_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted_privkey = encrypt_bytes(privkey_bytes, master_key)

    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)
    db_con.close()

    config = {
        "node_address": node_address,
        "store_path": str(store_path),
        "argon2_salt": salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "watermark_enabled": False,
        "sso_owner_identity": owner_identity,
        "identity_proxy_url": identity_proxy_url,
    }
    config_path.write_text(json.dumps(config, indent=2))

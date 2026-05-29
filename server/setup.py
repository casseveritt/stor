"""First-run setup, unlock, and restore endpoints."""
import base64
import io
import json
import os
import re
import secrets
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from .auth import OwnerDep
from .config import NodeConfig
from .crypto import (
    decrypt_bytes, derive_master_key, derive_subkeys, encrypt_bytes,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
)
from .db import WrongPassphraseError

router = APIRouter(prefix="/setup")

log = __import__("logging").getLogger("contacc")


def _state(app) -> str:
    if not Path(app.state.config_path).exists():
        return "uninitialized"
    if not app.state.initialized:
        return "locked"
    return "running"


def _setup_token_path(app) -> Path:
    return Path(app.state.config_path).parent / ".setup_token"


def ensure_setup_token(app) -> str:
    """Return the setup token, generating and persisting it if needed."""
    token_path = _setup_token_path(app)
    if token_path.exists():
        token = token_path.read_text().strip()
    else:
        token = secrets.token_urlsafe(24)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token)
    log.info("=" * 60)
    log.info("SETUP TOKEN: %s", token)
    log.info("Open the server URL and enter this token to initialize.")
    log.info("=" * 60)
    return token


def _validate_token(app, token: str) -> None:
    token_path = _setup_token_path(app)
    if not token_path.exists():
        raise HTTPException(status_code=403, detail="Setup token not found — server may already be initialized")
    expected = token_path.read_text().strip()
    if not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=403, detail="Invalid setup token")


def _consume_token(app) -> None:
    _setup_token_path(app).unlink(missing_ok=True)


@router.get("/status")
def setup_status(request: Request):
    return {"state": _state(request.app)}


_HANDLE_RE = re.compile(r'^[a-z_][a-z0-9_]*$')


def _validate_handle_format(handle: str) -> None:
    h = handle.lower()
    if not _HANDLE_RE.match(h):
        raise HTTPException(400, "Handle must start with a letter or _, followed by letters, digits, or _")


@router.get("/check-handle")
def check_handle(handle: str, request: Request):
    """Return 200 if handle is available, 400 if taken, 502 if registry unreachable."""
    handle = handle.lower()
    _validate_handle_format(handle)
    identity_proxy_url = os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://starkville.hopto.org:8421")
    registry_url = os.environ.get("CONTACC_REGISTRY_URL", identity_proxy_url)
    _check_handle_available(handle, registry_url)
    return {"available": True, "handle": handle}


class NewBody(BaseModel):
    passphrase: str
    confirm_passphrase: str
    owner_identity: str
    setup_token: str
    handle: str


def _check_handle_available(handle: str, registry_url: str) -> None:
    """Raise HTTPException if handle is already registered."""
    import httpx
    try:
        r = httpx.get(f"{registry_url}/lookup/{handle}", timeout=5)
        if r.status_code == 200:
            raise HTTPException(400, f"Handle '{handle}' is already taken")
        if r.status_code != 404:
            raise HTTPException(502, "Registry returned an unexpected response — try again")
    except httpx.RequestError as exc:
        raise HTTPException(502, f"Could not reach registry: {exc}")


@router.post("/new")
def setup_new(body: NewBody, request: Request):
    app = request.app
    if _state(app) != "uninitialized":
        raise HTTPException(400, "Server already initialized")
    _validate_token(app, body.setup_token)
    if body.passphrase != body.confirm_passphrase:
        raise HTTPException(400, "Passphrases do not match")
    if not body.owner_identity.startswith("google:"):
        raise HTTPException(400, "Owner identity must be in the form google:you@example.com")
    if not body.handle:
        raise HTTPException(400, "Handle is required")
    body.handle = body.handle.lower()
    _validate_handle_format(body.handle)

    config_path = Path(app.state.config_path)
    node_address = app.state.node_address or ""
    identity_proxy_url = os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://starkville.hopto.org:8421")
    registry_url = os.environ.get("CONTACC_REGISTRY_URL", identity_proxy_url)

    _check_handle_available(body.handle, registry_url)

    key_material = _create_node_config(config_path, node_address, identity_proxy_url, body.owner_identity, body.passphrase, body.handle)

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    _consume_token(app)
    return {
        "status": "ok",
        "node_address": node_address,
        "node_key": {
            "argon2_salt": key_material["argon2_salt"],
            "argon2_time_cost": key_material["argon2_time_cost"],
            "argon2_memory_cost": key_material["argon2_memory_cost"],
            "argon2_parallelism": key_material["argon2_parallelism"],
            "encrypted_private_key": key_material["encrypted_private_key"],
        },
        "internal_token": key_material["internal_token"],
    }


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
async def setup_restore(request: Request, bundle: UploadFile = File(...), passphrase: str = Form(...), setup_token: str = Form(...)):
    app = request.app
    if _state(app) == "running":
        raise HTTPException(400, "Server already running — stop it before restoring")
    if _state(app) == "uninitialized":
        _validate_token(app, setup_token)

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

    # Ensure internal_token exists (may be absent in older backups)
    store_path = Path(app.state.config_path).parent
    config_path = store_path / "node_config.json"
    config_data = json.loads(config_path.read_text())
    if "internal_token" not in config_data:
        config_data["internal_token"] = secrets.token_urlsafe(32)
        config_path.write_text(json.dumps(config_data, indent=2))

    try:
        app.state.do_initialize(passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after restore")

    _consume_token(app)
    return {
        "status": "ok",
        "node_key": {
            "argon2_salt": config_data["argon2_salt"],
            "argon2_time_cost": config_data.get("argon2_time_cost", 3),
            "argon2_memory_cost": config_data.get("argon2_memory_cost", 65536),
            "argon2_parallelism": config_data.get("argon2_parallelism", 4),
            "encrypted_private_key": config_data["encrypted_private_key"],
        },
        "internal_token": config_data["internal_token"],
    }


class ChangePassphraseBody(BaseModel):
    current_passphrase: str
    new_passphrase: str
    confirm_new_passphrase: str


@router.post("/change-passphrase")
def change_passphrase(body: ChangePassphraseBody, request: Request, identity: OwnerDep):
    if body.new_passphrase != body.confirm_new_passphrase:
        raise HTTPException(400, "New passphrases do not match")
    if not body.new_passphrase:
        raise HTTPException(400, "New passphrase cannot be empty")

    app = request.app
    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)

    # Verify current passphrase
    old_salt = bytes.fromhex(config.argon2_salt)
    old_master_key = derive_master_key(
        body.current_passphrase, old_salt,
        config.argon2_time_cost, config.argon2_memory_cost, config.argon2_parallelism,
    )
    try:
        privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), old_master_key)
    except Exception:
        raise HTTPException(403, "Wrong current passphrase")

    _, old_file_key = derive_subkeys(old_master_key)

    # Derive new keys
    new_salt = os.urandom(16)
    new_master_key = derive_master_key(body.new_passphrase, new_salt)
    new_db_key, new_file_key = derive_subkeys(new_master_key)

    # Re-encrypt all asset files in place
    store_path = Path(config.store_path)
    files_dir = store_path / "files"
    if files_dir.exists():
        for fpath in files_dir.rglob("*"):
            if not fpath.is_file():
                continue
            try:
                plaintext = decrypt_bytes(fpath.read_bytes(), old_file_key)
                fpath.write_bytes(encrypt_bytes(plaintext, new_file_key))
            except Exception as exc:
                raise HTTPException(500, f"Failed to re-encrypt {fpath.name}: {exc}")

    # Rekey the SQLCipher database
    app.state.db.execute(f"PRAGMA rekey = \"x'{new_db_key.hex()}'\"")
    app.state.db.commit()

    # Update node_config.json
    import json as _json
    config_data = _json.loads(config_path.read_text())
    config_data["argon2_salt"] = new_salt.hex()
    config_data["argon2_time_cost"] = ARGON2_TIME_COST
    config_data["argon2_memory_cost"] = ARGON2_MEMORY_COST
    config_data["argon2_parallelism"] = ARGON2_PARALLELISM
    config_data["encrypted_private_key"] = base64.b64encode(encrypt_bytes(privkey_bytes, new_master_key)).decode()
    config_path.write_text(_json.dumps(config_data, indent=2))

    # Update running state
    app.state.file_key = new_file_key

    return {"status": "ok"}


def _create_node_config(
    config_path: Path,
    node_address: str,
    identity_proxy_url: str,
    owner_identity: str,
    passphrase: str,
    handle: str,
) -> dict:
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

    internal_token = secrets.token_urlsafe(32)
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
        "registry_handle": handle,
        "internal_token": internal_token,
    }
    config_path.write_text(json.dumps(config, indent=2))
    return {
        "argon2_salt": salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "internal_token": internal_token,
    }

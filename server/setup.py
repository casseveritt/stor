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


@router.get("/passphrase-is-default")
def passphrase_is_default(request: Request):
    """Returns true if the node passphrase is still the default 'foobar'."""
    config_path = request.app.state.config_path
    try:
        import json as _j
        config_data = _j.loads(Path(config_path).read_text())
        salt = bytes.fromhex(config_data["argon2_salt"])
        master_key = derive_master_key(
            "foobar", salt,
            config_data.get("argon2_time_cost", 3),
            config_data.get("argon2_memory_cost", 65536),
            config_data.get("argon2_parallelism", 4),
        )
        decrypt_bytes(base64.b64decode(config_data["encrypted_private_key"]), master_key)
        return {"is_default": True}
    except Exception:
        return {"is_default": False}


_HANDLE_RE = re.compile(r'^[a-z_][a-z0-9_]*$')


def _validate_handle_format(handle: str) -> None:
    h = handle.lower()
    if not _HANDLE_RE.match(h):
        raise HTTPException(400, "Handle must start with a letter or _, followed by letters, digits, or _")


class NewBody(BaseModel):
    passphrase: str
    confirm_passphrase: str
    owner_identity: str
    setup_token: str
    handle: str
    display_name: str = ""
    tang_enabled: bool = True


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

    key_material = _create_node_config(config_path, node_address, identity_proxy_url, body.owner_identity, body.passphrase, body.handle, display_name=body.display_name, tang_enabled=body.tang_enabled)

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    # Register with the registry directly using fresh key material, then upload escrow.
    # We do this ourselves rather than waiting for the background heartbeat thread to avoid
    # a race where the escrow upload fires before the handles entry exists.
    _id_key_hex = key_material.pop("_identity_key_hex", None)
    _reg_url = key_material.pop("_registry_url", "")
    if _id_key_hex and _reg_url:
        try:
            import os as _os2, time as _time2, httpx as _hx_e, json as _json_e
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
            from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PrivateFormat as _PF, PublicFormat as _PuF, NoEncryption as _NE
            from .identity import identity_key_from_hex as _ikfh
            from .crypto import ARGON2_TIME_COST as _TC, ARGON2_MEMORY_COST as _MC, ARGON2_PARALLELISM as _PAR

            # Reconstruct node private key from encrypted key material
            _node_priv_bytes = decrypt_bytes(
                base64.b64decode(key_material["encrypted_private_key"]),
                derive_master_key(body.passphrase, bytes.fromhex(key_material["argon2_salt"]), _TC, _MC, _PAR)
            )
            _node_key = _Ed.from_private_bytes(_node_priv_bytes)
            _node_pub_b64 = base64.b64encode(_node_key.public_key().public_bytes(_Enc.Raw, _PuF.Raw)).decode()
            _uid = key_material.get("owner_id") or key_material.get("user_id")
            _dcert = _json_e.loads(Path(config_path).read_text()).get("identity_delegation")

            # Register node with registry
            ts_r = int(_time2.time())
            reg_msg = f"contacc:register:{body.handle}:{node_address}:{ts_r}"
            reg_sig = base64.b64encode(_node_key.sign(reg_msg.encode())).decode()
            web_address = app.state.web_address or ""
            _hx_e.post(f"{_reg_url.rstrip('/')}/register/{body.handle}", json={
                "server_url": node_address, "public_key": _node_pub_b64,
                "ttl": 14400, "timestamp": ts_r, "signature": reg_sig,
                "display_name": body.display_name or None,
                "web_url": web_address or None,
                "delegation_cert": _json_e.loads(_dcert) if _dcert else None,
                "google_identity": body.owner_identity,
            }, timeout=10)

            # Upload escrow now that the handles entry exists
            _ik = _ikfh(_id_key_hex)
            escrow_salt = _os2.urandom(16)
            escrow_key = derive_master_key(body.passphrase, escrow_salt, _TC, _MC, _PAR)
            enc_id_key = base64.b64encode(encrypt_bytes(bytes.fromhex(_id_key_hex), escrow_key)).decode()
            ts_e = int(_time2.time())
            escrow_sig = base64.b64encode(_ik.sign(f"contacc:escrow:{_uid}:{ts_e}".encode())).decode()
            r_e = _hx_e.put(f"{_reg_url.rstrip('/')}/identity-key/{_uid}", json={
                "encrypted_identity_key": enc_id_key,
                "argon2_salt": escrow_salt.hex(),
                "argon2_time_cost": _TC, "argon2_memory_cost": _MC, "argon2_parallelism": _PAR,
                "signature": escrow_sig, "timestamp": ts_e,
            }, timeout=10)
            if not r_e.is_success:
                log.warning("Escrow upload failed: %s %s", r_e.status_code, r_e.text)
        except Exception as _ee:
            log.warning("Escrow upload failed: %s", _ee)

    _consume_token(app)
    return {
        "status": "ok",
        "node_address": node_address,
        "node_id": key_material["node_id"],
        "node_key": {
            "argon2_salt": key_material["argon2_salt"],
            "argon2_time_cost": key_material["argon2_time_cost"],
            "argon2_memory_cost": key_material["argon2_memory_cost"],
            "argon2_parallelism": key_material["argon2_parallelism"],
            "encrypted_private_key": key_material["encrypted_private_key"],
        },
        "internal_token": key_material["internal_token"],
    }


class NewForOwnerBody(BaseModel):
    passphrase: str
    confirm_passphrase: str
    owner_identity: str       # google:...
    setup_token: str
    handle: str
    display_name: str = ""
    tang_enabled: bool = True
    existing_owner_id: str    # the owner's owner_id UUID
    owner_passphrase: str     # decrypts the identity key escrow


@router.post("/new-for-owner")
def setup_new_for_owner(body: NewForOwnerBody, request: Request):
    """Set up a new node for an existing owner. Fetches identity key from registry escrow,
    signs a new delegation cert, and registers as a new node under the same owner_id."""
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

    # Fetch identity key escrow from registry and decrypt with owner passphrase
    import httpx as _hx_o, uuid as _uuid_o
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK_o
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc_o, PublicFormat as _PuF_o
    from .identity import make_delegation_cert as _mkdel_o, identity_key_from_hex as _ikfh_o

    r_escrow = _hx_o.get(f"{registry_url.rstrip('/')}/identity-key/{body.existing_owner_id}", timeout=10)
    if not r_escrow.is_success:
        raise HTTPException(400, "Could not fetch identity key escrow for that owner ID — has the owner set up account recovery?")

    escrow = r_escrow.json()
    try:
        old_salt = bytes.fromhex(escrow["argon2_salt"])
        escrow_key = derive_master_key(body.owner_passphrase, old_salt,
                                       escrow.get("argon2_time_cost", ARGON2_TIME_COST),
                                       escrow.get("argon2_memory_cost", ARGON2_MEMORY_COST),
                                       escrow.get("argon2_parallelism", ARGON2_PARALLELISM))
        id_priv_bytes = decrypt_bytes(base64.b64decode(escrow["encrypted_identity_key"]), escrow_key)
        identity_key = _EK_o.from_private_bytes(id_priv_bytes)
    except Exception:
        raise HTTPException(403, "Wrong owner passphrase")

    # Generate fresh node credentials (new node_id, new node key pair)
    import uuid as _uuid2, os as _os3
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _NK
    from cryptography.hazmat.primitives.serialization import PrivateFormat as _PrF_o, NoEncryption as _NE_o

    new_node_id = str(_uuid2.uuid4())
    node_key = _NK.generate()
    node_priv_bytes = node_key.private_bytes(_Enc_o.Raw, _PrF_o.Raw, _NE_o())
    salt = _os3.urandom(16)
    master_key = derive_master_key(body.passphrase, salt)
    encrypted_privkey = encrypt_bytes(node_priv_bytes, master_key)
    db_key, _ = derive_subkeys(master_key)

    from .db import open_db, init_schema
    store_path = config_path.parent
    store_path.mkdir(parents=True, exist_ok=True)
    import shutil as _sh
    if (store_path / "db").exists():
        _sh.rmtree(store_path / "db")
    (store_path / "files").mkdir(exist_ok=True)

    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)
    if body.display_name:
        db_con.execute("INSERT OR REPLACE INTO profile (id, display_name) VALUES (1, ?)", (body.display_name,))
        db_con.commit()
    db_con.close()

    node_pub_b64 = base64.b64encode(node_key.public_key().public_bytes(_Enc_o.Raw, _PuF_o.Raw)).decode()
    id_pub_b64 = base64.b64encode(identity_key.public_key().public_bytes(_Enc_o.Raw, _PuF_o.Raw)).decode()
    delegation_cert = _mkdel_o(identity_key, body.existing_owner_id, node_pub_b64, node_id=new_node_id)
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
        "sso_owner_identity": body.owner_identity,
        "identity_proxy_url": identity_proxy_url,
        "registry_handle": body.handle,
        "internal_token": internal_token,
        "owner_id": body.existing_owner_id,
        "node_id": new_node_id,
        "identity_public_key": id_pub_b64,
        "identity_delegation": json.dumps(delegation_cert),
        "tang_enabled": body.tang_enabled,
    }

    # Tang registration
    tang_C = tang_E = tang_url_stored = None
    if body.tang_enabled:
        try:
            import time as _t2
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X2, X25519PublicKey as _XP2
            from cryptography.hazmat.primitives.serialization import Encoding as _E2, PublicFormat as _PF2
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _H2
            from cryptography.hazmat.primitives.hashes import SHA256 as _S2
            ts = int(_t2.time())
            tang_msg = f"contacc:tang:register:{new_node_id}:{ts}"
            tang_sig = base64.b64encode(identity_key.sign(tang_msg.encode())).decode()
            r_tang = _hx_o.post(f"{registry_url.rstrip('/')}/tang/register", json={
                "node_id": new_node_id, "identity_public_key": id_pub_b64,
                "timestamp": ts, "signature": tang_sig,
            }, timeout=10)
            if r_tang.is_success:
                T_pub = _XP2.from_public_bytes(base64.b64decode(r_tang.json()["T_pub"]))
                c_priv = _X2.generate()
                S_bytes = c_priv.exchange(T_pub)
                K = _H2(_S2(), 32, None, b"contacc-tang-unlock").derive(S_bytes)
                tang_C = base64.b64encode(c_priv.public_key().public_bytes(_E2.Raw, _PF2.Raw)).decode()
                tang_E = base64.b64encode(encrypt_bytes(body.passphrase.encode(), K)).decode()
                tang_url_stored = registry_url.rstrip("/")
        except Exception as _te:
            log.warning("Tang setup failed for new-for-owner node: %s", _te)

    if tang_C:
        config["tang_C"] = tang_C
        config["tang_E"] = tang_E
        config["tang_url"] = tang_url_stored

    config_path.write_text(json.dumps(config, indent=2))

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    # Register with registry
    try:
        import time as _t3, json as _j3
        ts_r = int(_t3.time())
        reg_msg = f"contacc:register:{body.handle}:{node_address}:{ts_r}"
        reg_sig = base64.b64encode(node_key.sign(reg_msg.encode())).decode()
        web_address = app.state.web_address or ""
        _hx_o.post(f"{registry_url.rstrip('/')}/register/{body.handle}", json={
            "server_url": node_address, "public_key": node_pub_b64,
            "ttl": 14400, "timestamp": ts_r, "signature": reg_sig,
            "display_name": body.display_name or None,
            "web_url": web_address or None,
            "delegation_cert": delegation_cert,
            "google_identity": body.owner_identity,
        }, timeout=10)
    except Exception as _re:
        log.warning("Registry registration failed for new-for-owner node: %s", _re)

    _consume_token(app)
    return {
        "status": "ok",
        "node_address": node_address,
        "node_id": new_node_id,
        "node_key": {
            "argon2_salt": salt.hex(),
            "argon2_time_cost": ARGON2_TIME_COST,
            "argon2_memory_cost": ARGON2_MEMORY_COST,
            "argon2_parallelism": ARGON2_PARALLELISM,
            "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        },
        "internal_token": internal_token,
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
    tang_enabled: bool = True   # whether to (re-)bind Tang with the new passphrase


@router.post("/change-passphrase")
def change_passphrase(body: ChangePassphraseBody, request: Request):
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
    # Re-encrypt DH key if present
    if config_data.get("encrypted_dh_private_key"):
        try:
            dh_raw = decrypt_bytes(base64.b64decode(config_data["encrypted_dh_private_key"]), old_master_key)
            config_data["encrypted_dh_private_key"] = base64.b64encode(encrypt_bytes(dh_raw, new_master_key)).decode()
        except Exception:
            pass  # non-fatal; DH key will be regenerated at next startup
    config_path.write_text(_json.dumps(config_data, indent=2))

    # Update running state
    app.state.file_key = new_file_key

    # Re-bind (or clear) Tang with the new passphrase
    import json as _json2
    config_data2 = _json2.loads(config_path.read_text())
    if body.tang_enabled and not config.tang_C and (config.node_id or config.user_id) and app.state.private_key:
        # First-time Tang registration for this node
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519PK2, X25519PublicKey as _X25519Pub2
            from cryptography.hazmat.primitives.serialization import Encoding as _E4, PublicFormat as _PF4
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF4
            from cryptography.hazmat.primitives.hashes import SHA256 as _SHA4
            import httpx as _hx3, time as _t3
            registry_url = (config.tang_url or config.identity_proxy_url or "").rstrip("/")
            if registry_url:
                ts3 = int(_t3.time())
                node_pub_b64_reg = base64.b64encode(
                    app.state.private_key.public_key().public_bytes(_E4.Raw, _PF4.Raw)
                ).decode()
                reg_msg = f"contacc:tang:register:{(config.node_id or config.user_id)}:{ts3}"
                reg_sig = base64.b64encode(app.state.private_key.sign(reg_msg.encode())).decode()
                r_reg = _hx3.post(f"{registry_url}/tang/register", json={
                    "node_id": (config.node_id or config.user_id), "identity_public_key": node_pub_b64_reg,
                    "timestamp": ts3, "signature": reg_sig,
                }, timeout=10)
                if r_reg.is_success:
                    T_pub_bytes = base64.b64decode(r_reg.json()["T_pub"])
                    c_priv_new = _X25519PK2.generate()
                    C_pub_bytes_new = c_priv_new.public_key().public_bytes(_E4.Raw, _PF4.Raw)
                    T_pub_key = _X25519Pub2.from_public_bytes(T_pub_bytes)
                    S_bytes_new = c_priv_new.exchange(T_pub_key)
                    K_new2 = _HKDF4(_SHA4(), 32, None, b"contacc-tang-unlock").derive(S_bytes_new)
                    config_data2["tang_C"] = base64.b64encode(C_pub_bytes_new).decode()
                    config_data2["tang_E"] = base64.b64encode(
                        encrypt_bytes(body.new_passphrase.encode(), K_new2)
                    ).decode()
                    config_data2["tang_url"] = registry_url
                    config_data2["tang_enabled"] = True
                    log.info("Tang registered for existing node during passphrase change")
        except Exception as _te:
            log.warning("Could not register Tang during passphrase change: %s", _te)
    elif body.tang_enabled and config.tang_C and (config.node_id or config.user_id) and app.state.private_key:
        try:
            from cryptography.hazmat.primitives.serialization import Encoding as _E3, PublicFormat as _PF3
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF3
            from cryptography.hazmat.primitives.hashes import SHA256 as _SHA3
            import httpx as _hx2, time as _t2
            registry_url = (config.tang_url or config.identity_proxy_url or "").rstrip("/")
            if registry_url:
                # Use /tang/exchange-direct: node signs the request, registry returns S inline
                ts2 = int(_t2.time())
                node_pub_b64 = base64.b64encode(
                    app.state.private_key.public_key().public_bytes(_E3.Raw, _PF3.Raw)
                ).decode()
                sig_msg = f"contacc:tang:direct:{(config.node_id or config.user_id)}:{config.tang_C}:{ts2}"
                sig = base64.b64encode(app.state.private_key.sign(sig_msg.encode())).decode()
                r = _hx2.post(f"{registry_url}/tang/exchange-direct", json={
                    "node_id": (config.node_id or config.user_id), "C": config.tang_C,
                    "node_public_key": node_pub_b64,
                    "timestamp": ts2, "signature": sig,
                }, timeout=10)
                if r.is_success:
                    S_bytes = base64.b64decode(r.json()["S"])
                    K_new = _HKDF3(_SHA3(), 32, None, b"contacc-tang-unlock").derive(S_bytes)
                    config_data2["tang_E"] = base64.b64encode(
                        encrypt_bytes(body.new_passphrase.encode(), K_new)
                    ).decode()
                    config_data2["tang_enabled"] = True
        except Exception as _te:
            log.warning("Could not re-bind Tang after passphrase change: %s", _te)
    elif not body.tang_enabled:
        config_data2.pop("tang_C", None)
        config_data2.pop("tang_E", None)
        config_data2.pop("tang_url", None)
        config_data2["tang_enabled"] = False

    config_path.write_text(_json2.dumps(config_data2, indent=2))

    return {
        "status": "ok",
        "node_key": {
            "argon2_salt": new_salt.hex(),
            "encrypted_private_key": base64.b64encode(encrypt_bytes(privkey_bytes, new_master_key)).decode(),
            "argon2_time_cost": ARGON2_TIME_COST,
            "argon2_memory_cost": ARGON2_MEMORY_COST,
            "argon2_parallelism": ARGON2_PARALLELISM,
        },
    }


def _create_node_config(
    config_path: Path,
    node_address: str,
    identity_proxy_url: str,
    owner_identity: str,
    passphrase: str,
    handle: str,
    display_name: str = "",
    tang_enabled: bool = True,
) -> dict:
    """Generate keys, initialize DB, and write node_config.json."""
    import os as _os
    import uuid as _uuid
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
    from .crypto import (
        derive_master_key as _derive, derive_subkeys, encrypt_bytes,
        ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    )
    from .db import open_db, init_schema

    store_path = config_path.parent
    store_path.mkdir(parents=True, exist_ok=True)

    # Remove any partial state from a previous failed setup attempt
    import shutil as _shutil
    db_path = store_path / "db"
    if db_path.exists():
        _shutil.rmtree(db_path)
    (store_path / "files").mkdir(exist_ok=True)

    salt = _os.urandom(16)
    master_key = _derive(passphrase, salt)
    db_key, _ = derive_subkeys(master_key)

    private_key = Ed25519PrivateKey.generate()
    privkey_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted_privkey = encrypt_bytes(privkey_bytes, master_key)

    from .identity import make_delegation_cert, identity_key_to_hex

    # Generate identity key pair — private key is NEVER stored on the node
    identity_key = Ed25519PrivateKey.generate()
    identity_pubkey_bytes = identity_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # owner_id identifies the person (permanent, registry); node_id identifies this deployment
    owner_id = str(_uuid.uuid4())
    node_id = str(_uuid.uuid4())

    # Sign delegation cert (1 year validity) — this is what lives on the node
    node_pub_b64 = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    delegation_cert = make_delegation_cert(identity_key, owner_id, node_pub_b64, node_id=node_id)

    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)
    if display_name:
        db_con.execute("INSERT OR REPLACE INTO profile (id, display_name) VALUES (1, ?)", (display_name,))
        db_con.commit()
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
        "owner_id": owner_id,
        "node_id": node_id,
        "identity_public_key": base64.b64encode(identity_pubkey_bytes).decode(),
        "identity_delegation": json.dumps(delegation_cert),
        # identity private key is NOT stored — returned once to caller for safekeeping
        "tang_enabled": tang_enabled,
    }

    # Generate X25519 DH key pair for DM thread key derivation
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519
    from cryptography.hazmat.primitives.serialization import PrivateFormat as _PrF2, NoEncryption as _NE2
    dh_priv = _X25519.generate()
    dh_priv_bytes = dh_priv.private_bytes(Encoding.Raw, _PrF2.Raw, _NE2())
    config["encrypted_dh_private_key"] = base64.b64encode(encrypt_bytes(dh_priv_bytes, master_key)).decode()

    # Tang network-bound unlock (opt-in, default True)
    tang_C = tang_E = tang_url_stored = None
    registry_url = identity_proxy_url.rstrip("/") if identity_proxy_url else ""
    if tang_enabled and registry_url:
        try:
            import time as _time
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding as _E2, PublicFormat as _PF2, PrivateFormat as _PrF, NoEncryption as _NE2
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
            from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
            # Register with Tang — authenticate with identity key
            ts = int(_time.time())
            tang_msg = f"contacc:tang:register:{node_id}:{ts}"
            tang_sig = base64.b64encode(identity_key.sign(tang_msg.encode())).decode()
            id_pub_b64 = base64.b64encode(identity_pubkey_bytes).decode()
            import httpx as _httpx
            r = _httpx.post(f"{registry_url.rstrip('/')}/tang/register", json={
                "node_id": node_id, "identity_public_key": id_pub_b64,
                "timestamp": ts, "signature": tang_sig,
            }, timeout=10)
            if r.is_success:
                T_pub_b64 = r.json()["T_pub"]
                T_pub_bytes = base64.b64decode(T_pub_b64 + "==")
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                T_pub = X25519PublicKey.from_public_bytes(T_pub_bytes)
                # McCallum-Relyea: generate ephemeral key, derive S, encrypt passphrase
                c_priv = X25519PrivateKey.generate()
                C_pub_bytes = c_priv.public_key().public_bytes(_E2.Raw, _PF2.Raw)
                S_bytes = c_priv.exchange(T_pub)
                K = _HKDF(_SHA256(), 32, None, b"contacc-tang-unlock").derive(S_bytes)
                tang_C = base64.b64encode(C_pub_bytes).decode()
                tang_E = base64.b64encode(encrypt_bytes(passphrase.encode(), K)).decode()
                tang_url_stored = registry_url.rstrip("/")
                # Discard c_priv, S_bytes, K — only C and E are stored
        except Exception as _te:
            log.warning("Tang setup failed (node will require manual unlock): %s", _te)

    if tang_C:
        config["tang_C"] = tang_C
        config["tang_E"] = tang_E
        config["tang_url"] = tang_url_stored

    config_path.write_text(json.dumps(config, indent=2))

    return {
        "argon2_salt": salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "internal_token": internal_token,
        "owner_id": owner_id,
        "node_id": node_id,
        "_identity_key_hex": identity_key_to_hex(identity_key),  # internal only — not sent to client
        "_registry_url": registry_url,
    }


class EscrowBody(BaseModel):
    identity_private_key: str   # hex — user provides this; never stored on node
    owner_passphrase: str


@router.post("/escrow-identity-key", status_code=204)
def escrow_identity_key(body: EscrowBody, request: Request):
    """Encrypt the user-provided identity private key with a owner passphrase and upload to the registry."""
    from .identity import identity_key_from_hex
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Server not initialized")

    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)
    if not (config.owner_id or config.user_id) or not config.identity_public_key:
        raise HTTPException(400, "No identity configured on this node")

    # Verify the provided key matches the stored public key
    try:
        identity_private_key = identity_key_from_hex(body.identity_private_key)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        provided_pub = base64.b64encode(
            identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        if provided_pub != config.identity_public_key:
            raise HTTPException(403, "Identity key does not match this node's identity")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Invalid identity private key")

    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    id_priv_bytes = identity_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    recovery_salt = os.urandom(16)
    recovery_key = derive_master_key(body.owner_passphrase, recovery_salt)
    encrypted_for_recovery = encrypt_bytes(id_priv_bytes, recovery_key)

    escrow_payload = {
        "encrypted_identity_key": base64.b64encode(encrypted_for_recovery).decode(),
        "argon2_salt": recovery_salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
    }

    import time as _time
    timestamp = int(_time.time())
    sign_msg = f"contacc:escrow:{(config.owner_id or config.user_id)}:{timestamp}"
    sig = base64.b64encode(identity_private_key.sign(sign_msg.encode())).decode()

    registry_url = config.registry_url or config.identity_proxy_url or ""
    if not registry_url:
        raise HTTPException(400, "No registry URL configured")

    import httpx as _httpx
    put_body = {**escrow_payload, "signature": sig, "timestamp": timestamp}
    r = _httpx.put(f"{registry_url.rstrip('/')}/identity-key/{(config.owner_id or config.user_id)}", json=put_body, timeout=10)
    if not r.is_success:
        raise HTTPException(502, f"Registry escrow failed: {r.status_code} {r.text}")


class RedelegateBody(BaseModel):
    identity_private_key: str   # hex — user provides this


@router.post("/redelegate")
def redelegate(body: RedelegateBody, request: Request):
    """Sign a new delegation cert using the user-provided identity private key.
    Use when the delegation cert has expired or the node key has changed."""
    from .identity import identity_key_from_hex, make_delegation_cert
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Server not initialized")

    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)
    if not (config.owner_id or config.user_id) or not config.identity_public_key:
        raise HTTPException(400, "No identity configured on this node")

    try:
        identity_private_key = identity_key_from_hex(body.identity_private_key)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        provided_pub = base64.b64encode(
            identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        if provided_pub != config.identity_public_key:
            raise HTTPException(403, "Identity key does not match this node's identity")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Invalid identity private key")

    node_pub_b64 = base64.b64encode(
        app.state.private_key.public_key().public_bytes(
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding', 'PublicFormat']).Encoding.Raw,
            __import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding', 'PublicFormat']).PublicFormat.Raw,
        )
    ).decode()
    delegation_cert = make_delegation_cert(identity_private_key, (config.owner_id or config.user_id), node_pub_b64)

    import json as _json
    config_data = _json.loads(config_path.read_text())
    config_data["identity_delegation"] = _json.dumps(delegation_cert)
    config_path.write_text(_json.dumps(config_data, indent=2))

    trigger = getattr(app.state, "trigger_heartbeat", None)
    if trigger:
        import threading
        threading.Thread(target=trigger, daemon=True).start()

    return {"status": "ok", "expires_at": delegation_cert["expires_at"]}


class ChangeOwnerPassphraseBody(BaseModel):
    old_owner_passphrase: str
    new_owner_passphrase: str


@router.post("/change-owner-passphrase")
def change_owner_passphrase(body: ChangeOwnerPassphraseBody, request: Request):
    """Fetch the identity key from registry escrow, decrypt with old passphrase,
    re-encrypt with new passphrase, re-upload. Returns identity_private_key hex
    so the user can confirm they have the latest version saved offline."""
    from .identity import identity_key_from_hex, identity_key_to_hex
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Server not initialized")

    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)
    if not (config.owner_id or config.user_id):
        raise HTTPException(400, "No identity configured on this node")

    registry_url = (config.registry_url or config.identity_proxy_url or "").rstrip("/")
    if not registry_url:
        raise HTTPException(400, "No registry URL configured")

    # Fetch escrow from registry
    import httpx as _httpx
    r = _httpx.post(f"{registry_url}/identity-key/{(config.owner_id or config.user_id)}/recover", timeout=10)
    if not r.is_success:
        raise HTTPException(502, "Could not fetch identity key from registry")
    escrow = r.json()

    # Decrypt with old passphrase
    try:
        old_salt = bytes.fromhex(escrow["argon2_salt"])
        old_key = derive_master_key(
            body.old_owner_passphrase, old_salt,
            escrow.get("argon2_time_cost", ARGON2_TIME_COST),
            escrow.get("argon2_memory_cost", ARGON2_MEMORY_COST),
            escrow.get("argon2_parallelism", ARGON2_PARALLELISM),
        )
        id_priv_bytes = decrypt_bytes(base64.b64decode(escrow["encrypted_identity_key"]), old_key)
        identity_private_key = identity_key_from_hex(id_priv_bytes.hex())
    except Exception:
        raise HTTPException(403, "Wrong owner passphrase")

    # Verify key matches stored public key
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    provided_pub = base64.b64encode(
        identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    if provided_pub != config.identity_public_key:
        raise HTTPException(403, "Recovered key does not match this node's identity")

    # Re-encrypt with new passphrase and re-upload
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    new_salt = os.urandom(16)
    new_key = derive_master_key(body.new_owner_passphrase, new_salt)
    new_encrypted = encrypt_bytes(
        identity_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()), new_key
    )
    timestamp = int(__import__("time").time())
    sign_msg = f"contacc:escrow:{(config.owner_id or config.user_id)}:{timestamp}"
    sig = base64.b64encode(identity_private_key.sign(sign_msg.encode())).decode()
    put_body = {
        "encrypted_identity_key": base64.b64encode(new_encrypted).decode(),
        "argon2_salt": new_salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "signature": sig,
        "timestamp": timestamp,
    }
    r2 = _httpx.put(f"{registry_url}/identity-key/{(config.owner_id or config.user_id)}", json=put_body, timeout=10)
    if not r2.is_success:
        raise HTTPException(502, f"Registry update failed: {r2.status_code}")

    return {
        "status": "ok",
        "identity_private_key": identity_key_to_hex(identity_private_key),
    }

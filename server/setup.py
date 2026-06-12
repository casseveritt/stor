"""First-run setup, unlock, and restore endpoints."""
import base64
import io
import json
import os
import re
import secrets
import shutil
import zipfile
from pathlib import Path

import httpx

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from .auth import OwnerDep, InternalOrOwnerDep
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


@router.get("/owner-lookup")
def setup_owner_lookup(google_identity: str):
    """Return the existing owner_id for a google_identity, or null if this is a new owner."""
    registry_url = os.environ.get("CONTACC_REGISTRY_URL",
                   os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://strk.xyzw.us:8421"))
    try:
        r = httpx.get(f"{registry_url}/owner-by-google-identity", params={"q": google_identity}, timeout=10)
        if r.status_code == 404:
            return {"owner_id": None, "is_new_owner": True}
        if not r.is_success:
            raise HTTPException(502, "Registry lookup failed")
        return {**r.json(), "is_new_owner": False}
    except httpx.RequestError:
        raise HTTPException(502, "Could not reach registry")


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
    identity_proxy_url = os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://strk.xyzw.us:8421")
    registry_url = os.environ.get("CONTACC_REGISTRY_URL", identity_proxy_url)

    key_material = _create_node_config(config_path, node_address, identity_proxy_url, body.owner_identity, body.passphrase, body.handle, display_name=body.display_name, tang_enabled=body.tang_enabled)

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    # The node is now live (serving /node under its real key). Reserve+claim its
    # identity from the registry and patch it into the running config — issuing the
    # delegation info is the final step before the node is open for business, and is
    # also what lets the registry confirm liveness (it can finally reach /node and see
    # the key the cert names).
    _id_key_hex = key_material.pop("_identity_key_hex")
    _node_pub_b64 = key_material.pop("_node_pub_b64")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
    from .identity import identity_key_from_hex as _ikfh
    from .crypto import ARGON2_TIME_COST as _TC, ARGON2_MEMORY_COST as _MC, ARGON2_PARALLELISM as _PAR
    _identity_key = _ikfh(_id_key_hex)
    _node_priv_bytes = decrypt_bytes(
        base64.b64decode(key_material["encrypted_private_key"]),
        derive_master_key(body.passphrase, bytes.fromhex(key_material["argon2_salt"]), _TC, _MC, _PAR)
    )
    _node_key = _Ed.from_private_bytes(_node_priv_bytes)
    web_address = app.state.web_address or ""

    owner_id, node_id = _finalize_node_identity(
        app, config_path, registry_url, body.handle, body.passphrase, node_address, web_address,
        body.owner_identity, body.display_name, _identity_key, _node_key, _node_pub_b64,
        body.tang_enabled, existing_owner_id=None, upload_escrow=True,
    )

    _consume_token(app)
    return {
        "status": "ok",
        "node_address": node_address,
        "node_id": node_id,
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
    identity_proxy_url = os.environ.get("CONTACC_IDENTITY_PROXY_URL", "https://strk.xyzw.us:8421")
    registry_url = os.environ.get("CONTACC_REGISTRY_URL", identity_proxy_url)

    # Fetch identity key escrow from registry and decrypt with owner passphrase
    import httpx as _hx_o
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK_o
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc_o, PublicFormat as _PuF_o

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

    # Generate fresh node credentials — node_id is minted by the registry once this
    # node is live (see _finalize_node_identity), never self-assigned.
    import os as _os3
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _NK
    from cryptography.hazmat.primitives.serialization import PrivateFormat as _PrF_o, NoEncryption as _NE_o

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
    _db_path = store_path / "db"
    if _db_path.is_dir():
        _sh.rmtree(_db_path)
    elif _db_path.exists():
        _db_path.unlink()
    (store_path / "files").mkdir(exist_ok=True)

    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)
    if body.display_name:
        db_con.execute("INSERT OR REPLACE INTO profile (id, display_name) VALUES (1, ?)", (body.display_name,))
        db_con.commit()
    db_con.close()

    node_pub_b64 = base64.b64encode(node_key.public_key().public_bytes(_Enc_o.Raw, _PuF_o.Raw)).decode()
    internal_token = secrets.token_urlsafe(32)

    # owner_id/node_id/the delegation cert are deferred to _finalize_node_identity,
    # which runs after the node is live — that's when the registry can verify it and
    # mint node_id (owner_id is already known: body.existing_owner_id).
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
        "tang_enabled": body.tang_enabled,
    }

    config_path.write_text(json.dumps(config, indent=2))

    try:
        app.state.do_initialize(body.passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after setup")

    # The node is now live. Reserve+claim its node_id under the existing owner_id and
    # patch it into the running config — the final step before it's open for business.
    web_address = app.state.web_address or ""
    owner_id, new_node_id = _finalize_node_identity(
        app, config_path, registry_url, body.handle, body.passphrase, node_address, web_address,
        body.owner_identity, body.display_name, identity_key, node_key, node_pub_b64,
        body.tang_enabled, existing_owner_id=body.existing_owner_id, upload_escrow=False,
    )

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

    # Patch the extracted config to match this node's address and store path,
    # and ensure internal_token exists (may be absent in older backups).
    store_path = Path(app.state.config_path).parent
    config_path = store_path / "node_config.json"
    config_data = json.loads(config_path.read_text())
    _patched = False
    current_node_address = app.state.node_address or os.environ.get("CONTACC_NODE_ADDRESS", "")
    if current_node_address and config_data.get("node_address") != current_node_address:
        config_data["node_address"] = current_node_address
        _patched = True
    if config_data.get("store_path") != str(store_path):
        config_data["store_path"] = str(store_path)
        _patched = True
    if "internal_token" not in config_data:
        config_data["internal_token"] = secrets.token_urlsafe(32)
        _patched = True
    if _patched:
        config_path.write_text(json.dumps(config_data, indent=2))

    try:
        app.state.do_initialize(passphrase)
    except WrongPassphraseError:
        raise HTTPException(500, "Failed to initialize after restore")

    # Re-register with the registry synchronously before returning so the node is
    # immediately reachable at its (possibly new) address.
    trigger = getattr(app.state, "trigger_heartbeat", None)
    if trigger:
        try:
            trigger()
        except Exception as _he:
            log.warning("Registry heartbeat after restore failed: %s", _he)

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
def change_passphrase(body: ChangePassphraseBody, request: Request, _identity: InternalOrOwnerDep):
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


def _finalize_node_identity(
    app,
    config_path: Path,
    registry_url: str,
    handle: str,
    passphrase: str,
    node_address: str,
    web_address: str,
    owner_identity: str,
    display_name: str,
    identity_key,
    node_key,
    node_pub_b64: str,
    tang_enabled: bool,
    existing_owner_id: str | None = None,
    upload_escrow: bool = True,
) -> tuple[str, str]:
    """Reserve owner_id/node_id from the registry, register, and patch the now-running
    node's config + in-memory state with its finalized identity. This runs *after* the
    node is already live (do_initialize has completed) — issuing the delegation info is
    the last step before the node is open for business, and it's also what lets the
    registry's liveness check (_claim_url) succeed: the node can finally prove it's
    serving at server_url under the key the cert names.

    The registry is the sole authority for owner_id/node_id — a node never self-assigns;
    /register/{username} only accepts IDs that match a reservation made here."""
    import time as _t, httpx as _hx, json as _j
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PuF
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519, X25519PublicKey as _X25519Pub
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
    from . import node as node_module
    from .identity import make_delegation_cert, identity_key_to_hex
    from .crypto import encrypt_bytes, derive_master_key, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM

    if not registry_url:
        raise HTTPException(502, "No registry configured — cannot obtain identifiers")
    registry_url = registry_url.rstrip("/")
    id_pub_b64 = base64.b64encode(identity_key.public_key().public_bytes(_Enc.Raw, _PuF.Raw)).decode()

    # 1. Reserve owner_id/node_id — minted by the registry, never self-assigned
    ts_res = int(_t.time())
    res_msg = f"contacc:reserve:{existing_owner_id or 'new'}:{node_pub_b64}:{ts_res}"
    res_sig = base64.b64encode(identity_key.sign(res_msg.encode())).decode()
    try:
        r_res = _hx.post(f"{registry_url}/register/reserve", json={
            "identity_public_key": id_pub_b64, "node_public_key": node_pub_b64,
            "owner_id": existing_owner_id, "timestamp": ts_res, "signature": res_sig,
        }, timeout=10)
    except Exception:
        raise HTTPException(502, "Could not reach the registry to reserve identifiers — try again")
    if not r_res.is_success:
        raise HTTPException(502, f"Registry declined to reserve identifiers: {r_res.text}")
    reserved = r_res.json()
    owner_id, node_id = reserved["owner_id"], reserved["node_id"]

    # 2. Sign the delegation cert now that the IDs are known
    delegation_cert = make_delegation_cert(identity_key, owner_id, node_pub_b64, node_id=node_id)

    # 3. Tang network-bound unlock (the registration message is keyed by node_id)
    tang_C = tang_E = tang_url_stored = None
    if tang_enabled:
        try:
            ts = int(_t.time())
            tang_msg = f"contacc:tang:register:{node_id}:{ts}"
            tang_sig = base64.b64encode(identity_key.sign(tang_msg.encode())).decode()
            r_tang = _hx.post(f"{registry_url}/tang/register", json={
                "node_id": node_id, "identity_public_key": id_pub_b64,
                "timestamp": ts, "signature": tang_sig,
            }, timeout=10)
            if r_tang.is_success:
                T_pub = _X25519Pub.from_public_bytes(base64.b64decode(r_tang.json()["T_pub"] + "=="))
                c_priv = _X25519.generate()
                S_bytes = c_priv.exchange(T_pub)
                K = _HKDF(_SHA256(), 32, None, b"contacc-tang-unlock").derive(S_bytes)
                tang_C = base64.b64encode(c_priv.public_key().public_bytes(_Enc.Raw, _PuF.Raw)).decode()
                tang_E = base64.b64encode(encrypt_bytes(passphrase.encode(), K)).decode()
                tang_url_stored = registry_url
        except Exception as _te:
            log.warning("Tang setup failed (node will require manual unlock): %s", _te)

    # 4. Register — the node is already live, so the registry can verify it at server_url
    ts_r = int(_t.time())
    reg_msg = f"contacc:register:{handle}:{node_address}:{ts_r}"
    reg_sig = base64.b64encode(node_key.sign(reg_msg.encode())).decode()
    try:
        r_reg = _hx.post(f"{registry_url}/register/{handle}", json={
            "server_url": node_address, "public_key": node_pub_b64,
            "ttl": 14400, "timestamp": ts_r, "signature": reg_sig,
            "display_name": display_name or None,
            "web_url": web_address or None,
            "delegation_cert": delegation_cert,
            "google_identity": owner_identity,
        }, timeout=10)
    except Exception:
        raise HTTPException(502, "Could not reach the registry to register — try again")
    if not r_reg.is_success:
        raise HTTPException(502, f"Registry registration failed: {r_reg.text}")

    # 5. Patch the live config + in-memory state — issuing the delegation info is the
    # final step before the node is open for business.
    config_data = _j.loads(config_path.read_text())
    config_data["owner_id"] = owner_id
    config_data["node_id"] = node_id
    config_data["identity_public_key"] = id_pub_b64
    config_data["identity_delegation"] = _j.dumps(delegation_cert)
    if tang_C:
        config_data["tang_C"] = tang_C
        config_data["tang_E"] = tang_E
        config_data["tang_url"] = tang_url_stored
    config_path.write_text(_j.dumps(config_data, indent=2))

    app.state.user_id = owner_id
    app.state.node_id = node_id
    node_module.setup(node_address, app.state.private_key, app.state.watermark_enabled, handle,
                      user_id=owner_id, owner_id=owner_id, node_id=node_id)

    # 6. Escrow the identity key for brand-new owners (existing owners already have one)
    if upload_escrow:
        try:
            escrow_salt = os.urandom(16)
            escrow_key = derive_master_key(passphrase, escrow_salt, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
            enc_id_key = base64.b64encode(encrypt_bytes(bytes.fromhex(identity_key_to_hex(identity_key)), escrow_key)).decode()
            ts_e = int(_t.time())
            escrow_sig = base64.b64encode(identity_key.sign(f"contacc:escrow:{owner_id}:{ts_e}".encode())).decode()
            r_e = _hx.put(f"{registry_url}/identity-key/{owner_id}", json={
                "encrypted_identity_key": enc_id_key,
                "argon2_salt": escrow_salt.hex(),
                "argon2_time_cost": ARGON2_TIME_COST, "argon2_memory_cost": ARGON2_MEMORY_COST, "argon2_parallelism": ARGON2_PARALLELISM,
                "signature": escrow_sig, "timestamp": ts_e,
            }, timeout=10)
            if not r_e.is_success:
                log.warning("Escrow upload failed: %s %s", r_e.status_code, r_e.text)
        except Exception as _ee:
            log.warning("Escrow upload failed: %s", _ee)

    return owner_id, node_id


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
    if db_path.is_dir():
        _shutil.rmtree(db_path)
    elif db_path.exists():
        db_path.unlink()
    (store_path / "files").mkdir(exist_ok=True)

    salt = _os.urandom(16)
    master_key = _derive(passphrase, salt)
    db_key, _ = derive_subkeys(master_key)

    private_key = Ed25519PrivateKey.generate()
    privkey_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted_privkey = encrypt_bytes(privkey_bytes, master_key)
    node_pub_b64 = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()

    from .identity import identity_key_to_hex

    # Generate identity key pair — private key is NEVER stored on the node.
    # owner_id/node_id/the delegation cert are NOT written here: the registry mints
    # them, and it can only do so once this node is live (it verifies liveness at
    # server_url before registering). _finalize_node_identity runs after
    # do_initialize and patches them into the running node as the final setup step.
    identity_key = Ed25519PrivateKey.generate()

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
        "tang_enabled": tang_enabled,
    }

    # Generate X25519 DH key pair for DM thread key derivation
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519
    from cryptography.hazmat.primitives.serialization import PrivateFormat as _PrF2, NoEncryption as _NE2
    dh_priv = _X25519.generate()
    dh_priv_bytes = dh_priv.private_bytes(Encoding.Raw, _PrF2.Raw, _NE2())
    config["encrypted_dh_private_key"] = base64.b64encode(encrypt_bytes(dh_priv_bytes, master_key)).decode()

    config_path.write_text(json.dumps(config, indent=2))

    return {
        "argon2_salt": salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "internal_token": internal_token,
        "_identity_key_hex": identity_key_to_hex(identity_key),  # internal only — not sent to client
        "_node_pub_b64": node_pub_b64,
    }


class EscrowBody(BaseModel):
    identity_private_key: str   # hex — user provides this; never stored on node
    owner_passphrase: str


@router.post("/escrow-identity-key", status_code=204)
def escrow_identity_key(body: EscrowBody, request: Request, _identity: InternalOrOwnerDep):
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
def redelegate(body: RedelegateBody, request: Request, _identity: InternalOrOwnerDep):
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


@router.get("/has-escrow")
def has_escrow(request: Request):
    """Check whether this owner has an identity key escrow in the registry."""
    app = request.app
    if not app.state.initialized:
        return {"has_escrow": False}
    config = NodeConfig.load(Path(app.state.config_path))
    owner_id = config.owner_id or config.user_id
    if not owner_id:
        return {"has_escrow": False}
    registry_url = (config.registry_url or config.identity_proxy_url or "").rstrip("/")
    if not registry_url:
        return {"has_escrow": False}
    import httpx as _hx
    try:
        r = _hx.get(f"{registry_url}/identity-key/{owner_id}", timeout=5)
        return {"has_escrow": r.is_success}
    except Exception:
        return {"has_escrow": False}


class CreateEscrowBody(BaseModel):
    owner_passphrase: str


@router.post("/create-identity-escrow")
def create_identity_escrow(body: CreateEscrowBody, request: Request, _identity: InternalOrOwnerDep):
    """Generate a fresh identity key, create a delegation cert, and store escrow in the registry.
    Use when the owner has no existing escrow. Fails if escrow already exists."""
    from .identity import make_delegation_cert
    import httpx as _hx2
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Server not initialized")
    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)
    owner_id = config.owner_id or config.user_id
    if not owner_id:
        raise HTTPException(400, "No owner identity configured on this node")
    registry_url = (config.registry_url or config.identity_proxy_url or "").rstrip("/")
    if not registry_url:
        raise HTTPException(400, "No registry URL configured")
    node_id = config.node_id
    if not node_id:
        raise HTTPException(400, "Node ID not yet assigned")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PuF, PrivateFormat as _PrF, NoEncryption as _NE
    import json as _json

    identity_key = _EK.generate()
    id_pub_b64 = base64.b64encode(identity_key.public_key().public_bytes(_Enc.Raw, _PuF.Raw)).decode()
    id_priv_raw = identity_key.private_bytes(_Enc.Raw, _PrF.Raw, _NE())

    node_pub_b64 = base64.b64encode(
        app.state.private_key.public_key().public_bytes(_Enc.Raw, _PuF.Raw)
    ).decode()
    delegation_cert = make_delegation_cert(identity_key, owner_id, node_pub_b64, node_id=node_id)

    recovery_salt = os.urandom(16)
    recovery_key = derive_master_key(body.owner_passphrase, recovery_salt)
    encrypted_id = encrypt_bytes(id_priv_raw, recovery_key)

    import time as _t
    timestamp = int(_t.time())
    sign_msg = f"contacc:identity-bootstrap:{owner_id}:{timestamp}"
    sig = base64.b64encode(app.state.private_key.sign(sign_msg.encode())).decode()

    bootstrap_payload = {
        "node_id": node_id,
        "identity_public_key": id_pub_b64,
        "delegation_cert": delegation_cert,
        "encrypted_identity_key": base64.b64encode(encrypted_id).decode(),
        "argon2_salt": recovery_salt.hex(),
        "argon2_time_cost": ARGON2_TIME_COST,
        "argon2_memory_cost": ARGON2_MEMORY_COST,
        "argon2_parallelism": ARGON2_PARALLELISM,
        "timestamp": timestamp,
        "signature": sig,
    }
    r = _hx2.post(f"{registry_url}/identity-key/{owner_id}/bootstrap", json=bootstrap_payload, timeout=10)
    if r.status_code == 409:
        raise HTTPException(409, "Escrow already exists — use refresh-delegation instead")
    if not r.is_success:
        raise HTTPException(502, f"Registry bootstrap failed: {r.status_code} {r.text}")

    # Store new delegation cert and identity key in node config
    config_data = _json.loads(config_path.read_text())
    config_data["identity_delegation"] = _json.dumps(delegation_cert)
    config_data["identity_public_key"] = id_pub_b64
    _mk = getattr(app.state, "master_key", None)
    if _mk:
        config_data["encrypted_identity_private_key"] = base64.b64encode(
            encrypt_bytes(id_priv_raw, _mk)
        ).decode()
    config_path.write_text(_json.dumps(config_data, indent=2))

    trigger = getattr(app.state, "trigger_heartbeat", None)
    if trigger:
        import threading
        threading.Thread(target=trigger, daemon=True).start()

    return {"status": "ok", "expires_at": delegation_cert["expires_at"]}


class RefreshDelegationBody(BaseModel):
    owner_passphrase: str


@router.post("/refresh-delegation")
def refresh_delegation(body: RefreshDelegationBody, request: Request, _identity: InternalOrOwnerDep):
    """Fetch identity key from registry escrow, sign a fresh delegation cert.
    Use when the stored delegation cert has expired (e.g. after bundle restore)."""
    from .identity import identity_key_from_hex, make_delegation_cert
    import httpx as _httpx
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Server not initialized")
    config_path = Path(app.state.config_path)
    config = NodeConfig.load(config_path)
    owner_id = config.owner_id or config.user_id
    if not owner_id or not config.identity_public_key:
        raise HTTPException(400, "No identity configured on this node")
    registry_url = (config.registry_url or config.identity_proxy_url or "").rstrip("/")
    if not registry_url:
        raise HTTPException(400, "No registry URL configured")
    r = _httpx.post(f"{registry_url}/identity-key/{owner_id}/recover", timeout=10)
    if not r.is_success:
        raise HTTPException(502, "Could not fetch identity key from registry escrow")
    escrow = r.json()
    try:
        salt = bytes.fromhex(escrow["argon2_salt"])
        key = derive_master_key(
            body.owner_passphrase, salt,
            escrow.get("argon2_time_cost", ARGON2_TIME_COST),
            escrow.get("argon2_memory_cost", ARGON2_MEMORY_COST),
            escrow.get("argon2_parallelism", ARGON2_PARALLELISM),
        )
        id_priv_bytes = decrypt_bytes(base64.b64decode(escrow["encrypted_identity_key"]), key)
        identity_private_key = identity_key_from_hex(id_priv_bytes.hex())
    except Exception:
        raise HTTPException(403, "Wrong owner passphrase")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    provided_pub = base64.b64encode(
        identity_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    if provided_pub != config.identity_public_key:
        raise HTTPException(403, "Recovered key does not match this node's identity")
    node_pub_b64 = base64.b64encode(
        app.state.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    delegation_cert = make_delegation_cert(identity_private_key, owner_id, node_pub_b64)
    import json as _json
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    config_data = _json.loads(config_path.read_text())
    config_data["identity_delegation"] = _json.dumps(delegation_cert)
    # Re-store the identity key encrypted with the node's master key so future bundle
    # restores can self-heal without user intervention.
    try:
        _mk = getattr(app.state, "master_key", None)
        if _mk:
            _id_priv_raw = identity_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            config_data["encrypted_identity_private_key"] = base64.b64encode(
                encrypt_bytes(_id_priv_raw, _mk)
            ).decode()
    except Exception:
        pass
    config_path.write_text(_json.dumps(config_data, indent=2))
    trigger = getattr(app.state, "trigger_heartbeat", None)
    if trigger:
        import threading
        threading.Thread(target=trigger, daemon=True).start()
    return {"status": "ok", "expires_at": delegation_cert["expires_at"]}


class ReleaseBody(BaseModel):
    passphrase: str
    delete_from_registry: bool = False


@router.post("/release", status_code=204)
def release_node(body: ReleaseBody, request: Request, _identity: InternalOrOwnerDep):
    """Erase all node data and return to uninitialized state.
    The caller must have already downloaded a backup; this is irreversible."""
    app = request.app
    if not app.state.initialized:
        raise HTTPException(400, "Node is not initialized")

    # Verify passphrase before destroying anything
    config_path = Path(app.state.config_path)
    try:
        config_data = json.loads(config_path.read_text())
        salt = bytes.fromhex(config_data["argon2_salt"])
        master_key = derive_master_key(
            body.passphrase, salt,
            config_data.get("argon2_time_cost", ARGON2_TIME_COST),
            config_data.get("argon2_memory_cost", ARGON2_MEMORY_COST),
            config_data.get("argon2_parallelism", ARGON2_PARALLELISM),
        )
        decrypt_bytes(base64.b64decode(config_data["encrypted_private_key"]), master_key)
    except (InvalidTag, KeyError, ValueError):
        raise HTTPException(403, "Wrong passphrase")

    store_path = Path(app.state.store_path)

    # Notify registry that this node's URL is no longer valid — do this before wiping state
    # so we still have the private key to sign the request.
    try:
        import httpx as _hx_r, time as _t_r
        _config_r = NodeConfig.load(config_path)
        _registry_url_r = (_config_r.registry_url or _config_r.identity_proxy_url or "").rstrip("/")
        _node_id_r = _config_r.node_id or ""
        if _registry_url_r and _node_id_r and app.state.private_key:
            _ts_r = int(_t_r.time())
            _msg_r = f"contacc:suspend:{_node_id_r}:{_ts_r}"
            _sig_r = base64.b64encode(app.state.private_key.sign(_msg_r.encode())).decode()
            _hx_r.post(f"{_registry_url_r}/suspend/{_node_id_r}",
                       json={"timestamp": _ts_r, "signature": _sig_r}, timeout=5.0)
            log.info("Notified registry of suspension for node %s", _node_id_r)
    except Exception as _re:
        log.warning("Could not notify registry of node suspension: %s", _re)

    if body.delete_from_registry:
        try:
            import httpx as _hx_d, time as _t_d
            _config_d = NodeConfig.load(config_path)
            _registry_url_d = (_config_d.registry_url or _config_d.identity_proxy_url or "").rstrip("/")
            _node_id_d = _config_d.node_id or ""
            if _registry_url_d and _node_id_d and app.state.private_key:
                _ts_d = int(_t_d.time())
                _msg_d = f"contacc:deregister:{_node_id_d}:{_ts_d}"
                _sig_d = base64.b64encode(app.state.private_key.sign(_msg_d.encode())).decode()
                _hx_d.post(f"{_registry_url_d}/nodes/{_node_id_d}/deregister",
                           json={"timestamp": _ts_d, "signature": _sig_d}, timeout=5.0)
                log.info("Deregistered node %s from registry", _node_id_d)
        except Exception as _de:
            log.warning("Could not deregister node from registry: %s", _de)

    # Reset in-memory state first so in-flight requests fail fast
    app.state.initialized = False
    app.state.private_key = None
    app.state.file_key = None
    app.state.node_id = ""
    app.state.user_id = ""
    app.state.internal_token = None
    app.state.dh_private_key = None
    app.state.dh_public_key = None

    # Close the database connection
    try:
        db = app.state.db
        app.state.db = None
        if db is not None:
            db.close()
    except Exception:
        pass

    # Delete database files, asset files, and config
    for name in ["db", "db-wal", "db-shm"]:
        (store_path / name).unlink(missing_ok=True)
    files_dir = store_path / "files"
    if files_dir.exists():
        shutil.rmtree(files_dir)
    config_path.unlink(missing_ok=True)

    # Generate a fresh setup token so the owner can re-initialize
    ensure_setup_token(app)
    log.info("Node released — all data erased, setup token generated")

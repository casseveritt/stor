import base64
import logging
import os
import secrets
import sys
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .config import NodeConfig
from .crypto import derive_master_key, derive_subkeys, decrypt_bytes
from .db import open_db, init_schema, WrongPassphraseError
from . import node as node_module
from . import auth as auth_module
from . import feed as feed_module
from . import assets as assets_module
from . import auth_routes as auth_routes_module
from . import sso as sso_module
from . import comments as comments_module
from . import write as write_module
from . import admin as admin_module
from . import posts as posts_module
from . import setup as setup_module
from . import profile as profile_module
from . import contacts as contacts_module
from . import reactions as reactions_module
from . import debug as debug_module

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contacc")


def _registry_heartbeat(
    private_key: Ed25519PrivateKey,
    node_address: str,
    handle: str,
    registry_url: str,
    display_name: str | None = None,
    web_address: str | None = None,
    delegation_cert: dict | None = None,
    google_identity: str | None = None,
) -> None:
    """Sign and push an update to the registry. Runs in the background; failures are logged and ignored."""
    try:
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        timestamp = int(time.time())
        msg = f"contacc:update:{handle}:{node_address}:{timestamp}"
        signature = base64.b64encode(private_key.sign(msg.encode())).decode()
        payload = {"server_url": node_address, "ttl": 14400,
                   "timestamp": timestamp, "signature": signature}
        if display_name:
            payload["display_name"] = display_name
        if web_address:
            payload["web_url"] = web_address
        if delegation_cert:
            payload["delegation_cert"] = delegation_cert
        if google_identity:
            payload["google_identity"] = google_identity
        r = httpx.put(f"{registry_url.rstrip('/')}/update/{handle}", json=payload, timeout=10.0)
        if r.status_code == 404:
            # Not registered yet — register for the first time
            pub_b64 = base64.b64encode(pub_bytes).decode()
            reg_msg = f"contacc:register:{handle}:{node_address}:{timestamp}"
            reg_sig = base64.b64encode(private_key.sign(reg_msg.encode())).decode()
            reg_payload = {**payload, "public_key": pub_b64, "signature": reg_sig}
            r = httpx.post(f"{registry_url.rstrip('/')}/register/{handle}", json=reg_payload, timeout=10.0)
        if r.is_success:
            log.info("Registry heartbeat OK: %s → %s", handle, node_address)
        else:
            log.warning("Registry heartbeat failed %s: %s", r.status_code, r.text)
    except Exception as e:
        log.warning("Registry heartbeat error: %s", e)


def _initialize(app: FastAPI, config_path: Path, passphrase: str) -> None:
    """Load keys, open DB, and populate app.state. Raises WrongPassphraseError on bad passphrase."""
    config = NodeConfig.load(config_path)

    salt = bytes.fromhex(config.argon2_salt)
    log.info("Deriving keys...")
    master_key = derive_master_key(
        passphrase, salt,
        config.argon2_time_cost,
        config.argon2_memory_cost,
        config.argon2_parallelism,
    )
    db_key, file_key = derive_subkeys(master_key)

    encrypted_privkey = base64.b64decode(config.encrypted_private_key)
    try:
        privkey_bytes = decrypt_bytes(encrypted_privkey, master_key)
    except InvalidTag:
        raise WrongPassphraseError("Wrong passphrase: private key decryption failed")
    private_key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)

    # Migration: generate permanent user identity if missing
    if not config.user_id:
        import uuid as _uuid
        import json as _json
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _E, PrivateFormat as _PF, NoEncryption as _NE, PublicFormat as _PuF,
        )
        from .identity import make_delegation_cert as _mkdel
        new_id_key = _EK.generate()
        new_user_id = str(_uuid.uuid4())
        id_pub_bytes = new_id_key.public_key().public_bytes(_E.Raw, _PuF.Raw)
        node_pub_b64 = base64.b64encode(
            private_key.public_key().public_bytes(_E.Raw, _PuF.Raw)
        ).decode()
        delegation_cert = _mkdel(new_id_key, new_user_id, node_pub_b64)
        config_data = _json.loads(config_path.read_text())
        config_data["user_id"] = new_user_id
        config_data["identity_public_key"] = base64.b64encode(id_pub_bytes).decode()
        config_data["identity_delegation"] = _json.dumps(delegation_cert)
        # Remove legacy encrypted key if present
        config_data.pop("encrypted_identity_private_key", None)
        config_path.write_text(_json.dumps(config_data, indent=2))
        config = NodeConfig.load(config_path)
        log.info("Generated permanent user identity: %s (identity private key NOT stored — save it from settings)", new_user_id)

    # Migration: if legacy encrypted_identity_private_key exists, convert to delegation cert
    import json as _json2
    _raw_config = _json2.loads(config_path.read_text())
    if "encrypted_identity_private_key" in _raw_config:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK2
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _E2, PrivateFormat as _PF2, NoEncryption as _NE2, PublicFormat as _PuF2,
            )
            from .crypto import decrypt_bytes as _dec2
            from .identity import make_delegation_cert as _mkdel2
            id_priv = _dec2(base64.b64decode(_raw_config["encrypted_identity_private_key"]), master_key)
            id_key = _EK2.from_private_bytes(id_priv)
            node_pub_b64 = base64.b64encode(
                private_key.public_key().public_bytes(_E2.Raw, _PuF2.Raw)
            ).decode()
            delegation_cert = _mkdel2(id_key, config.user_id, node_pub_b64)
            _raw_config["identity_delegation"] = _json2.dumps(delegation_cert)
            del _raw_config["encrypted_identity_private_key"]
            config_path.write_text(_json2.dumps(_raw_config, indent=2))
            config = NodeConfig.load(config_path)
            # Auto-upload escrow to registry using "foobar" so recovery is available immediately.
            # User should change this passphrase in settings.
            try:
                from .identity import identity_key_to_hex as _id2hex
                from .crypto import (derive_master_key as _dmk2, encrypt_bytes as _enc2,
                                     ARGON2_TIME_COST as _TC, ARGON2_MEMORY_COST as _MC, ARGON2_PARALLELISM as _PA)
                _reg_url = (_raw_config.get("registry_url") or _raw_config.get("identity_proxy_url") or "").rstrip("/")
                if _reg_url and config.user_id:
                    _rec_salt = os.urandom(16)
                    _rec_key = _dmk2("foobar", _rec_salt)
                    _enc_id = _enc2(id_priv, _rec_key)
                    _ts = int(time.time())
                    _escrow_sig = base64.b64encode(id_key.sign(
                        f"contacc:escrow:{config.user_id}:{_ts}".encode()
                    )).decode()
                    _escrow_body = {
                        "encrypted_identity_key": base64.b64encode(_enc_id).decode(),
                        "argon2_salt": _rec_salt.hex(),
                        "argon2_time_cost": _TC, "argon2_memory_cost": _MC, "argon2_parallelism": _PA,
                        "signature": _escrow_sig, "timestamp": _ts,
                    }
                    httpx.put(f"{_reg_url}/identity-key/{config.user_id}", json=_escrow_body, timeout=10)
                    log.warning("Identity key migrated. Recovery passphrase is currently 'foobar'. "
                                "Change it in settings → Identity Security.")
            except Exception as _e2:
                log.warning("Could not auto-upload identity escrow: %s", _e2)
        except Exception as _e:
            log.error("Failed to migrate identity key: %s", _e)

    store_path = Path(config.store_path)
    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)

    node_address = os.environ.get("CONTACC_NODE_ADDRESS") or config.node_address

    app.state.db = db_con
    app.state.file_key = file_key
    app.state.store_path = store_path
    app.state.config_path = config_path
    app.state.node_address = node_address
    app.state.watermark_enabled = config.watermark_enabled
    app.state.owner_identity = config.sso_owner_identity
    app.state.identity_proxy_url = config.identity_proxy_url
    app.state.sso_config = {
        "google_client_id": config.sso_google_client_id,
        "google_client_secret": config.sso_google_client_secret,
    }
    app.state.sso_exchange_google = sso_module.exchange_google_code
    app.state.user_id = config.user_id or ""

    node_module.setup(node_address, private_key, config.watermark_enabled, config.registry_handle, user_id=config.user_id)
    auth_module.setup(private_key)

    app.state.private_key = private_key
    app.state.internal_token = config.internal_token
    app.state.initialized = True
    log.info("Node %s ready.", node_address)

    if config.registry_handle and node_address:
        registry_url = config.registry_url or config.identity_proxy_url or ""
        if registry_url:
            import threading

            HEARTBEAT_INTERVAL = 3600  # re-register every hour; TTL is 4 hours

            def _make_trigger(pk, addr, hdl, reg_url, db_con, web_addr, cfg_path):
                def trigger():
                    row = db_con.execute(
                        "SELECT display_name FROM profile WHERE id = 1"
                    ).fetchone()
                    dn = row[0] if row else None
                    import json as _j
                    try:
                        _cfg = NodeConfig.load(cfg_path)
                        _dcert = _j.loads(_cfg.identity_delegation) if _cfg.identity_delegation else None
                        _gid = _cfg.sso_owner_identity
                    except Exception:
                        _dcert = None
                        _gid = None
                    _registry_heartbeat(pk, addr, hdl, reg_url, dn, web_addr, _dcert, _gid)
                return trigger

            def _heartbeat_loop(trigger):
                import time as _time
                while True:
                    trigger()
                    _time.sleep(HEARTBEAT_INTERVAL)

            trigger_fn = _make_trigger(private_key, node_address, config.registry_handle, registry_url, db_con, app.state.web_address, config_path)
            app.state.trigger_heartbeat = trigger_fn
            threading.Thread(target=_heartbeat_loop, args=(trigger_fn,), daemon=True).start()


def create_app(config_path: str | Path) -> FastAPI:
    config_path = Path(config_path)

    app = FastAPI(title="contacc node")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.initialized = False
    app.state.config_path = config_path
    app.state.node_address = os.environ.get("CONTACC_NODE_ADDRESS", "")
    app.state.web_address = os.environ.get("CONTACC_WEB_ADDRESS", "")

    if not config_path.exists():
        setup_module.ensure_setup_token(app)

    def _do_initialize(passphrase: str) -> None:
        _initialize(app, config_path, passphrase)

    app.state.do_initialize = _do_initialize

    # Setup routes are always accessible
    app.include_router(setup_module.router)

    # Normal routes — blocked by middleware until initialized
    app.include_router(node_module.router)
    app.include_router(feed_module.router)
    app.include_router(assets_module.router)
    app.include_router(auth_routes_module.router)
    app.include_router(comments_module.router)
    app.include_router(write_module.router)
    app.include_router(admin_module.router)
    app.include_router(posts_module.router)
    app.include_router(profile_module.router)
    app.include_router(contacts_module.router)
    app.include_router(reactions_module.router)
    app.include_router(debug_module.router)

    @app.middleware("http")
    async def init_guard(request: Request, call_next):
        path = request.url.path
        is_setup_path = path.startswith("/setup")
        is_public_path = path == "/profile/photo" or path.startswith("/node")
        if not app.state.initialized and not is_setup_path:
            state = "locked" if config_path.exists() else "uninitialized"
            return JSONResponse({"detail": "Server not ready", "state": state}, status_code=503)
        if app.state.initialized and not is_setup_path and not is_public_path:
            internal_token = getattr(app.state, "internal_token", None)
            if internal_token:
                provided = request.headers.get("x-contacc-internal", "")
                if not secrets.compare_digest(provided, internal_token):
                    return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        return await call_next(request)

    # Try to initialize immediately if we have everything we need
    passphrase = os.environ.get("CONTACC_PASSPHRASE_UNSECURE", "")
    if not passphrase and os.environ.get("CONTACC_DEV"):
        passphrase = "foobar"
    if config_path.exists() and passphrase:
        try:
            _initialize(app, config_path, passphrase)
        except WrongPassphraseError as e:
            log.error("Wrong passphrase at startup — server will start in locked state: %s", e)

    return app


def _dev_factory() -> FastAPI:
    """Factory for uvicorn --reload mode; reads config path from env."""
    return create_app(os.environ["CONTACC_CONFIG"])


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contacc node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--reload", action="store_true", help="Reload on source changes (dev mode)")
    parser.add_argument("--print-token", action="store_true", help="Print an owner token to stdout before serving")
    args = parser.parse_args()

    if args.reload:
        os.environ["CONTACC_CONFIG"] = args.config
        uvicorn.run("server.main:_dev_factory", factory=True, host=args.host, port=args.port,
                    reload=True, reload_dirs=["/app/server"], proxy_headers=True, forwarded_allow_ips="*")
        return

    app = create_app(args.config)

    if args.print_token:
        if not app.state.initialized:
            log.error("--print-token requires the server to be initialized (set CONTACC_PASSPHRASE_UNSECURE)")
            sys.exit(1)
        token = auth_module.issue_token(ttl_seconds=86400 * 30)
        print(f"Owner token: {token}", flush=True)

    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

import base64
import logging
import os
import sys
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contacc")


def _registry_heartbeat(private_key: Ed25519PrivateKey, node_address: str, handle: str, registry_url: str) -> None:
    """Sign and push an update to the registry. Runs in the background; failures are logged and ignored."""
    try:
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        timestamp = int(time.time())
        msg = f"contacc:update:{handle}:{node_address}::{timestamp}"
        signature = base64.b64encode(private_key.sign(msg.encode())).decode()
        payload = {"server_url": node_address, "client_url": "", "ttl": 14400,
                   "timestamp": timestamp, "signature": signature}
        r = httpx.put(f"{registry_url.rstrip('/')}/update/{handle}", json=payload, timeout=10.0)
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

    node_module.setup(node_address, private_key, config.watermark_enabled)
    auth_module.setup(private_key)

    app.state.initialized = True
    log.info("Node %s ready.", node_address)

    if config.registry_handle and node_address:
        registry_url = config.registry_url or config.identity_proxy_url or ""
        if registry_url:
            import threading
            threading.Thread(
                target=_registry_heartbeat,
                args=(private_key, node_address, config.registry_handle, registry_url),
                daemon=True,
            ).start()


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

    static_dir = Path(__file__).parent / "static"

    @app.get("/")
    def index():
        return FileResponse(static_dir / "index.html")

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.middleware("http")
    async def init_guard(request: Request, call_next):
        path = request.url.path
        if not app.state.initialized and not (
            path.startswith("/setup") or path == "/" or path.startswith("/static")
        ):
            state = "locked" if config_path.exists() else "uninitialized"
            return JSONResponse({"detail": "Server not ready", "state": state}, status_code=503)
        return await call_next(request)

    # Try to initialize immediately if we have everything we need
    passphrase = os.environ.get("CONTACC_PASSPHRASE")
    if config_path.exists() and passphrase:
        try:
            _initialize(app, config_path, passphrase)
        except WrongPassphraseError as e:
            log.error("Wrong passphrase at startup — server will start in locked state: %s", e)

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contacc node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--print-token", action="store_true", help="Print an owner token to stdout before serving")
    args = parser.parse_args()

    app = create_app(args.config)

    if args.print_token:
        if not app.state.initialized:
            log.error("--print-token requires the server to be initialized (set CONTACC_PASSPHRASE)")
            sys.exit(1)
        token = auth_module.issue_token(ttl_seconds=86400 * 30)
        print(f"Owner token: {token}", flush=True)

    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

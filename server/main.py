import os
import sys
import base64
import getpass
import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidTag

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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contacc")


def create_app(config_path: str | Path, passphrase: str) -> FastAPI:
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
    log.info("Database opened.")

    app = FastAPI(title="contacc node")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # CONTACC_NODE_ADDRESS env var overrides config — lets Docker deployments change
    # the public address by updating .env without touching the data volume.
    node_address = os.environ.get("CONTACC_NODE_ADDRESS") or config.node_address

    app.state.db = db_con
    app.state.file_key = file_key
    app.state.store_path = store_path
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

    log.info("Node %s ready.", config.node_address)
    return app


def _get_passphrase(key_stdin: bool) -> str:
    env = os.environ.get("CONTACC_PASSPHRASE")
    if env:
        return env
    if key_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Passphrase: ")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contacc node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--key-stdin", action="store_true", help="Read passphrase from stdin")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--print-token", action="store_true", help="Print an owner token to stdout before serving")
    args = parser.parse_args()

    passphrase = _get_passphrase(args.key_stdin)
    try:
        app = create_app(args.config, passphrase)
    except WrongPassphraseError as e:
        log.error("Startup failed: %s", e)
        sys.exit(1)

    if args.print_token:
        token = auth_module.issue_token(ttl_seconds=86400 * 30)
        print(f"Owner token: {token}", flush=True)

    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()

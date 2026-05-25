import sys
import base64
import getpass
import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from cryptography.exceptions import InvalidTag

from .config import NodeConfig
from .crypto import derive_master_key, derive_subkeys, decrypt_bytes
from .db import open_db, init_schema, WrongPassphraseError
from . import node as node_module
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contac")


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

    app = FastAPI(title="contac node")
    app.state.db = db_con
    app.state.file_key = file_key

    node_module.setup(config.node_address, private_key, config.watermark_enabled)
    app.include_router(node_module.router)

    log.info("Node %s ready.", config.node_address)
    return app


def _get_passphrase(key_stdin: bool) -> str:
    if key_stdin:
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Passphrase: ")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contac node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--key-stdin", action="store_true", help="Read passphrase from stdin")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    passphrase = _get_passphrase(args.key_stdin)
    try:
        app = create_app(args.config, passphrase)
    except WrongPassphraseError as e:
        log.error("Startup failed: %s", e)
        sys.exit(1)

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

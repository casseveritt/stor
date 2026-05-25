import json
import base64
import sqlite3
import pytest
import sqlcipher3
from pathlib import Path
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from server.crypto import derive_master_key, derive_subkeys, encrypt_bytes

TEST_PASSPHRASE = "test-passphrase-phase1"
WRONG_PASSPHRASE = "definitely-wrong"

# Low-cost Argon2id params so tests run fast
TEST_ARGON2 = dict(time_cost=1, memory_cost=8 * 1024, parallelism=1)
TEST_SALT = bytes.fromhex("deadbeefcafebabe" * 2)  # fixed 16-byte salt


def _make_store(tmp_path: Path, passphrase: str = TEST_PASSPHRASE) -> Path:
    store = tmp_path / "store"
    store.mkdir()
    (store / "files").mkdir()

    master_key = derive_master_key(passphrase, TEST_SALT, **TEST_ARGON2)
    db_key, _file_key = derive_subkeys(master_key)

    private_key = Ed25519PrivateKey.generate()
    privkey_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    encrypted_privkey = encrypt_bytes(privkey_bytes, master_key)

    db_path = str(store / "db")
    con = sqlcipher3.connect(db_path)
    con.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
    con.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
    con.execute("INSERT OR IGNORE INTO schema_version VALUES (1)")
    con.commit()
    con.close()

    config = {
        "node_address": "http://localhost:8000",
        "store_path": str(store),
        "argon2_salt": TEST_SALT.hex(),
        "argon2_time_cost": TEST_ARGON2["time_cost"],
        "argon2_memory_cost": TEST_ARGON2["memory_cost"],
        "argon2_parallelism": TEST_ARGON2["parallelism"],
        "encrypted_private_key": base64.b64encode(encrypted_privkey).decode(),
        "watermark_enabled": False,
    }
    (store / "node_config.json").write_text(json.dumps(config))
    return store


@pytest.fixture(scope="session")
def store(tmp_path_factory):
    return _make_store(tmp_path_factory.mktemp("base"))


@pytest.fixture(scope="session")
def client(store):
    from server.main import create_app
    app = create_app(store / "node_config.json", TEST_PASSPHRASE)
    return TestClient(app)


@pytest.fixture(scope="session")
def wrong_passphrase_store(tmp_path_factory):
    return _make_store(tmp_path_factory.mktemp("wrong"))

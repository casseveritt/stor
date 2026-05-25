import base64
import os
import sqlite3

import pytest
import sqlcipher3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from server.crypto import derive_master_key, derive_subkeys, encrypt_bytes, decrypt_bytes
from server.db import WrongPassphraseError, open_db
from tests.conftest import TEST_PASSPHRASE, WRONG_PASSPHRASE, TEST_SALT, TEST_ARGON2


class TestServerStarts:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_node_metadata_shape(self, client):
        r = client.get("/node")
        assert r.status_code == 200
        data = r.json()
        assert "node" in data
        assert "public_key" in data
        assert "watermark_policy" in data

    def test_node_address(self, client):
        r = client.get("/node")
        assert r.json()["node"] == "http://localhost:8000"

    def test_watermark_policy_value(self, client):
        r = client.get("/node")
        assert r.json()["watermark_policy"] in ("enabled", "disabled")

    def test_public_key_is_valid_ed25519(self, client):
        r = client.get("/node")
        pub_b64 = r.json()["public_key"]
        pub_bytes = base64.b64decode(pub_b64)
        assert len(pub_bytes) == 32
        # cryptography will raise if the bytes are not a valid Ed25519 public key
        Ed25519PublicKey.from_public_bytes(pub_bytes)


class TestWrongPassphrase:
    def test_wrong_passphrase_raises(self, wrong_passphrase_store):
        from server.main import create_app
        with pytest.raises(WrongPassphraseError):
            create_app(wrong_passphrase_store / "node_config.json", WRONG_PASSPHRASE)


class TestEncryptionAtRest:
    def test_db_file_is_not_plaintext_sqlite(self, store):
        db_path = store / "db"
        with pytest.raises(sqlite3.DatabaseError):
            con = sqlite3.connect(str(db_path))
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()

    def test_db_opens_with_correct_key(self, store):
        master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
        db_key, _ = derive_subkeys(master_key)
        con = open_db(str(store / "db"), db_key)
        result = con.execute("SELECT count(*) FROM sqlite_master").fetchone()
        assert result[0] >= 0
        con.close()

    def test_file_encryption_round_trip(self):
        key = os.urandom(32)
        plaintext = b"sensitive content that must not leak"
        ciphertext = encrypt_bytes(plaintext, key)
        assert ciphertext != plaintext
        assert plaintext not in ciphertext
        assert decrypt_bytes(ciphertext, key) == plaintext

    def test_encrypted_file_is_not_plaintext(self):
        key = os.urandom(32)
        plaintext = b"secret photo bytes " * 100
        ciphertext = encrypt_bytes(plaintext, key)
        assert plaintext not in ciphertext

    def test_nonce_is_random(self):
        key = os.urandom(32)
        c1 = encrypt_bytes(b"same", key)
        c2 = encrypt_bytes(b"same", key)
        assert c1[:12] != c2[:12]
        assert c1 != c2

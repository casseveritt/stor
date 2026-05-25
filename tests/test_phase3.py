"""Phase 3: FetchAsset, FetchAssetMeta, FetchThumbnail tests."""
import io
import json
import time
import uuid

import pytest
from PIL import Image

from server.crypto import encrypt_bytes, decrypt_bytes
from tests.test_phase2 import _auth, _insert_asset


# ── fixtures ──────────────────────────────────────────────────────────────────

def _make_jpeg(width=100, height=80, color=(100, 149, 237)) -> bytes:
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _store_file(store, file_key: bytes, content: bytes, content_hash: str) -> None:
    prefix = store / "files" / content_hash[:2]
    prefix.mkdir(parents=True, exist_ok=True)
    (prefix / content_hash).write_bytes(encrypt_bytes(content, file_key))


@pytest.fixture(scope="module")
def token(store):
    from server.config import NodeConfig
    from server.auth import setup as auth_setup, issue_token
    from server.crypto import derive_master_key, derive_subkeys, decrypt_bytes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64
    from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def image_asset(store, client, token):
    """A real encrypted JPEG in the store with a matching DB record."""
    content = _make_jpeg()
    content_hash = "deadbeef" * 8   # 64-char hex stand-in for a blake3 hash
    file_key = client.app.state.file_key
    _store_file(store, file_key, content, content_hash)
    asset_id = _insert_asset(
        client.app.state.db,
        content_hash=content_hash,
        media_type="image/jpeg",
        size=len(content),
        title="Phase 3 test image",
        tags=["test"],
    )
    return {"id": asset_id, "content_hash": content_hash, "content": content}


@pytest.fixture(scope="module")
def text_asset(store, client, token):
    """A plaintext file (non-image) to exercise the thumbnail 415 path."""
    content = b"hello contac"
    content_hash = "cafebabe" * 8
    file_key = client.app.state.file_key
    _store_file(store, file_key, content, content_hash)
    asset_id = _insert_asset(
        client.app.state.db,
        content_hash=content_hash,
        media_type="text/plain",
        size=len(content),
    )
    return {"id": asset_id, "content_hash": content_hash, "content": content}


# ── FetchAsset ────────────────────────────────────────────────────────────────

class TestFetchAsset:
    def test_requires_auth(self, client, image_asset):
        r = client.get(f"/assets/{image_asset['id']}")
        assert r.status_code == 403

    def test_returns_correct_bytes(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}", headers=_auth(token))
        assert r.status_code == 200
        assert r.content == image_asset["content"]

    def test_content_type_header(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}", headers=_auth(token))
        assert r.headers["content-type"].startswith("image/jpeg")

    def test_content_hash_header(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}", headers=_auth(token))
        assert r.headers["x-content-hash"] == image_asset["content_hash"]

    def test_unknown_id_404(self, client, token):
        r = client.get(f"/assets/{uuid.uuid4()}", headers=_auth(token))
        assert r.status_code == 404

    def test_text_asset(self, client, token, text_asset):
        r = client.get(f"/assets/{text_asset['id']}", headers=_auth(token))
        assert r.status_code == 200
        assert r.content == text_asset["content"]


# ── FetchAssetMeta ────────────────────────────────────────────────────────────

class TestFetchAssetMeta:
    def test_requires_auth(self, client, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/meta")
        assert r.status_code == 403

    def test_returns_metadata(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/meta", headers=_auth(token))
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == image_asset["id"]
        assert data["content_hash"] == image_asset["content_hash"]
        assert data["media_type"] == "image/jpeg"
        assert data["title"] == "Phase 3 test image"
        assert data["tags"] == ["test"]
        assert "node" in data
        assert "created_at" in data

    def test_unknown_id_404(self, client, token):
        r = client.get(f"/assets/{uuid.uuid4()}/meta", headers=_auth(token))
        assert r.status_code == 404


# ── FetchThumbnail ────────────────────────────────────────────────────────────

class TestFetchThumbnail:
    def test_requires_auth(self, client, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/thumb")
        assert r.status_code == 403

    def test_returns_image(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/thumb", headers=_auth(token))
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("image/jpeg")
        img = Image.open(io.BytesIO(r.content))
        assert img.width <= 256
        assert img.height <= 256

    def test_content_hash_header_is_original(self, client, token, image_asset):
        r = client.get(f"/assets/{image_asset['id']}/thumb", headers=_auth(token))
        assert r.headers["x-content-hash"] == image_asset["content_hash"]

    def test_non_image_returns_415(self, client, token, text_asset):
        r = client.get(f"/assets/{text_asset['id']}/thumb", headers=_auth(token))
        assert r.status_code == 415

    def test_unknown_id_404(self, client, token):
        r = client.get(f"/assets/{uuid.uuid4()}/thumb", headers=_auth(token))
        assert r.status_code == 404

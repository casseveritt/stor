"""Phase 5: Watermarking tests."""
import io
import json
import time
import uuid

import pytest
from PIL import Image

from server.auth import issue_recipient_token, setup as auth_setup, issue_token
from server.crypto import derive_master_key, decrypt_bytes, encrypt_bytes
from server.watermark import WatermarkError, apply as wm_apply
from tests.conftest import TEST_PASSPHRASE, TEST_SALT, TEST_ARGON2
from tests.test_phase3 import _make_jpeg, _store_file


# ── helpers ───────────────────────────────────────────────────────────────────

def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _insert_asset(db, **kwargs):
    asset_id = kwargs.get("id", str(uuid.uuid4()))
    db.execute(
        """INSERT INTO assets (id, content_hash, media_type, size, created_at, title, tags)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id,
            kwargs.get("content_hash", "00112233" * 8),
            kwargs.get("media_type", "image/jpeg"),
            kwargs.get("size", 512),
            kwargs.get("created_at", time.time()),
            kwargs.get("title", None),
            json.dumps([]),
        ),
    )
    db.commit()
    return asset_id


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def owner_token(store):
    import base64
    from server.config import NodeConfig
    config = NodeConfig.load(store / "node_config.json")
    master_key = derive_master_key(TEST_PASSPHRASE, TEST_SALT, **TEST_ARGON2)
    privkey_bytes = decrypt_bytes(base64.b64decode(config.encrypted_private_key), master_key)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    auth_setup(Ed25519PrivateKey.from_private_bytes(privkey_bytes))
    return issue_token(ttl_seconds=3600)


@pytest.fixture(scope="module")
def watermarked_client(client):
    """Temporarily enable watermarking on the shared app."""
    client.app.state.watermark_enabled = True
    yield client
    client.app.state.watermark_enabled = False


@pytest.fixture(scope="module")
def recipient_with_image(store, client, watermarked_client):
    """A recipient + ACL'd image asset in the watermark-enabled client."""
    db = client.app.state.db
    recipient_id = str(uuid.uuid4())
    identity = "google:wm-test@example.com"
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, identity, "WM Test"),
    )
    db.commit()

    content = _make_jpeg(200, 150, color=(30, 80, 160))
    content_hash = "wm000001" + "aa" * 28
    file_key = client.app.state.file_key
    _store_file(store, file_key, content, content_hash)

    asset_id = _insert_asset(
        db,
        content_hash=content_hash,
        media_type="image/jpeg",
        size=len(content),
    )
    db.execute("INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)", (asset_id, recipient_id))
    db.commit()

    token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
    return {
        "token": token,
        "asset_id": asset_id,
        "content_hash": content_hash,
        "original_content": content,
        "identity": identity,
        "recipient_id": recipient_id,
    }


@pytest.fixture(scope="module")
def text_asset_for_wm(store, client):
    """A non-image asset to verify pass-through."""
    content = b"plain text content, no watermark applies"
    content_hash = "textasset" + "bb" * 27 + "b"
    file_key = client.app.state.file_key
    _store_file(store, file_key, content, content_hash)
    db = client.app.state.db
    asset_id = _insert_asset(db, content_hash=content_hash, media_type="text/plain", size=len(content))
    recipient_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
        (recipient_id, "google:text-wm@example.com", "Text WM"),
    )
    db.execute("INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)", (asset_id, recipient_id))
    db.commit()
    token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)
    return {"token": token, "asset_id": asset_id, "content": content}


# ── watermark module unit tests ───────────────────────────────────────────────

class TestWatermarkModule:
    def test_image_is_modified(self):
        original = _make_jpeg(120, 120)
        result = wm_apply(original, "image/jpeg", "google:alice@test.com")
        assert result != original

    def test_non_image_passes_through(self):
        content = b"some text document"
        result = wm_apply(content, "text/plain", "google:alice@test.com")
        assert result == content

    def test_invalid_image_raises_watermark_error(self):
        with pytest.raises(WatermarkError):
            wm_apply(b"this is not an image", "image/jpeg", "google:alice@test.com")

    def test_result_is_valid_jpeg(self):
        original = _make_jpeg(80, 80)
        result = wm_apply(original, "image/jpeg", "google:alice@test.com")
        img = Image.open(io.BytesIO(result))
        assert img.format == "JPEG"

    def test_dimensions_preserved(self):
        original = _make_jpeg(100, 75)
        result = wm_apply(original, "image/jpeg", "google:alice@test.com")
        img = Image.open(io.BytesIO(result))
        assert img.size == (100, 75)


# ── watermarking in FetchAsset ────────────────────────────────────────────────

class TestFetchAssetWatermark:
    def test_recipient_gets_watermarked_content(self, watermarked_client, recipient_with_image):
        r = watermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}",
            headers=_auth(recipient_with_image["token"]),
        )
        assert r.status_code == 200
        assert r.content != recipient_with_image["original_content"]

    def test_content_hash_header_is_original(self, watermarked_client, recipient_with_image):
        r = watermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}",
            headers=_auth(recipient_with_image["token"]),
        )
        assert r.headers["x-content-hash"] == recipient_with_image["content_hash"]

    def test_owner_gets_unwatermarked_content(self, watermarked_client, owner_token, recipient_with_image):
        r = watermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}",
            headers=_auth(owner_token),
        )
        assert r.status_code == 200
        assert r.content == recipient_with_image["original_content"]

    def test_non_image_passes_through_unchanged(self, watermarked_client, text_asset_for_wm):
        r = watermarked_client.get(
            f"/assets/{text_asset_for_wm['asset_id']}",
            headers=_auth(text_asset_for_wm["token"]),
        )
        assert r.status_code == 200
        assert r.content == text_asset_for_wm["content"]


# ── watermarking in FetchThumbnail ────────────────────────────────────────────

class TestFetchThumbnailWatermark:
    def test_thumbnail_is_watermarked(self, watermarked_client, recipient_with_image):
        r = watermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}/thumb",
            headers=_auth(recipient_with_image["token"]),
        )
        assert r.status_code == 200
        img = Image.open(io.BytesIO(r.content))
        assert img.format == "JPEG"

    def test_thumb_content_hash_header_is_original(self, watermarked_client, recipient_with_image):
        r = watermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}/thumb",
            headers=_auth(recipient_with_image["token"]),
        )
        assert r.headers["x-content-hash"] == recipient_with_image["content_hash"]


# ── watermark failure ─────────────────────────────────────────────────────────

class TestWatermarkFailure:
    def test_server_returns_500_on_failure(self, store, watermarked_client):
        """Corrupt image (invalid bytes stored as image/jpeg) must return 500,
        not the raw un-watermarkable bytes."""
        db = watermarked_client.app.state.db
        recipient_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO recipients (id, identity, display_name) VALUES (?, ?, ?)",
            (recipient_id, "google:badimg@test.com", "Bad Image"),
        )
        db.commit()

        bad_content = b"not a jpeg at all"
        content_hash = "badadd00" * 8
        file_key = watermarked_client.app.state.file_key
        _store_file(store, file_key, bad_content, content_hash)

        asset_id = _insert_asset(
            db, content_hash=content_hash, media_type="image/jpeg", size=len(bad_content)
        )
        db.execute("INSERT OR IGNORE INTO acl (asset_id, recipient_id) VALUES (?, ?)", (asset_id, recipient_id))
        db.commit()
        token = issue_recipient_token(db, recipient_id, ttl_seconds=3600)

        r = watermarked_client.get(f"/assets/{asset_id}", headers=_auth(token))
        assert r.status_code == 500
        # Critically: the response must NOT contain the raw content
        assert bad_content not in r.content


# ── watermark disabled (default) ──────────────────────────────────────────────

@pytest.fixture
def unwatermarked_client(client):
    """Force watermarking off for the duration of a single test."""
    prev = client.app.state.watermark_enabled
    client.app.state.watermark_enabled = False
    yield client
    client.app.state.watermark_enabled = prev


class TestWatermarkDisabled:
    def test_content_unchanged_when_disabled(self, unwatermarked_client, recipient_with_image):
        r = unwatermarked_client.get(
            f"/assets/{recipient_with_image['asset_id']}",
            headers=_auth(recipient_with_image["token"]),
        )
        assert r.status_code == 200
        assert r.content == recipient_with_image["original_content"]
